module AISupportAgent
  class DiagnosticEngine
    def initialize(
      @context : PlaceOSContext = PlaceOSContext.new,
      @ai_reporter : AIReporter = AIReporter.disabled,
      @procedures : DiagnosticProcedureRegistry? = nil,
    )
    end

    def report_for(incident : Incident, selected_procedure : DiagnosticProcedure? = nil) : IncidentReport
      event = incident.event
      redacted_payload = Redactor.redact(event.payload)
      investigation = [] of InvestigationStep

      inbound_evidence = evidence_for(event, redacted_payload)
      investigation << InvestigationStep.new(
        name: "capture_signal",
        status: InvestigationStepStatus::Completed,
        summary: "Captured and redacted inbound #{event.source} signal",
        evidence_count: inbound_evidence.size
      )

      evidence = inbound_evidence
      playbook = selected_procedure || procedures.select(event, redacted_payload)
      classification = playbook.classification
      plan = playbook.plan(event)
      unless executable_step?(plan.steps, event)
        evidence << Evidence.new(
          source: "diagnostic_context_missing",
          message: "Incident context cannot satisfy any primary step in playbook #{playbook.id}"
        )
      end
      investigation << InvestigationStep.new(
        name: "plan_investigation",
        status: InvestigationStepStatus::Completed,
        summary: "Loaded #{playbook.id} v#{playbook.version} and planned #{plan.steps.size} read-only tool step(s)",
        evidence_count: evidence.size
      )

      completed_tools = [] of String
      failed_tools = [] of String
      tool_evidence = execute_steps(plan.steps, event, investigation, completed_tools, failed_tools)
      evidence.concat(tool_evidence)
      current_confidence = confidence(playbook, evidence, completed_tools, failed_tools)

      fallback_steps = playbook.fallback_steps(completed_tools)
      iteration = 0
      while current_confidence < plan.confidence_threshold && iteration < plan.max_iterations
        fallback_step = fallback_steps.shift?
        break unless fallback_step

        iteration += 1
        investigation << InvestigationStep.new(
          name: "iterate_for_confidence",
          status: InvestigationStepStatus::Completed,
          summary: "Confidence #{current_confidence} below #{plan.confidence_threshold}; running fallback iteration #{iteration} with #{fallback_step.tool}",
          evidence_count: evidence.size
        )
        evidence.concat(execute_steps([fallback_step], event, investigation, completed_tools, failed_tools))
        current_confidence = confidence(playbook, evidence, completed_tools, failed_tools)
      end

      investigation << InvestigationStep.new(
        name: "classify_symptoms",
        status: InvestigationStepStatus::Completed,
        summary: "Selected #{playbook.name} playbook after classifying incident as #{classification}",
        evidence_count: evidence.size
      )

      decision = playbook.decision(classification, evidence, current_confidence)
      investigation << InvestigationStep.new(
        name: "build_agent_decision",
        status: InvestigationStepStatus::Completed,
        summary: "Built diagnostic decision with #{decision.hypotheses.size} hypotheses and operator guidance",
        evidence_count: evidence.size
      )

      report = IncidentReport.new(
        incident_id: incident.id,
        status: IncidentStatus::Open,
        summary: summary(event, classification),
        classification: classification,
        confidence: current_confidence,
        severity: event.severity,
        source: event.source,
        correlation_key: event.correlation_key,
        tenant_id: event.tenant_id,
        system_id: event.system_id,
        module_id: event.module_id,
        module_name: event.module_name,
        module_index: event.module_index,
        created_at: incident.created_at,
        evidence: evidence,
        actions_taken: ["report_only_no_remediation"],
        next_steps: playbook.guidance.operator_steps,
        investigation_plan: plan,
        investigation: investigation,
        decision: decision
      )

      if analysis = @ai_reporter.analyze?(report)
        analysis = validated_analysis(analysis)
        analysis = apply_failure_confidence_ceiling(analysis, current_confidence, evidence, failed_tools)
        final_confidence = analysis.confidence || current_confidence
        final_decision = playbook.decision(classification, evidence, final_confidence)
        report.with_agent_analysis(
          analysis,
          InvestigationStep.new(
            name: "ai_structured_analysis",
            status: InvestigationStepStatus::Completed,
            summary: "AI produced structured report analysis",
            evidence_count: evidence.size
          ),
          final_decision
        )
      else
        report.with_investigation_step(InvestigationStep.new(
          name: "deterministic_fallback",
          status: InvestigationStepStatus::Completed,
          summary: "AI analysis unavailable; deterministic playbook analysis produced report",
          evidence_count: evidence.size
        ))
      end
    end

    private def summary(event : IncidentEvent, classification : DiagnosticClassification) : String
      target = event.module_name || event.module_id || event.system_id || event.correlation_key
      "#{event.source} #{event.severity} incident for #{target}: #{classification}"
    end

    private def procedures : DiagnosticProcedureRegistry
      @procedures ||= DiagnosticProcedureRegistry.from_environment
    end

    private def confidence(
      playbook : DiagnosticProcedure,
      evidence : Array(Evidence),
      completed_tools : Array(String),
      failed_tools : Array(String),
    ) : Float64
      base = playbook.analysis.initial_confidence
      sources = evidence.map(&.source)
      score = base
      score += {completed_tools.uniq.size * 0.05, 0.15}.min
      failures = failed_tools.size + sources.count("diagnostic_context_missing")
      successful_tool_evidence = !completed_tools.empty?
      score -= successful_tool_evidence ? 0.1 : 0.35 if failures > 0
      score.clamp(0.0, 0.95)
    end

    private def validated_analysis(analysis : AgentAnalysis) : AgentAnalysis
      confidence = analysis.confidence
      return analysis unless confidence
      return analysis if (0.0..1.0).includes?(confidence)

      AISupportAgent::Log.warn { "AI analysis returned confidence outside 0..1; retaining deterministic confidence" }
      AgentAnalysis.new(analysis.summary, analysis.next_steps, nil)
    end

    private def apply_failure_confidence_ceiling(
      analysis : AgentAnalysis,
      ceiling : Float64,
      evidence : Array(Evidence),
      failed_tools : Array(String),
    ) : AgentAnalysis
      confidence = analysis.confidence
      return analysis unless confidence && confidence > ceiling
      return analysis if failed_tools.empty? && evidence.none?(&.source.==("diagnostic_context_missing"))

      AISupportAgent::Log.warn { "AI confidence exceeded failure-penalized diagnostic confidence; applying diagnostic ceiling" }
      AgentAnalysis.new(analysis.summary, analysis.next_steps, ceiling)
    end

    private def execute_steps(
      steps : Array(PlaybookStep),
      event : IncidentEvent,
      investigation : Array(InvestigationStep),
      completed_tools : Array(String),
      failed_tools : Array(String),
    ) : Array(Evidence)
      evidence = [] of Evidence
      statuses = {} of String => InvestigationStepStatus

      steps.each do |step|
        unless step.context_satisfied?(event)
          statuses[step.id] = InvestigationStepStatus::Skipped
          investigation << InvestigationStep.new(
            name: "tool:#{step.tool}",
            status: InvestigationStepStatus::Skipped,
            summary: "Skipped #{step.id}; required context was unavailable",
            evidence_count: 0
          )
          next
        end

        if step.depends_on.any? { |dependency| statuses[dependency]? != InvestigationStepStatus::Completed }
          statuses[step.id] = InvestigationStepStatus::Skipped
          investigation << InvestigationStep.new(
            name: "tool:#{step.tool}",
            status: InvestigationStepStatus::Skipped,
            summary: "Skipped #{step.id}; a dependency did not complete",
            evidence_count: 0
          )
          next
        end

        result = execute_step(step, event)
        statuses[step.id] = result.status
        completed_tools << step.tool if result.status.completed?
        failed_tools << step.tool if result.status.failed?
        step_evidence = result.evidence.dup
        if result.status.failed? && step_evidence.none?(&.source.==("diagnostic_tool_error"))
          step_evidence << Evidence.new(source: "diagnostic_tool_error", message: "#{step.tool} failed: #{result.summary}")
        end
        evidence.concat(step_evidence)
        investigation << InvestigationStep.new(
          name: "tool:#{step.tool}",
          status: result.status,
          summary: result.summary,
          evidence_count: step_evidence.size
        )
      end
      evidence
    end

    private def executable_step?(steps : Array(PlaybookStep), event : IncidentEvent) : Bool
      executable = {} of String => Bool
      any_executable = false
      steps.each do |step|
        step_executable = step.context_satisfied?(event) &&
                          step.depends_on.all? { |dependency| executable[dependency]? }
        executable[step.id] = step_executable
        any_executable ||= step_executable
      end
      any_executable
    end

    private def execute_step(step : PlaybookStep, event : IncidentEvent) : DiagnosticToolResult
      @context.execute(step.tool, event, step.io_timeout_seconds)
    rescue error
      DiagnosticToolResult.new(
        step.tool,
        [Evidence.new(source: "diagnostic_tool_error", message: "#{step.tool} failed: #{error.class}: #{error.message}")],
        "Tool #{step.id} failed",
        InvestigationStepStatus::Failed
      )
    end

    private def evidence_for(event : IncidentEvent, redacted_payload : JSON::Any) : Array(Evidence)
      evidence = [
        Evidence.new(
          source: event.source.to_s.downcase,
          message: "Inbound webhook payload captured and redacted",
          data: redacted_payload
        ),
      ]

      if module_id = event.module_id
        evidence << Evidence.new(source: "incident_event", message: "Module id: #{module_id}")
      end

      if system_id = event.system_id
        evidence << Evidence.new(source: "incident_event", message: "System id: #{system_id}")
      end

      evidence
    end
  end
end
