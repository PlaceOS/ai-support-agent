require "./helper"

module AISupportAgent
  def self.diagnostic_report_for(payload : String)
    event = IncidentEvent.new(
      source: IncidentSource::Webhook,
      severity: IncidentSeverity::Error,
      correlation_key: "spec",
      payload: JSON.parse(payload),
      module_id: "mod-123",
      module_name: "Display"
    )
    DiagnosticEngine.new.report_for(Incident.new("aisup-spec", event, Time.utc))
  end

  class MissingModuleContext < PlaceOSContext
    getter tools = [] of String

    def execute(target : String, event : IncidentEvent, io_timeout_seconds : Int32 = 10) : DiagnosticToolResult
      @tools << target
      if target == "module_details"
        DiagnosticToolResult.new(target,
          [Evidence.new("diagnostic_target_missing", "module #{event.module_id} was not found in PlaceOS")],
          "Module missing", InvestigationStepStatus::Failed)
      else
        DiagnosticToolResult.new(target, [Evidence.new("placeos_rest_api", "System exists")], "System found")
      end
    end
  end

  describe DiagnosticEngine do
    {false, true}.each do |with_ai|
      it "stops confidence recovery for a missing target with AI=#{with_ai}" do
        context = MissingModuleContext.new
        reporter = with_ai ? AIReporter.fake(AgentAnalysis.new("Confident diagnosis", confidence: 0.9)) : AIReporter.disabled
        event = IncidentEvent.new(source: IncidentSource::Webhook, severity: IncidentSeverity::Error,
          correlation_key: "target-missing", payload: JSON.parse({message: "runtime error"}.to_json),
          module_id: "mod-missing", system_id: "sys-existing")
        report = DiagnosticEngine.new(context, reporter).report_for(Incident.new("aisup-missing", event, Time.utc))
        report.confidence.should eq 0.0
        context.tools.should eq ["module_details"]
        report.investigation.map(&.name).should_not contain "iterate_for_confidence"
        step = report.investigation.find!(&.name.==("target_not_found"))
        step.status.failed?.should be_true
        step.summary.should eq "Module mod-missing was not found in PlaceOS; no further evidence can be collected"
        report.decision.not_nil!.escalation_required?.should be_true
        report.decision.not_nil!.observed_facts.should contain "module mod-missing was not found in PlaceOS"
      end
    end

    it "keeps the existing score when an existing module's state times out" do
      WebMock.stub(:get, "http://place.test/api/engine/v2/modules/mod-existing").to_return(body: "{}")
      WebMock.stub(:get, "http://place.test/api/engine/v2/modules/mod-existing/state").to_return do |_request|
        raise IO::TimeoutError.new("state timed out")
      end
      WebMock.stub(:get, "http://place.test/api/engine/v2/modules/mod-existing/error").to_return(body: "[]")
      WebMock.stub(:get, "http://place.test/api/engine/v2/cluster/").to_return(body: "[]")
      context = PlaceOSContext.new(::PlaceOS::Client.new("http://place.test", x_api_key: "test-key"))
      event = IncidentEvent.new(source: IncidentSource::Webhook, severity: IncidentSeverity::Error,
        correlation_key: "state-timeout", payload: JSON.parse({message: "runtime error"}.to_json), module_id: "mod-existing")
      report = DiagnosticEngine.new(context, AIReporter.disabled).report_for(Incident.new("aisup-timeout", event, Time.utc))
      report.confidence.should be_close(0.8, 0.0001)
      report.evidence.map(&.source).should_not contain "diagnostic_target_missing"
      report.investigation.map(&.name).should_not contain "target_not_found"
    end

    it "classifies auth failures" do
      report = AISupportAgent.diagnostic_report_for({error: "HTTP 401 Unauthorized from upstream"}.to_json)

      report.classification.http_auth?.should be_true
      report.confidence.should be > 0.7
      report.actions_taken.should eq ["report_only_no_remediation"]
    end

    it "skips module and system lookups when the ids are blank" do
      modules = WebMock.stub(:get, "http://place.test/api/engine/v2/modules/")
        .to_return(body: "[]")
      systems = WebMock.stub(:get, "http://place.test/api/engine/v2/systems/")
        .to_return(body: "[]")

      client = ::PlaceOS::Client.new("http://place.test", x_api_key: "test-key")
      event = IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "blank-ids-engine",
        payload: JSON.parse({error: "HTTP 401 Unauthorized from upstream"}.to_json),
        system_id: "",
        module_id: ""
      )

      report = DiagnosticEngine.new(PlaceOSContext.new(client), AIReporter.disabled)
        .report_for(Incident.new("aisup-blank-ids", event, Time.utc))

      modules.calls.should eq 0
      systems.calls.should eq 0
      report.module_id.should be_nil
      report.evidence.map(&.source).should contain "diagnostic_context_missing"
      report.evidence.map(&.source).should_not contain "placeos_rest_api"
      tool_steps = report.investigation.select(&.name.starts_with?("tool:"))
      tool_steps.should_not be_empty
      tool_steps.all?(&.status.skipped?).should be_true
    end

    it "classifies tcp connection failures" do
      report = AISupportAgent.diagnostic_report_for({error: "ECONNREFUSED while opening socket"}.to_json)

      report.classification.tcp_closed?.should be_true
    end

    it "redacts sensitive evidence" do
      report = AISupportAgent.diagnostic_report_for({
        message: "runtime error",
        token:   "abc123",
        nested:  {password: "secret"},
      }.to_json)
      evidence = report.evidence.first.data.try(&.to_json) || ""

      evidence.should contain "[redacted]"
      evidence.should_not contain "abc123"
      evidence.should_not contain "secret"
    end

    it "records deterministic investigation steps when AI is unavailable" do
      report = AISupportAgent.diagnostic_report_for({error: "HTTP 401 Unauthorized from upstream"}.to_json)

      report.investigation.map(&.name).should eq [
        "capture_signal",
        "plan_investigation",
        "tool:module_details",
        "tool:module_state",
        "tool:system_details",
        "classify_symptoms",
        "build_agent_decision",
        "deterministic_fallback",
      ]
      report.investigation.last.summary.should contain "AI analysis unavailable"
      plan = report.investigation_plan
      plan.should_not be_nil
      plan.try(&.evidence_targets).should eq ["module_details", "module_state", "system_details"]
      plan.try(&.playbook_id).should eq "http-authentication-failure"
      plan.try(&.playbook_version).should eq 1
      plan.try(&.playbook_hash.to_s.size).should eq 64
      report.decision.should_not be_nil
      report.decision.try(&.hypotheses.should_not be_empty)
      report.remediation_proposal.should be_nil
      report.decision.try(&.recommended_action).to_s.should contain "Verify credentials"
      report.actions_taken.should eq ["report_only_no_remediation"]
    end

    it "iterates for additional read-only evidence when confidence is low" do
      report = AISupportAgent.diagnostic_report_for({message: "display alert without known signature"}.to_json)
      steps = report.investigation.map(&.name)

      report.classification.unknown?.should be_true
      plan = report.investigation_plan
      plan.should_not be_nil
      if agent_plan = plan
        agent_plan.goal.should contain "Unknown"
      end
      steps.should contain "plan_investigation"
      steps.should contain "iterate_for_confidence"
      steps.should contain "tool:module_details"
      steps.should contain "tool:module_state"
      steps.should contain "tool:module_error_logs"
      steps.should contain "tool:core_loaded_processes"
      report.actions_taken.should eq ["report_only_no_remediation"]
    end

    it "uses AI structured analysis when a reporter is configured" do
      event = IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Critical,
        correlation_key: "ai-spec",
        payload: JSON.parse({message: "response timeout"}.to_json),
        module_id: "mod-123",
        module_name: "Display"
      )
      engine = DiagnosticEngine.new(
        PlaceOSContext.new,
        AIReporter.fake(AgentAnalysis.new(
          summary: "AI summary: display command responses are timing out.",
          next_steps: ["Inspect display driver debug logs.", "Check network latency to the display."],
          confidence: 0.86
        ))
      )

      report = engine.report_for(Incident.new("aisup-ai-spec", event, Time.utc))

      report.summary.should eq "AI summary: display command responses are timing out."
      report.ai_summary.should eq report.summary
      report.next_steps.should eq ["Inspect display driver debug logs.", "Check network latency to the display."]
      report.confidence.should eq 0.86
      report.evidence.map(&.source).should contain "openai"
      report.investigation.map(&.name).should contain "ai_structured_analysis"
      report.decision.try(&.recommended_action.should_not be_empty)
      report.remediation_proposal.should be_nil
      report.investigation_plan.should_not be_nil
      report.actions_taken.should eq ["report_only_no_remediation"]
    end

    it "rebuilds the decision when AI lowers confidence" do
      event = IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "ai-low-confidence",
        payload: JSON.parse({message: "response timeout"}.to_json),
        module_id: "mod-123"
      )
      engine = DiagnosticEngine.new(
        PlaceOSContext.new,
        AIReporter.fake(AgentAnalysis.new("Uncertain AI analysis", confidence: 0.2))
      )

      report = engine.report_for(Incident.new("aisup-ai-low-confidence", event, Time.utc))

      report.confidence.should eq 0.2
      report.decision.try(&.escalation_required?).should be_true
    end

    it "ignores AI confidence outside the zero-to-one range" do
      event = IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "ai-invalid-confidence",
        payload: JSON.parse({message: "response timeout"}.to_json),
        module_id: "mod-123"
      )
      engine = DiagnosticEngine.new(
        PlaceOSContext.new,
        AIReporter.fake(AgentAnalysis.new("AI analysis with invalid confidence", confidence: 1.5))
      )

      report = engine.report_for(Incident.new("aisup-ai-invalid-confidence", event, Time.utc))

      report.confidence.should eq 0.75
      report.decision.try(&.escalation_required?).should be_false
    end

    it "reduces confidence when incident scope cannot satisfy playbook steps" do
      event = IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "missing-scope",
        payload: JSON.parse({message: "HTTP 401 Unauthorized"}.to_json)
      )

      report = DiagnosticEngine.new.report_for(Incident.new("aisup-missing-scope", event, Time.utc))

      report.confidence.should eq 0.4
      report.decision.try(&.escalation_required?).should be_true
      report.evidence.map(&.source).should contain "diagnostic_context_missing"
    end

    it "reduces confidence when scope does not match the selected playbook" do
      event = IncidentEvent.new(
        source: IncidentSource::ModuleState,
        severity: IncidentSeverity::Error,
        correlation_key: "runtime-error-without-module",
        payload: JSON.parse({message: "runtime error"}.to_json),
        system_id: "sys-123"
      )

      report = DiagnosticEngine.new.report_for(Incident.new("aisup-mismatched-scope", event, Time.utc))

      report.confidence.should be < 0.5
      report.decision.try(&.escalation_required?).should be_true
      report.evidence.map(&.source).should contain "diagnostic_context_missing"
    end
  end
end
