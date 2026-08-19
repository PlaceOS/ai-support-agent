module AISupportAgent
  enum IncidentStatus
    Open
    Resolved
    Escalated
    Ignored
  end

  struct DiagnosticClassification
    HttpAuth        = new("http_auth")
    TlsCertificate  = new("tls_certificate")
    TcpTimeout      = new("tcp_timeout")
    TcpClosed       = new("tcp_closed")
    ResponseTimeout = new("response_timeout")
    SshAuth         = new("ssh_auth")
    RuntimeError    = new("runtime_error")
    Unknown         = new("unknown")

    LEGACY_NAMES = {
      "HttpAuth"        => "http_auth",
      "TlsCertificate"  => "tls_certificate",
      "TcpTimeout"      => "tcp_timeout",
      "TcpClosed"       => "tcp_closed",
      "ResponseTimeout" => "response_timeout",
      "SshAuth"         => "ssh_auth",
      "RuntimeError"    => "runtime_error",
      "Unknown"         => "unknown",
    }

    getter value : String

    def initialize(@value : String)
      unless value.matches?(/\A[a-z][a-z0-9_]*\z/)
        raise ArgumentError.new("invalid diagnostic classification #{value.inspect}")
      end
    end

    def initialize(pull : JSON::PullParser)
      @value = self.class.parse(pull.read_string).value
    end

    def self.parse(value : String) : DiagnosticClassification
      new(LEGACY_NAMES[value]? || value)
    end

    def to_json(json : JSON::Builder) : Nil
      value.to_json(json)
    end

    def to_s(io : IO) : Nil
      io << value
    end

    {% for name, value in {
                            http_auth:        "http_auth",
                            tls_certificate:  "tls_certificate",
                            tcp_timeout:      "tcp_timeout",
                            tcp_closed:       "tcp_closed",
                            response_timeout: "response_timeout",
                            ssh_auth:         "ssh_auth",
                            runtime_error:    "runtime_error",
                            unknown:          "unknown",
                          } %}
      def {{name.id}}? : Bool
        value == {{value}}
      end
    {% end %}
  end

  struct Incident
    getter id : String
    getter event : IncidentEvent
    getter created_at : Time

    def initialize(@id : String, @event : IncidentEvent, @created_at : Time)
    end
  end

  struct Evidence
    include JSON::Serializable

    getter source : String
    getter message : String
    getter data : JSON::Any?

    def initialize(@source : String, @message : String, @data : JSON::Any? = nil)
    end
  end

  enum InvestigationStepStatus
    Pending
    Completed
    Skipped
    Failed
  end

  struct InvestigationStep
    include JSON::Serializable

    getter name : String
    getter status : InvestigationStepStatus
    getter summary : String
    getter evidence_count : Int32

    def initialize(
      @name : String,
      @status : InvestigationStepStatus,
      @summary : String,
      @evidence_count : Int32 = 0,
    )
    end
  end

  struct IncidentReport
    include JSON::Serializable

    REPORT_SCHEMA_VERSION = "incident-report.v1"

    getter report_schema_version : String
    getter incident_id : String
    getter status : IncidentStatus
    getter duplicate_count : Int32
    getter last_seen_at : Time
    getter resolved_at : Time?
    getter summary : String
    getter classification : DiagnosticClassification
    getter confidence : Float64
    getter severity : IncidentSeverity
    getter source : IncidentSource
    getter correlation_key : String
    getter tenant_id : String?
    getter system_id : String?
    getter module_id : String?
    getter module_name : String?
    getter module_index : Int32?
    getter created_at : Time
    getter evidence : Array(Evidence)
    getter actions_taken : Array(String)
    getter next_steps : Array(String)
    getter investigation_plan : InvestigationPlan?
    getter investigation : Array(InvestigationStep)
    getter decision : AgentDecision?
    getter remediation_proposal : RemediationProposal?
    getter ai_summary : String?

    def initialize(
      @incident_id : String,
      @status : IncidentStatus,
      @summary : String,
      @classification : DiagnosticClassification,
      @confidence : Float64,
      @severity : IncidentSeverity,
      @source : IncidentSource,
      @correlation_key : String,
      @created_at : Time,
      @evidence : Array(Evidence),
      @actions_taken : Array(String),
      @next_steps : Array(String),
      @investigation_plan : InvestigationPlan? = nil,
      @investigation : Array(InvestigationStep) = [] of InvestigationStep,
      @decision : AgentDecision? = nil,
      @remediation_proposal : RemediationProposal? = nil,
      @ai_summary : String? = nil,
      @report_schema_version : String = REPORT_SCHEMA_VERSION,
      @duplicate_count : Int32 = 0,
      last_seen_at : Time? = nil,
      @resolved_at : Time? = nil,
      @tenant_id : String? = nil,
      @system_id : String? = nil,
      @module_id : String? = nil,
      @module_name : String? = nil,
      @module_index : Int32? = nil,
    )
      @last_seen_at = last_seen_at || created_at
    end

    def with_ai_summary(ai_summary : String) : IncidentReport
      IncidentReport.new(
        incident_id: incident_id,
        status: status,
        summary: ai_summary,
        classification: classification,
        confidence: confidence,
        severity: severity,
        source: source,
        correlation_key: correlation_key,
        tenant_id: tenant_id,
        system_id: system_id,
        module_id: module_id,
        module_name: module_name,
        module_index: module_index,
        created_at: created_at,
        evidence: evidence + [Evidence.new(source: "openai", message: "AI-assisted summary generated through crystal-openai")],
        actions_taken: actions_taken,
        next_steps: next_steps,
        investigation_plan: investigation_plan,
        investigation: investigation,
        decision: decision,
        remediation_proposal: remediation_proposal,
        ai_summary: ai_summary,
        report_schema_version: report_schema_version,
        duplicate_count: duplicate_count,
        last_seen_at: last_seen_at,
        resolved_at: resolved_at
      )
    end

    def with_agent_analysis(
      analysis : AgentAnalysis,
      step : InvestigationStep,
      decision : AgentDecision? = self.decision,
      remediation_proposal : RemediationProposal? = self.remediation_proposal,
    ) : IncidentReport
      IncidentReport.new(
        incident_id: incident_id,
        status: status,
        summary: analysis.summary,
        classification: classification,
        confidence: analysis.confidence || confidence,
        severity: severity,
        source: source,
        correlation_key: correlation_key,
        tenant_id: tenant_id,
        system_id: system_id,
        module_id: module_id,
        module_name: module_name,
        module_index: module_index,
        created_at: created_at,
        evidence: evidence + [Evidence.new(source: "openai", message: "AI-assisted structured analysis generated through crystal-openai")],
        actions_taken: actions_taken,
        next_steps: analysis.next_steps.empty? ? next_steps : analysis.next_steps,
        investigation_plan: investigation_plan,
        investigation: investigation + [step],
        decision: decision,
        remediation_proposal: remediation_proposal,
        ai_summary: analysis.summary,
        report_schema_version: report_schema_version,
        duplicate_count: duplicate_count,
        last_seen_at: last_seen_at,
        resolved_at: resolved_at
      )
    end

    def with_investigation_step(step : InvestigationStep) : IncidentReport
      IncidentReport.new(
        incident_id: incident_id,
        status: status,
        summary: summary,
        classification: classification,
        confidence: confidence,
        severity: severity,
        source: source,
        correlation_key: correlation_key,
        tenant_id: tenant_id,
        system_id: system_id,
        module_id: module_id,
        module_name: module_name,
        module_index: module_index,
        created_at: created_at,
        evidence: evidence,
        actions_taken: actions_taken,
        next_steps: next_steps,
        investigation_plan: investigation_plan,
        investigation: investigation + [step],
        decision: decision,
        remediation_proposal: remediation_proposal,
        ai_summary: ai_summary,
        report_schema_version: report_schema_version,
        duplicate_count: duplicate_count,
        last_seen_at: last_seen_at,
        resolved_at: resolved_at
      )
    end

    def with_workflow_result(
      plan : InvestigationPlan?,
      workflow_status : IncidentStatus,
      steps : Array(InvestigationStep),
    ) : IncidentReport
      IncidentReport.new(
        incident_id: incident_id,
        status: workflow_status,
        summary: summary,
        classification: classification,
        confidence: confidence,
        severity: severity,
        source: source,
        correlation_key: correlation_key,
        tenant_id: tenant_id,
        system_id: system_id,
        module_id: module_id,
        module_name: module_name,
        module_index: module_index,
        created_at: created_at,
        evidence: evidence,
        actions_taken: actions_taken,
        next_steps: next_steps,
        investigation_plan: plan,
        investigation: investigation + steps,
        decision: decision,
        remediation_proposal: remediation_proposal,
        ai_summary: ai_summary,
        report_schema_version: report_schema_version,
        duplicate_count: duplicate_count,
        last_seen_at: last_seen_at,
        resolved_at: resolved_at
      )
    end

    def with_remediation_proposal(
      proposal : RemediationProposal,
      plan : InvestigationPlan?,
      step : InvestigationStep,
    ) : IncidentReport
      IncidentReport.new(
        incident_id: incident_id,
        status: status,
        summary: summary,
        classification: classification,
        confidence: confidence,
        severity: severity,
        source: source,
        correlation_key: correlation_key,
        tenant_id: tenant_id,
        system_id: system_id,
        module_id: module_id,
        module_name: module_name,
        module_index: module_index,
        created_at: created_at,
        evidence: evidence,
        actions_taken: actions_taken,
        next_steps: next_steps,
        investigation_plan: plan,
        investigation: investigation + [step],
        decision: decision,
        remediation_proposal: proposal,
        ai_summary: ai_summary,
        report_schema_version: report_schema_version,
        duplicate_count: duplicate_count,
        last_seen_at: last_seen_at,
        resolved_at: resolved_at
      )
    end

    def with_verification_result(run : VerificationRun) : IncidentReport
      workflow_status = if run.status.verified?
                          IncidentStatus::Resolved
                        elsif run.status.failed?
                          IncidentStatus::Escalated
                        else
                          status
                        end
      plan = investigation_plan.try do |current|
        current.with_procedure(
          ProcedureReference.new(run.procedure.category, run.procedure.id, run.procedure.version),
          run.procedure.content_hash
        )
      end
      IncidentReport.new(
        incident_id: incident_id,
        status: workflow_status,
        summary: summary,
        classification: classification,
        confidence: confidence,
        severity: severity,
        source: source,
        correlation_key: correlation_key,
        tenant_id: tenant_id,
        system_id: system_id,
        module_id: module_id,
        module_name: module_name,
        module_index: module_index,
        created_at: created_at,
        evidence: evidence + run.evidence,
        actions_taken: actions_taken,
        next_steps: verification_next_steps(run),
        investigation_plan: plan,
        investigation: investigation + [InvestigationStep.new(
          name: "verification:#{run.procedure.id}",
          status: run.status.verified? ? InvestigationStepStatus::Completed : InvestigationStepStatus::Failed,
          summary: "Verification attempt #{run.attempt} completed with #{run.status}",
          evidence_count: run.evidence.size
        )],
        decision: decision,
        remediation_proposal: remediation_proposal,
        ai_summary: ai_summary,
        report_schema_version: report_schema_version,
        duplicate_count: duplicate_count,
        last_seen_at: run.completed_at,
        resolved_at: run.status.verified? ? run.completed_at : resolved_at
      )
    end

    def with_decision(decision : AgentDecision) : IncidentReport
      IncidentReport.new(
        incident_id: incident_id,
        status: status,
        summary: summary,
        classification: classification,
        confidence: confidence,
        severity: severity,
        source: source,
        correlation_key: correlation_key,
        tenant_id: tenant_id,
        system_id: system_id,
        module_id: module_id,
        module_name: module_name,
        module_index: module_index,
        created_at: created_at,
        evidence: evidence,
        actions_taken: actions_taken,
        next_steps: next_steps,
        investigation_plan: investigation_plan,
        investigation: investigation,
        decision: decision,
        remediation_proposal: remediation_proposal,
        ai_summary: ai_summary,
        report_schema_version: report_schema_version,
        duplicate_count: duplicate_count,
        last_seen_at: last_seen_at,
        resolved_at: resolved_at
      )
    end

    def with_duplicate_seen(at : Time) : IncidentReport
      IncidentReport.new(
        incident_id: incident_id,
        status: status,
        summary: summary,
        classification: classification,
        confidence: confidence,
        severity: severity,
        source: source,
        correlation_key: correlation_key,
        tenant_id: tenant_id,
        system_id: system_id,
        module_id: module_id,
        module_name: module_name,
        module_index: module_index,
        created_at: created_at,
        evidence: evidence,
        actions_taken: actions_taken,
        next_steps: next_steps,
        investigation_plan: investigation_plan,
        investigation: investigation + [InvestigationStep.new(
          name: "deduplicate_signal",
          status: InvestigationStepStatus::Completed,
          summary: "Repeated signal suppressed for correlation key #{correlation_key}",
          evidence_count: evidence.size
        )],
        decision: decision,
        remediation_proposal: remediation_proposal,
        ai_summary: ai_summary,
        report_schema_version: report_schema_version,
        duplicate_count: duplicate_count + 1,
        last_seen_at: at,
        resolved_at: resolved_at
      )
    end

    def with_resolution_seen(at : Time) : IncidentReport
      IncidentReport.new(
        incident_id: incident_id,
        status: IncidentStatus::Resolved,
        summary: "#{summary} (resolved)",
        classification: classification,
        confidence: confidence,
        severity: severity,
        source: source,
        correlation_key: correlation_key,
        tenant_id: tenant_id,
        system_id: system_id,
        module_id: module_id,
        module_name: module_name,
        module_index: module_index,
        created_at: created_at,
        evidence: evidence + [Evidence.new(source: "incident_lifecycle", message: "Received correlated resolution signal")],
        actions_taken: actions_taken,
        next_steps: next_steps,
        investigation_plan: investigation_plan,
        investigation: investigation + [InvestigationStep.new(
          name: "resolve_signal",
          status: InvestigationStepStatus::Completed,
          summary: "Correlated alert-resolution signal received for #{correlation_key}",
          evidence_count: evidence.size
        )],
        decision: decision,
        remediation_proposal: remediation_proposal,
        ai_summary: ai_summary,
        report_schema_version: report_schema_version,
        duplicate_count: duplicate_count,
        last_seen_at: at,
        resolved_at: at
      )
    end

    def to_markdown : String
      String.build do |io|
        io << "# Incident Diagnostic Report\n\n"
        io << summary << "\n\n"
        io << "- Report Schema: `" << report_schema_version << "`\n"
        io << "- Incident ID: `" << incident_id << "`\n"
        io << "- Status: " << status << "\n"
        io << "- Severity: " << severity << "\n"
        io << "- Classification: " << classification << "\n"
        io << "- Confidence: " << confidence << "\n"
        io << "- Source: " << source << "\n"
        io << "- Correlation Key: `" << correlation_key << "`\n"
        io << "- Created At: " << created_at.to_rfc3339 << "\n\n"
        io << "- Duplicate Count: " << duplicate_count << "\n"
        io << "- Last Seen At: " << last_seen_at.to_rfc3339 << "\n\n"
        io << "- Resolved At: " << (resolved_at.try(&.to_rfc3339) || "not resolved") << "\n\n"

        io << "## Affected Scope\n\n"
        scope_line(io, "Tenant", tenant_id)
        scope_line(io, "System", system_id)
        scope_line(io, "Module", module_name || module_id)
        scope_line(io, "Module Index", module_index.try(&.to_s))
        io << "\n"

        if plan = investigation_plan
          io << "## Investigation Plan\n\n"
          io << "- Workflow: `" << (plan.workflow_id || "legacy") << "`\n"
          io << "- Workflow Version: " << (plan.workflow_version || "not recorded") << "\n"
          io << "- Workflow Hash: `" << (plan.workflow_hash || "not recorded") << "`\n"
          io << "- Workflow Stage: `" << (plan.workflow_stage || "not recorded") << "`\n"
          io << "- Playbook: `" << (plan.playbook_id || "legacy") << "`\n"
          io << "- Playbook Version: " << (plan.playbook_version || "not recorded") << "\n"
          io << "- Playbook Hash: `" << (plan.playbook_hash || "not recorded") << "`\n"
          unless plan.procedures.empty?
            io << "- Procedures: " << plan.procedures.map { |procedure| "`#{procedure.category}:#{procedure.id}@#{procedure.version}`" }.join(", ") << "\n"
          end
          if escalation = plan.escalation
            io << "- Escalation Owner: " << escalation.owner_queue << "\n"
            io << "- Response SLA: " << escalation.response_sla_minutes << " minutes\n"
            io << "- Escalation Reason: " << escalation.reason << "\n"
          end
          io << "- Goal: " << plan.goal << "\n"
          io << "- Confidence Threshold: " << plan.confidence_threshold << "\n"
          io << "- Max Iterations: " << plan.max_iterations << "\n"
          markdown_list(io, "Evidence Targets", plan.evidence_targets)
        end

        if decision = self.decision
          io << "## Diagnosis\n\n"
          markdown_list(io, "Observed Facts", decision.observed_facts)
          markdown_list(io, "Hypotheses", decision.hypotheses)
          markdown_list(io, "Ruled Out", decision.ruled_out)
          io << "Recommended Action: " << decision.recommended_action << "\n\n"
          io << "Escalation Required: " << decision.escalation_required? << "\n\n"
        end

        if proposal = remediation_proposal
          io << "## Remediation Proposal\n\n"
          io << "- Execution Mode: `" << proposal.execution_mode << "`\n"
          io << "- Approval Required: " << proposal.approval_required? << "\n"
          io << "- Risk Level: " << proposal.risk_level << "\n"
          io << "- Proposed Action: " << proposal.action << "\n"
          io << "- Policy Basis: " << proposal.policy_basis << "\n\n"
          io << "- Verification Procedure: `" << (proposal.verification_procedure || "not configured") << "`\n\n"
          markdown_list(io, "Verification Plan", proposal.verification_plan)
        end

        io << "## Investigation Timeline\n\n"
        io << "| Step | Status | Evidence | Summary |\n"
        io << "|---|---:|---:|---|\n"
        investigation.each do |step|
          io << "| " << table_text(step.name) << " | " << step.status << " | " << step.evidence_count << " | " << table_text(step.summary) << " |\n"
        end
        io << "\n"

        io << "## Evidence\n\n"
        evidence.each_with_index do |item, index|
          io << "### " << index + 1 << ". " << item.source << "\n\n"
          io << item.message << "\n\n"
          if data = item.data
            io << "```json\n" << data.to_pretty_json << "\n```\n\n"
          end
        end

        markdown_list(io, "Actions Taken", actions_taken)
        markdown_list(io, "Recommended Next Steps", next_steps)

        io << "## Agent Boundary\n\n"
        io << "This report was generated in report-only mode. The service gathered evidence and produced recommendations, but did not mutate PlaceOS state or execute remediation.\n"
      end
    end

    private def scope_line(io : IO, label : String, value : String?) : Nil
      io << "- " << label << ": " << (value.presence || "not provided") << "\n"
    end

    private def verification_next_steps(run : VerificationRun) : Array(String)
      if retry_at = run.next_retry_at
        next_steps + ["Retry verification after #{retry_at.to_rfc3339}"]
      elsif run.status.failed?
        next_steps + ["Escalate because verification failed after #{run.attempt} attempts"]
      else
        next_steps
      end
    end

    private def markdown_list(io : IO, title : String, items : Array(String)) : Nil
      io << "## " << title << "\n\n"
      if items.empty?
        io << "- None recorded.\n\n"
        return
      end

      items.each { |item| io << "- " << item << "\n" }
      io << "\n"
    end

    private def table_text(value : String) : String
      value.gsub('|', "\\|").gsub('\n', ' ')
    end
  end

  class IncidentClaimInProgress < Exception
    getter incident_id : String
    getter retry_after_seconds : Int32

    def initialize(@incident_id : String, @retry_after_seconds : Int32 = 2)
      super("incident #{incident_id} is already being investigated")
    end
  end

  class IncidentClaimUnavailable < Exception
    getter retry_after_seconds : Int32

    def initialize(error : Exception, @retry_after_seconds : Int32 = 5)
      super("incident claim service is unavailable: #{error.message}", cause: error)
    end
  end

  class IncidentClaimLost < Exception
    getter incident_id : String

    def initialize(@incident_id : String)
      super("incident claim ownership was lost for #{incident_id}")
    end
  end

  struct IncidentClaim
    getter incident_id : String
    getter owner_token : String?
    getter expires_at : Time?
    getter? acquired : Bool

    def self.acquired(incident_id : String, owner_token : String, expires_at : Time) : self
      new(incident_id, owner_token, expires_at, true)
    end

    def self.existing(incident_id : String, expires_at : Time?) : self
      new(incident_id, nil, expires_at, false)
    end

    def token : String
      owner_token || raise ArgumentError.new("incident claim #{incident_id} is not owned")
    end

    private def initialize(
      @incident_id : String,
      @owner_token : String?,
      @expires_at : Time?,
      @acquired : Bool,
    )
    end
  end

  private class IncidentCorrelationLock
    getter mutex = Mutex.new
    property users = 0
  end

  class IncidentClaimHeartbeat
    @stopped = Atomic(Bool).new(false)

    def initialize(
      @store : IncidentStore,
      @claim : IncidentClaim,
      @renewal_interval : Time::Span = INCIDENT_CLAIM_RENEWAL_SECONDS.seconds,
    )
      raise ArgumentError.new("cannot renew an unowned incident claim") unless claim.acquired?

      spawn do
        loop do
          sleep @renewal_interval
          break if @stopped.get
          unless @store.renew_claim(claim)
            AISupportAgent::Log.warn { "incident claim renewal failed for #{claim.incident_id}; final commit will verify ownership" }
            break
          end
        end
      end
    end

    def stop : Nil
      @stopped.set(true)
    end
  end

  struct PersistenceSchemaInventory
    getter tables : Hash(String, Array(String))
    getter indexes : Array(String)
    getter foreign_keys : Array(String)
    getter checks : Array(String)

    def self.from_database : self
      tables = {} of String => Array(String)
      PgORM::Database.info.table_infos.each do |table|
        tables[table.table_name] = table.column_names
      end

      indexes = PgORM::Database.connection do |database|
        database.query_all(
          "SELECT indexname FROM pg_indexes WHERE schemaname = 'public'",
          &.read(String)
        )
      end
      foreign_keys = PgORM::Database.connection do |database|
        query = <<-SQL
          SELECT constraint_name
          FROM information_schema.table_constraints
          WHERE table_schema = 'public' AND constraint_type = 'FOREIGN KEY'
          SQL
        database.query_all(query, &.read(String))
      end
      checks = PgORM::Database.connection do |database|
        query = <<-SQL
          SELECT constraint_name
          FROM information_schema.table_constraints
          WHERE table_schema = 'public' AND constraint_type = 'CHECK'
          SQL
        database.query_all(query, &.read(String))
      end

      new(tables, indexes, foreign_keys, checks)
    end

    def initialize(
      @tables : Hash(String, Array(String)),
      @indexes : Array(String),
      @foreign_keys : Array(String),
      @checks : Array(String),
    )
    end
  end

  struct PersistenceSchemaStatus
    include JSON::Serializable

    getter state : String
    getter missing_tables : Array(String)
    getter missing_columns : Hash(String, Array(String))
    getter missing_indexes : Array(String)
    getter missing_foreign_keys : Array(String)
    getter missing_checks : Array(String)
    getter error : String?
    getter checked_at : Time?

    def self.unconfigured : self
      new("unconfigured")
    end

    def self.unavailable(error : Exception) : self
      new("unavailable", error: "#{error.class}: #{error.message}", checked_at: Time.utc)
    end

    def initialize(
      @state : String,
      @missing_tables : Array(String) = [] of String,
      @missing_columns : Hash(String, Array(String)) = {} of String => Array(String),
      @missing_indexes : Array(String) = [] of String,
      @missing_foreign_keys : Array(String) = [] of String,
      @missing_checks : Array(String) = [] of String,
      @error : String? = nil,
      @checked_at : Time? = nil,
    )
    end

    def ready? : Bool
      state == "ready"
    end

    def summary : String
      return "persistence schema is ready" if ready?
      return error || "persistence schema is unavailable" if state == "unavailable"
      return "persistence schema has not been checked" if state == "unconfigured"

      details = [] of String
      details << "tables: #{missing_tables.join(", ")}" unless missing_tables.empty?
      missing_columns.each do |table, columns|
        details << "#{table} columns: #{columns.join(", ")}"
      end
      details << "indexes: #{missing_indexes.join(", ")}" unless missing_indexes.empty?
      details << "foreign keys: #{missing_foreign_keys.join(", ")}" unless missing_foreign_keys.empty?
      details << "checks: #{missing_checks.join(", ")}" unless missing_checks.empty?
      "persistence schema is incomplete (#{details.join("; ")})"
    end
  end

  module PersistenceSchema
    REQUIRED_COLUMNS = {
      "ai_incidents" => %w[
        id status severity source classification confidence summary correlation_key
        report_schema_version tenant_id system_id module_id module_name module_index
        duplicate_count last_seen_at resolved_at claim_token claim_expires_at created_at updated_at
      ],
      "ai_incident_events" => %w[
        id incident_id source severity correlation_key payload received_at created_at updated_at
      ],
      "ai_incident_reports" => %w[
        id incident_id report_schema_version status classification confidence report_json
        evidence_json investigation_json decision_json markdown created_at updated_at
      ],
      "ai_agent_runs" => %w[
        id incident_id correlation_key classification confidence plan_json investigation_json
        decision_json remediation_proposal_json created_at updated_at
      ],
      "ai_approval_requests" => %w[
        id incident_id status requested_by request_note decided_by decision_note proposal_json
        execution_mode decided_at executed_at created_at updated_at
      ],
      "ai_report_deliveries" => %w[
        id incident_id status destination attempted_at response_status error created_at updated_at
      ],
      "ai_verification_runs" => %w[
        id incident_id procedure_id procedure_version procedure_hash attempt status checks_json
        evidence_json started_at completed_at next_retry_at
      ],
      "ai_escalation_records" => %w[
        id incident_id procedure_id procedure_version procedure_hash owner_queue response_sla_minutes
        reason required_artefacts_json delivery_status delivery_destination delivery_error
        response_due_at escalated_at
      ],
      "ai_maintenance_runs" => %w[
        id procedure_id procedure_version procedure_hash schedule_bucket status target_count
        incident_ids_json classification_counts_json started_at completed_at error
      ],
      "ai_correlation_findings" => %w[
        id deduplication_key kind policy_id policy_version policy_hash scope_key tenant_id system_id
        module_id classification incident_ids_json observation_count transition_count window_start
        window_end summary detected_at
      ],
      "ai_incident_feedback" => %w[
        id incident_id rating submitted_by comment submitted_at
      ],
      "ai_trend_reports" => %w[
        id policy_id policy_version policy_hash window_start window_end summary_json markdown generated_at
      ],
    }

    REQUIRED_INDEXES = %w[
      ai_incidents_active_correlation_key_index
      ai_incidents_claim_expires_at_index
      ai_incident_events_incident_id_index
      ai_incident_reports_incident_id_index
      ai_agent_runs_incident_id_index
      ai_approval_requests_incident_id_index
      ai_report_deliveries_incident_id_index
      ai_verification_runs_incident_id_index
      ai_escalation_records_incident_id_index
      ai_maintenance_runs_window_index
      ai_correlation_findings_deduplication_key_index
      ai_incident_feedback_incident_id_index
      ai_trend_reports_generated_at_index
    ]

    REQUIRED_FOREIGN_KEYS = %w[
      ai_incident_events_incident_id_fkey
      ai_incident_reports_incident_id_fkey
      ai_agent_runs_incident_id_fkey
      ai_approval_requests_incident_id_fkey
      ai_report_deliveries_incident_id_fkey
      ai_verification_runs_incident_id_fkey
      ai_escalation_records_incident_id_fkey
      ai_incident_feedback_incident_id_fkey
    ]

    REQUIRED_CHECKS = %w[
      ai_incidents_claim_state_check
    ]

    def self.validate(inventory : PersistenceSchemaInventory, checked_at : Time = Time.utc) : PersistenceSchemaStatus
      missing_tables = REQUIRED_COLUMNS.keys.reject { |table| inventory.tables.has_key?(table) }.sort!
      missing_columns = {} of String => Array(String)
      REQUIRED_COLUMNS.each do |table, required|
        next unless actual = inventory.tables[table]?
        missing = required.reject { |column| actual.includes?(column) }.sort!
        missing_columns[table] = missing unless missing.empty?
      end
      missing_indexes = REQUIRED_INDEXES.reject { |index| inventory.indexes.includes?(index) }.sort!
      missing_foreign_keys = REQUIRED_FOREIGN_KEYS.reject { |key| inventory.foreign_keys.includes?(key) }.sort!
      missing_checks = REQUIRED_CHECKS.reject { |check| inventory.checks.includes?(check) }.sort!
      ready = missing_tables.empty? && missing_columns.empty? && missing_indexes.empty? &&
              missing_foreign_keys.empty? && missing_checks.empty?

      PersistenceSchemaStatus.new(
        ready ? "ready" : "invalid",
        missing_tables: missing_tables,
        missing_columns: missing_columns,
        missing_indexes: missing_indexes,
        missing_foreign_keys: missing_foreign_keys,
        missing_checks: missing_checks,
        checked_at: checked_at
      )
    end
  end

  class IncidentStore
    @reports = {} of String => IncidentReport
    @correlation_index = {} of String => String
    @observations = [] of IncidentObservation
    @correlation_locks = {} of String => IncidentCorrelationLock
    @repository : PostgresIncidentRepository?
    @persistence_error : String?
    @lock = Mutex.new
    @correlation_locks_guard = Mutex.new

    def persist_with(@repository : PostgresIncidentRepository) : Nil
    end

    def disable_persistence : Nil
      @repository = nil
      @persistence_error = nil
    end

    def persistence_enabled? : Bool
      !!@repository
    end

    def persistence_error : String?
      @persistence_error
    end

    def save(
      report : IncidentReport,
      event : IncidentEvent? = nil,
      observed_at : Time = Time.utc,
      claim_token : String? = nil,
    ) : IncidentReport
      if token = claim_token
        persist_claimed(report, event, token)
      else
        persist(&.save_report(report, event))
      end

      @lock.synchronize do
        @reports[report.incident_id] = report
        if report.status.resolved?
          @correlation_index.delete(report.correlation_key)
        else
          @correlation_index[report.correlation_key] = report.incident_id
        end
        @observations << IncidentObservation.from(report, observed_at)
      end
      report
    end

    def claim(event : IncidentEvent, incident_id : String) : IncidentClaim?
      return unless repository = @repository

      token = UUID.random.to_s
      claim = repository.claim_incident(event, incident_id, token)
      @persistence_error = nil
      claim
    rescue error
      record_persistence_error(error, "incident claim failed; refusing an uncoordinated incident")
      raise IncidentClaimUnavailable.new(error)
    end

    def renew_claim(claim : IncidentClaim) : Bool
      return false unless repository = @repository

      renewed = repository.renew_incident_claim(
        claim.incident_id,
        claim.token
      )
      @persistence_error = nil if renewed
      renewed
    rescue error
      record_persistence_error(error, "incident claim renewal failed")
      false
    end

    def wait_for_report(
      incident_id : String,
      wait_milliseconds : Int32 = INCIDENT_CLAIM_WAIT_MILLISECONDS,
    ) : IncidentReport?
      deadline = Time.instant + wait_milliseconds.milliseconds
      loop do
        if report = find(incident_id)
          return report
        end
        return if Time.instant >= deadline
        sleep INCIDENT_CLAIM_POLL_MILLISECONDS.milliseconds
      end
    end

    def synchronize_correlation(correlation_key : String, & : -> T) : T forall T
      entry = @correlation_locks_guard.synchronize do
        lock = @correlation_locks[correlation_key] ||= IncidentCorrelationLock.new
        lock.users += 1
        lock
      end

      begin
        entry.mutex.synchronize { yield }
      ensure
        @correlation_locks_guard.synchronize do
          entry.users -= 1
          @correlation_locks.delete(correlation_key) if entry.users == 0
        end
      end
    end

    def find_by_correlation_key(correlation_key : String) : IncidentReport?
      @lock.synchronize do
        if incident_id = @correlation_index[correlation_key]?
          @reports[incident_id]?
        end
      end || persist(&.find_by_correlation_key(correlation_key))
    end

    def all : Array(IncidentReport)
      persist(&.all_reports) || @lock.synchronize { @reports.values.sort_by!(&.created_at) }
    end

    def find(id : String) : IncidentReport?
      @lock.synchronize { @reports[id]? } || persist(&.find_report(id))
    end

    def observations_since(time : Time) : Array(IncidentObservation)
      memory = @lock.synchronize { @observations.select { |observation| observation.observed_at >= time } }
      return memory if @persistence_error
      persisted = persist(&.incident_observations_since(time))
      return persisted if persisted && !persisted.empty?
      memory
    end

    def clear : Nil
      @lock.synchronize do
        @reports.clear
        @correlation_index.clear
        @observations.clear
      end
    end

    private def persist(& : PostgresIncidentRepository -> T) : T? forall T
      return unless repository = @repository

      value = yield repository
      @persistence_error = nil
      value
    rescue error
      record_persistence_error(error, "incident persistence failed; continuing with in-memory store")
      nil
    end

    private def persist_claimed(report : IncidentReport, event : IncidentEvent?, token : String) : Nil
      repository = @repository || raise IncidentClaimLost.new(report.incident_id)
      repository.save_report(report, event, token)
      @persistence_error = nil
    rescue error : IncidentClaimLost
      raise error
    rescue error
      record_persistence_error(error, "claimed incident persistence failed; refusing an uncommitted report")
      raise error
    end

    private def record_persistence_error(error : Exception, message : String) : Nil
      @persistence_error = "#{error.class}: #{error.message}"
      AISupportAgent::Log.warn(exception: error) { message }
    end
  end

  class PostgresIncidentRepository
    def persistence_schema_status : PersistenceSchemaStatus
      PersistenceSchema.validate(PersistenceSchemaInventory.from_database)
    rescue error
      PersistenceSchemaStatus.unavailable(error)
    end

    def claim_incident(
      event : IncidentEvent,
      incident_id : String,
      owner_token : String,
      lease_seconds : Int32 = INCIDENT_CLAIM_LEASE_SECONDS,
    ) : IncidentClaim
      claim : IncidentClaim? = nil
      PgORM::Database.transaction do
        acquired = PgORM::Database.connection do |database|
          database.query_one?(
            <<-SQL,
              INSERT INTO ai_incidents (
                id, status, severity, source, classification, confidence, summary,
                correlation_key, report_schema_version, tenant_id, system_id, module_id,
                module_name, module_index, duplicate_count, last_seen_at, resolved_at,
                claim_token, claim_expires_at, created_at, updated_at
              )
              VALUES (
                $1, 'investigating', $2, $3, 'unknown', 0.0, '', $4,
                'incident-report.v1', $5, $6, $7, $8, $9, 0, clock_timestamp(), NULL,
                $10, clock_timestamp() + ($11 * INTERVAL '1 second'),
                clock_timestamp(), clock_timestamp()
              )
              ON CONFLICT (correlation_key) WHERE resolved_at IS NULL
              DO UPDATE SET
                claim_token = EXCLUDED.claim_token,
                claim_expires_at = EXCLUDED.claim_expires_at,
                updated_at = clock_timestamp()
              WHERE ai_incidents.status = 'investigating'
                AND ai_incidents.claim_expires_at <= clock_timestamp()
              RETURNING id, claim_token, claim_expires_at
              SQL
            incident_id,
            event.severity.to_s.downcase,
            event.source.to_s.downcase,
            event.correlation_key,
            event.tenant_id,
            event.system_id,
            event.module_id,
            event.module_name,
            event.module_index,
            owner_token,
            lease_seconds
          ) do |result|
            IncidentClaim.acquired(
              result.read(String),
              result.read(String),
              result.read(Time)
            )
          end
        end

        if acquired
          claim = acquired
          next
        end

        existing = PgORM::Database.connection do |database|
          database.query_one?(
            <<-SQL,
              SELECT id, claim_expires_at
              FROM ai_incidents
              WHERE correlation_key = $1 AND resolved_at IS NULL
              ORDER BY created_at DESC
              LIMIT 1
              FOR UPDATE
              SQL
            args: [event.correlation_key]
          ) do |result|
            IncidentClaim.existing(result.read(String), result.read(Time?))
          end
        end
        raise "active incident conflict did not return a database row" unless existing

        claim = existing
      end
      claim || raise "incident claim transaction returned no result"
    end

    def renew_incident_claim(
      incident_id : String,
      owner_token : String,
      lease_seconds : Int32 = INCIDENT_CLAIM_LEASE_SECONDS,
    ) : Bool
      renewed = PgORM::Database.connection do |database|
        database.query_one?(
          <<-SQL,
            UPDATE ai_incidents
            SET
              claim_expires_at = clock_timestamp() + ($1 * INTERVAL '1 second'),
              updated_at = clock_timestamp()
            WHERE id = $2 AND status = 'investigating' AND claim_token = $3
            RETURNING id
            SQL
          lease_seconds,
          incident_id,
          owner_token,
          &.read(String)
        )
      end
      !!renewed
    end

    def save_report(
      report : IncidentReport,
      event : IncidentEvent? = nil,
      claim_token : String? = nil,
    ) : IncidentReport
      PgORM::Database.transaction do
        incident = ::PlaceOS::Model::AiIncident.find?(report.incident_id) || ::PlaceOS::Model::AiIncident.new
        if token = claim_token
          persisted_token = PgORM::Database.connection do |database|
            database.query_one?(
              "SELECT claim_token FROM ai_incidents WHERE id = $1 FOR UPDATE",
              args: [report.incident_id],
              &.read(String?)
            )
          end
          raise IncidentClaimLost.new(report.incident_id) unless persisted_token == token
        end

        incident.id = report.incident_id
        incident.status = report.status.to_s.downcase
        incident.severity = report.severity.to_s.downcase
        incident.source = report.source.to_s.downcase
        incident.classification = report.classification.to_s
        incident.confidence = report.confidence
        incident.summary = report.summary
        incident.correlation_key = report.correlation_key
        incident.report_schema_version = report.report_schema_version
        incident.tenant_id = report.tenant_id
        incident.system_id = report.system_id
        incident.module_id = report.module_id
        incident.module_name = report.module_name
        incident.module_index = report.module_index
        incident.duplicate_count = report.duplicate_count
        incident.last_seen_at = report.last_seen_at
        incident.resolved_at = report.resolved_at
        incident.claim_token = nil
        incident.claim_expires_at = nil
        incident.save!

        save_event(incident.id.as(String), event) if event
        save_snapshot(report)
      end
      report
    end

    def find_report(id : String) : IncidentReport?
      latest_report(id)
    end

    def find_by_correlation_key(correlation_key : String) : IncidentReport?
      incident = ::PlaceOS::Model::AiIncident.where(correlation_key: correlation_key, resolved_at: nil).order(created_at: :desc).limit(1).to_a.first?
      incident.try { |model| latest_report(model.id.as(String)) }
    end

    def all_reports : Array(IncidentReport)
      ::PlaceOS::Model::AiIncident.order(created_at: :asc).to_a.compact_map do |incident|
        latest_report(incident.id.as(String))
      end
    end

    def incident_observations_since(time : Time) : Array(IncidentObservation)
      ::PlaceOS::Model::AiIncidentReport.where("created_at >= ?", time).order(created_at: :asc).to_a.map do |snapshot|
        report = IncidentReport.from_json(snapshot.report_json.to_json)
        IncidentObservation.from(report, snapshot.created_at || time)
      end
    end

    def save_run(run : AgentRun) : AgentRun
      model = ::PlaceOS::Model::AiAgentRun.new
      model.incident_id = run.incident_id
      model.correlation_key = run.correlation_key
      model.classification = run.classification.to_s
      model.confidence = run.confidence
      model.plan_json = run.investigation_plan.try { |plan| JSON.parse(plan.to_json) }
      model.investigation_json = JSON.parse(run.investigation.to_json)
      model.decision_json = run.decision.try { |decision| JSON.parse(decision.to_json) }
      model.remediation_proposal_json = run.remediation_proposal.try { |proposal| JSON.parse(proposal.to_json) }
      model.save!
      run
    end

    def find_run(id : String) : AgentRun?
      model = ::PlaceOS::Model::AiAgentRun.where(incident_id: id).order(created_at: :desc).limit(1).to_a.first?
      model.try { |run| run_from_model(run) }
    end

    def all_runs : Array(AgentRun)
      ::PlaceOS::Model::AiAgentRun.order(created_at: :asc).to_a.map { |run| run_from_model(run) }
    end

    def save_delivery(record : ReportDeliveryRecord) : ReportDeliveryRecord
      model = ::PlaceOS::Model::AiReportDelivery.new
      model.incident_id = record.incident_id
      model.status = record.status.to_s.downcase
      model.destination = record.destination
      model.attempted_at = record.attempted_at
      model.response_status = record.response_status
      model.error = record.error
      model.save!
      record
    end

    def deliveries_for_incident(incident_id : String) : Array(ReportDeliveryRecord)
      ::PlaceOS::Model::AiReportDelivery.where(incident_id: incident_id).order(attempted_at: :asc).to_a.map do |delivery|
        delivery_from_model(delivery)
      end
    end

    def all_deliveries : Array(ReportDeliveryRecord)
      ::PlaceOS::Model::AiReportDelivery.order(attempted_at: :asc).to_a.map do |delivery|
        delivery_from_model(delivery)
      end
    end

    def save_approval_request(request : ApprovalRequest) : ApprovalRequest
      model = ::PlaceOS::Model::AiApprovalRequest.find?(request.id) || ::PlaceOS::Model::AiApprovalRequest.new
      model.id = request.id
      model.incident_id = request.incident_id
      model.status = request.status.to_s.downcase
      model.requested_by = request.requested_by
      model.request_note = request.request_note
      model.decided_by = request.decided_by
      model.decision_note = request.decision_note
      model.proposal_json = JSON.parse(request.proposal.to_json)
      model.execution_mode = request.execution_mode
      model.decided_at = request.decided_at
      model.executed_at = request.executed_at
      model.save!
      request
    end

    def find_approval_request(id : String) : ApprovalRequest?
      ::PlaceOS::Model::AiApprovalRequest.find?(id).try { |request| approval_request_from_model(request) }
    end

    def approval_requests_for_incident(incident_id : String) : Array(ApprovalRequest)
      ::PlaceOS::Model::AiApprovalRequest.where(incident_id: incident_id).order(created_at: :asc).to_a.map do |request|
        approval_request_from_model(request)
      end
    end

    def save_verification_run(run : VerificationRun) : VerificationRun
      model = ::PlaceOS::Model::AiVerificationRun.find?(run.id) || ::PlaceOS::Model::AiVerificationRun.new
      model.id = run.id
      model.incident_id = run.incident_id
      model.procedure_id = run.procedure.id
      model.procedure_version = run.procedure.version
      model.procedure_hash = run.procedure.content_hash
      model.attempt = run.attempt
      model.status = verification_status_key(run.status)
      model.checks_json = JSON.parse(run.checks.to_json)
      model.evidence_json = JSON.parse(run.evidence.to_json)
      model.started_at = run.started_at
      model.completed_at = run.completed_at
      model.next_retry_at = run.next_retry_at
      model.save!
      run
    end

    def verification_runs_for_incident(incident_id : String) : Array(VerificationRun)
      ::PlaceOS::Model::AiVerificationRun.where(incident_id: incident_id).order(started_at: :asc).to_a.map do |run|
        verification_run_from_model(run)
      end
    end

    def all_verification_runs : Array(VerificationRun)
      ::PlaceOS::Model::AiVerificationRun.order(started_at: :asc).to_a.map do |run|
        verification_run_from_model(run)
      end
    end

    def save_escalation_record(record : EscalationRecord) : EscalationRecord
      model = ::PlaceOS::Model::AiEscalationRecord.find?(record.id) || ::PlaceOS::Model::AiEscalationRecord.new
      model.id = record.id
      model.incident_id = record.incident_id
      model.procedure_id = record.plan.procedure.id
      model.procedure_version = record.plan.procedure.version
      model.procedure_hash = record.plan.procedure.content_hash
      model.owner_queue = record.plan.owner_queue
      model.response_sla_minutes = record.plan.response_sla_minutes
      model.reason = record.plan.reason
      model.required_artefacts_json = JSON.parse(record.plan.required_artefacts.to_json)
      model.delivery_status = report_delivery_status_key(record.delivery_status)
      model.delivery_destination = record.delivery_destination
      model.delivery_error = record.delivery_error
      model.response_due_at = record.response_due_at
      model.escalated_at = record.created_at
      model.save!
      record
    end

    def escalation_records_for_incident(incident_id : String) : Array(EscalationRecord)
      ::PlaceOS::Model::AiEscalationRecord.where(incident_id: incident_id).order(escalated_at: :asc).to_a.map do |record|
        escalation_record_from_model(record)
      end
    end

    def all_escalation_records : Array(EscalationRecord)
      ::PlaceOS::Model::AiEscalationRecord.order(escalated_at: :asc).to_a.map do |record|
        escalation_record_from_model(record)
      end
    end

    def save_maintenance_run(run : MaintenanceRun) : MaintenanceRun
      existing = find_maintenance_run(run.procedure.id, run.procedure.version, run.schedule_bucket)
      return existing if existing

      model = ::PlaceOS::Model::AiMaintenanceRun.find?(run.id) || ::PlaceOS::Model::AiMaintenanceRun.new
      model.id = run.id
      model.procedure_id = run.procedure.id
      model.procedure_version = run.procedure.version
      model.procedure_hash = run.procedure.content_hash
      model.schedule_bucket = run.schedule_bucket
      model.status = maintenance_run_status_key(run.status)
      model.target_count = run.target_count
      model.incident_ids_json = JSON.parse(run.incident_ids.to_json)
      model.classification_counts_json = JSON.parse(run.classification_counts.to_json)
      model.started_at = run.started_at
      model.completed_at = run.completed_at
      model.error = run.error
      model.save!
      run
    end

    def find_maintenance_run(procedure_id : String, procedure_version : Int32, schedule_bucket : Int64) : MaintenanceRun?
      ::PlaceOS::Model::AiMaintenanceRun
        .where(procedure_id: procedure_id, procedure_version: procedure_version, schedule_bucket: schedule_bucket)
        .limit(1)
        .to_a
        .first?
        .try { |run| maintenance_run_from_model(run) }
    end

    def all_maintenance_runs : Array(MaintenanceRun)
      ::PlaceOS::Model::AiMaintenanceRun.order(started_at: :asc).to_a.map do |run|
        maintenance_run_from_model(run)
      end
    end

    def save_correlation_finding(finding : CorrelationFinding) : CorrelationFinding
      existing = find_correlation_finding(finding.deduplication_key)
      return existing if existing

      model = ::PlaceOS::Model::AiCorrelationFinding.find?(finding.id) || ::PlaceOS::Model::AiCorrelationFinding.new
      model.id = finding.id
      model.deduplication_key = finding.deduplication_key
      model.kind = correlation_kind_key(finding.kind)
      model.policy_id = finding.policy.id
      model.policy_version = finding.policy.version
      model.policy_hash = finding.policy.content_hash
      model.scope_key = finding.scope_key
      model.tenant_id = finding.tenant_id
      model.system_id = finding.system_id
      model.module_id = finding.module_id
      model.classification = finding.classification.to_s
      model.incident_ids_json = JSON.parse(finding.incident_ids.to_json)
      model.observation_count = finding.observation_count
      model.transition_count = finding.transition_count
      model.window_start = finding.window_start
      model.window_end = finding.window_end
      model.summary = finding.summary
      model.detected_at = finding.created_at
      model.save!
      finding
    end

    def find_correlation_finding(key : String) : CorrelationFinding?
      ::PlaceOS::Model::AiCorrelationFinding.find_by?(deduplication_key: key).try do |finding|
        correlation_finding_from_model(finding)
      end
    end

    def all_correlation_findings : Array(CorrelationFinding)
      ::PlaceOS::Model::AiCorrelationFinding.order(detected_at: :asc).to_a.map do |finding|
        correlation_finding_from_model(finding)
      end
    end

    def save_incident_feedback(record : IncidentFeedback) : IncidentFeedback
      model = ::PlaceOS::Model::AiIncidentFeedback.find?(record.id) || ::PlaceOS::Model::AiIncidentFeedback.new
      model.id = record.id
      model.incident_id = record.incident_id
      model.rating = feedback_rating_key(record.rating)
      model.submitted_by = record.submitted_by
      model.comment = record.comment
      model.submitted_at = record.created_at
      model.save!
      record
    end

    def incident_feedback_for(incident_id : String) : Array(IncidentFeedback)
      ::PlaceOS::Model::AiIncidentFeedback.where(incident_id: incident_id).order(submitted_at: :asc).to_a.map do |record|
        incident_feedback_from_model(record)
      end
    end

    def all_incident_feedback : Array(IncidentFeedback)
      ::PlaceOS::Model::AiIncidentFeedback.order(submitted_at: :asc).to_a.map do |record|
        incident_feedback_from_model(record)
      end
    end

    def save_trend_report(report : TrendReport) : TrendReport
      model = ::PlaceOS::Model::AiTrendReport.find?(report.id) || ::PlaceOS::Model::AiTrendReport.new
      model.id = report.id
      model.policy_id = report.policy.id
      model.policy_version = report.policy.version
      model.policy_hash = report.policy.content_hash
      model.window_start = report.summary.window_start
      model.window_end = report.summary.window_end
      model.summary_json = JSON.parse(report.summary.to_json)
      model.markdown = report.markdown
      model.generated_at = report.generated_at
      model.save!
      report
    end

    def find_trend_report(id : String) : TrendReport?
      ::PlaceOS::Model::AiTrendReport.find?(id).try { |report| trend_report_from_model(report) }
    end

    def all_trend_reports : Array(TrendReport)
      ::PlaceOS::Model::AiTrendReport.order(generated_at: :asc).to_a.map { |report| trend_report_from_model(report) }
    end

    private def latest_report(incident_id : String) : IncidentReport?
      report = ::PlaceOS::Model::AiIncidentReport.where(incident_id: incident_id).order(created_at: :desc).limit(1).to_a.first?
      report.try { |model| IncidentReport.from_json(model.report_json.to_json) }
    end

    private def save_event(incident_id : String, event : IncidentEvent) : Nil
      model = ::PlaceOS::Model::AiIncidentEvent.new
      model.incident_id = incident_id
      model.source = event.source.to_s.downcase
      model.severity = event.severity.to_s.downcase
      model.correlation_key = event.correlation_key
      model.payload = event.payload
      model.received_at = Time.utc
      model.save!
    end

    private def save_snapshot(report : IncidentReport) : Nil
      model = ::PlaceOS::Model::AiIncidentReport.new
      model.incident_id = report.incident_id
      model.report_schema_version = report.report_schema_version
      model.status = report.status.to_s.downcase
      model.classification = report.classification.to_s
      model.confidence = report.confidence
      model.report_json = JSON.parse(report.to_json)
      model.evidence_json = JSON.parse(report.evidence.to_json)
      model.investigation_json = JSON.parse(report.investigation.to_json)
      model.decision_json = report.decision.try { |decision| JSON.parse(decision.to_json) }
      model.markdown = report.to_markdown
      model.save!
    end

    private def run_from_model(model : ::PlaceOS::Model::AiAgentRun) : AgentRun
      AgentRun.new(
        incident_id: model.incident_id.as(String),
        correlation_key: model.correlation_key.as(String),
        classification: DiagnosticClassification.parse(model.classification),
        confidence: model.confidence,
        investigation_plan: deserialize_optional_json(model.plan_json, InvestigationPlan),
        investigation: Array(InvestigationStep).from_json(model.investigation_json.to_json),
        decision: deserialize_optional_json(model.decision_json, AgentDecision),
        remediation_proposal: deserialize_optional_json(model.remediation_proposal_json, RemediationProposal),
        created_at: model.created_at || Time.utc
      )
    end

    private def deserialize_optional_json(value : JSON::Any?, type : T.class) : T? forall T
      return if value.nil? || value.raw.nil?

      T.from_json(value.to_json)
    end

    private def approval_request_from_model(model : ::PlaceOS::Model::AiApprovalRequest) : ApprovalRequest
      ApprovalRequest.new(
        id: model.id.as(String),
        incident_id: model.incident_id.as(String),
        status: approval_status(model.status),
        requested_by: model.requested_by,
        request_note: model.request_note,
        decided_by: model.decided_by,
        decision_note: model.decision_note,
        proposal: RemediationProposal.from_json(model.proposal_json.to_json),
        execution_mode: model.execution_mode,
        created_at: model.created_at || Time.utc,
        decided_at: model.decided_at,
        executed_at: model.executed_at
      )
    end

    private def delivery_from_model(model : ::PlaceOS::Model::AiReportDelivery) : ReportDeliveryRecord
      ReportDeliveryRecord.new(
        incident_id: model.incident_id.as(String),
        status: report_delivery_status(model.status),
        destination: model.destination,
        attempted_at: model.attempted_at,
        response_status: model.response_status,
        error: model.error
      )
    end

    private def verification_run_from_model(model : ::PlaceOS::Model::AiVerificationRun) : VerificationRun
      VerificationRun.new(
        id: model.id.as(String),
        incident_id: model.incident_id.as(String),
        procedure: ProcedureAudit.new(
          "verification",
          model.procedure_id,
          model.procedure_version,
          model.procedure_hash
        ),
        attempt: model.attempt,
        status: verification_run_status(model.status),
        checks: Array(VerificationCheckResult).from_json(model.checks_json.to_json),
        evidence: Array(Evidence).from_json(model.evidence_json.to_json),
        started_at: model.started_at,
        completed_at: model.completed_at,
        next_retry_at: model.next_retry_at
      )
    end

    private def escalation_record_from_model(model : ::PlaceOS::Model::AiEscalationRecord) : EscalationRecord
      procedure = ProcedureAudit.new(
        "escalation",
        model.procedure_id,
        model.procedure_version,
        model.procedure_hash
      )
      EscalationRecord.new(
        id: model.id.as(String),
        incident_id: model.incident_id.as(String),
        plan: EscalationPlan.new(
          procedure: procedure,
          owner_queue: model.owner_queue,
          response_sla_minutes: model.response_sla_minutes,
          required_artefacts: Array(String).from_json(model.required_artefacts_json.to_json),
          reason: model.reason
        ),
        delivery_status: report_delivery_status(model.delivery_status),
        delivery_destination: model.delivery_destination,
        delivery_error: model.delivery_error,
        created_at: model.escalated_at,
        response_due_at: model.response_due_at
      )
    end

    private def maintenance_run_from_model(model : ::PlaceOS::Model::AiMaintenanceRun) : MaintenanceRun
      MaintenanceRun.new(
        id: model.id.as(String),
        procedure: ProcedureAudit.new(
          "maintenance",
          model.procedure_id,
          model.procedure_version,
          model.procedure_hash
        ),
        schedule_bucket: model.schedule_bucket,
        status: maintenance_run_status(model.status),
        target_count: model.target_count,
        incident_ids: Array(String).from_json(model.incident_ids_json.to_json),
        classification_counts: Hash(String, Int32).from_json(model.classification_counts_json.to_json),
        started_at: model.started_at,
        completed_at: model.completed_at,
        error: model.error
      )
    end

    private def correlation_finding_from_model(model : ::PlaceOS::Model::AiCorrelationFinding) : CorrelationFinding
      CorrelationFinding.new(
        id: model.id.as(String),
        deduplication_key: model.deduplication_key,
        kind: correlation_kind(model.kind),
        policy: ProcedureAudit.new("correlation", model.policy_id, model.policy_version, model.policy_hash),
        scope_key: model.scope_key,
        tenant_id: model.tenant_id,
        system_id: model.system_id,
        module_id: model.module_id,
        classification: DiagnosticClassification.parse(model.classification),
        incident_ids: Array(String).from_json(model.incident_ids_json.to_json),
        observation_count: model.observation_count,
        transition_count: model.transition_count,
        window_start: model.window_start,
        window_end: model.window_end,
        summary: model.summary,
        created_at: model.detected_at
      )
    end

    private def incident_feedback_from_model(model : ::PlaceOS::Model::AiIncidentFeedback) : IncidentFeedback
      IncidentFeedback.new(
        id: model.id.as(String),
        incident_id: model.incident_id.as(String),
        rating: FeedbackRating.from_api(model.rating),
        submitted_by: model.submitted_by,
        comment: model.comment,
        created_at: model.submitted_at
      )
    end

    private def trend_report_from_model(model : ::PlaceOS::Model::AiTrendReport) : TrendReport
      TrendReport.new(
        id: model.id.as(String),
        policy: ProcedureAudit.new("correlation", model.policy_id, model.policy_version, model.policy_hash),
        summary: TrendSummary.from_json(model.summary_json.to_json),
        markdown: model.markdown,
        generated_at: model.generated_at
      )
    end

    private def report_delivery_status_key(status : ReportDeliveryStatus) : String
      case status
      in .skipped?   then "skipped"
      in .delivered? then "delivered"
      in .failed?    then "failed"
      end
    end

    private def verification_status_key(status : VerificationRunStatus) : String
      case status
      in .verified?        then "verified"
      in .retry_scheduled? then "retry_scheduled"
      in .failed?          then "failed"
      end
    end

    private def maintenance_run_status_key(status : MaintenanceRunStatus) : String
      case status
      in .completed? then "completed"
      in .skipped?   then "skipped"
      in .failed?    then "failed"
      end
    end

    private def maintenance_run_status(value : String) : MaintenanceRunStatus
      case value
      when "completed" then MaintenanceRunStatus::Completed
      when "skipped"   then MaintenanceRunStatus::Skipped
      when "failed"    then MaintenanceRunStatus::Failed
      else                  MaintenanceRunStatus.parse(value)
      end
    end

    private def correlation_kind_key(kind : CorrelationKind) : String
      kind.key
    end

    private def correlation_kind(value : String) : CorrelationKind
      case value
      when "repeated_incident" then CorrelationKind::RepeatedIncident
      when "flapping"          then CorrelationKind::Flapping
      when "noisy_signals"     then CorrelationKind::NoisySignals
      else                          CorrelationKind.parse(value)
      end
    end

    private def feedback_rating_key(rating : FeedbackRating) : String
      rating.key
    end

    private def verification_run_status(value : String) : VerificationRunStatus
      case value
      when "verified"        then VerificationRunStatus::Verified
      when "retry_scheduled" then VerificationRunStatus::RetryScheduled
      when "failed"          then VerificationRunStatus::Failed
      else                        VerificationRunStatus.parse(value)
      end
    end

    private def report_delivery_status(value : String) : ReportDeliveryStatus
      case value
      when "skipped"
        ReportDeliveryStatus::Skipped
      when "delivered"
        ReportDeliveryStatus::Delivered
      when "failed"
        ReportDeliveryStatus::Failed
      else
        ReportDeliveryStatus.parse(value)
      end
    end

    private def approval_status(value : String) : ApprovalRequestStatus
      case value
      when "pending"
        ApprovalRequestStatus::Pending
      when "approved"
        ApprovalRequestStatus::Approved
      when "rejected"
        ApprovalRequestStatus::Rejected
      else
        ApprovalRequestStatus.parse(value)
      end
    end
  end
end
