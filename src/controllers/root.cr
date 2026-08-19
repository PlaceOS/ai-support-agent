module AISupportAgent
  class Root < Application
    base "/api/ai-support/v1/"

    struct Version
      include JSON::Serializable

      getter version : String
      getter build_time : String
      getter commit : String
      getter service : String

      def initialize(@version, @build_time, @commit, @service)
      end
    end

    struct Status
      include JSON::Serializable

      getter service : String
      getter? database_configured : Bool
      getter? persistence_enabled : Bool
      getter persistence_schema : PersistenceSchemaStatus
      getter incident_persistence_error : String?
      getter agent_run_persistence_error : String?
      getter report_delivery_persistence_error : String?
      getter approval_persistence_error : String?
      getter verification_persistence_error : String?
      getter escalation_persistence_error : String?
      getter maintenance_persistence_error : String?
      getter correlation_persistence_error : String?
      getter feedback_persistence_error : String?
      getter trend_persistence_error : String?
      getter report_count : Int32
      getter playbook_count : Int32
      getter playbook_path : String
      getter playbook_reload_error : String?
      getter workflow_count : Int32
      getter diagnostic_procedure_count : Int32
      getter remediation_procedure_count : Int32
      getter verification_procedure_count : Int32
      getter verification_run_count : Int32
      getter escalation_procedure_count : Int32
      getter escalation_record_count : Int32
      getter maintenance_procedure_count : Int32
      getter maintenance_run_count : Int32
      getter correlation_policy_count : Int32
      getter correlation_finding_count : Int32
      getter feedback_count : Int32
      getter trend_report_count : Int32
      getter? placeos_context_configured : Bool
      getter placeos_context_error : String?

      def initialize(
        @service : String,
        @database_configured : Bool,
        @persistence_enabled : Bool,
        @persistence_schema : PersistenceSchemaStatus,
        @incident_persistence_error : String?,
        @agent_run_persistence_error : String?,
        @report_delivery_persistence_error : String?,
        @approval_persistence_error : String?,
        @verification_persistence_error : String?,
        @escalation_persistence_error : String?,
        @maintenance_persistence_error : String?,
        @correlation_persistence_error : String?,
        @feedback_persistence_error : String?,
        @trend_persistence_error : String?,
        @report_count : Int32,
        @playbook_count : Int32,
        @playbook_path : String,
        @playbook_reload_error : String?,
        @workflow_count : Int32,
        @diagnostic_procedure_count : Int32,
        @remediation_procedure_count : Int32,
        @verification_procedure_count : Int32,
        @verification_run_count : Int32,
        @escalation_procedure_count : Int32,
        @escalation_record_count : Int32,
        @maintenance_procedure_count : Int32,
        @maintenance_run_count : Int32,
        @correlation_policy_count : Int32,
        @correlation_finding_count : Int32,
        @feedback_count : Int32,
        @trend_report_count : Int32,
        @placeos_context_configured : Bool,
        @placeos_context_error : String?,
      )
      end
    end

    @[AC::Route::GET("/")]
    def healthcheck : Nil
    end

    @[AC::Route::GET("/version")]
    def version : Version
      Version.new(
        version: VERSION,
        build_time: BUILD_TIME,
        commit: BUILD_COMMIT,
        service: APP_NAME
      )
    end

    @[AC::Route::GET("/status")]
    def status : Status
      Status.new(
        service: APP_NAME,
        database_configured: AISupportAgent.database_configured?,
        persistence_enabled: AISupportAgent.incidents.persistence_enabled? || AISupportAgent.agent_runs.persistence_enabled? || AISupportAgent.deliveries.persistence_enabled? || AISupportAgent.approvals.persistence_enabled? || AISupportAgent.verification_runs.persistence_enabled? || AISupportAgent.escalations.persistence_enabled? || AISupportAgent.maintenance_runs.persistence_enabled? || AISupportAgent.correlation_findings.persistence_enabled? || AISupportAgent.feedback.persistence_enabled? || AISupportAgent.trend_reports.persistence_enabled?,
        persistence_schema: AISupportAgent.persistence_schema_status,
        incident_persistence_error: AISupportAgent.incidents.persistence_error,
        agent_run_persistence_error: AISupportAgent.agent_runs.persistence_error,
        report_delivery_persistence_error: AISupportAgent.deliveries.persistence_error,
        approval_persistence_error: AISupportAgent.approvals.persistence_error,
        verification_persistence_error: AISupportAgent.verification_runs.persistence_error,
        escalation_persistence_error: AISupportAgent.escalations.persistence_error,
        maintenance_persistence_error: AISupportAgent.maintenance_runs.persistence_error,
        correlation_persistence_error: AISupportAgent.correlation_findings.persistence_error,
        feedback_persistence_error: AISupportAgent.feedback.persistence_error,
        trend_persistence_error: AISupportAgent.trend_reports.persistence_error,
        report_count: AISupportAgent.incidents.all.size,
        playbook_count: AISupportAgent.workflow_catalog.workflow_count,
        playbook_path: AISupportAgent.workflow_catalog.root,
        playbook_reload_error: AISupportAgent.workflow_catalog.reload_error,
        workflow_count: AISupportAgent.workflow_catalog.workflow_count,
        diagnostic_procedure_count: AISupportAgent.workflow_catalog.diagnostic_count,
        remediation_procedure_count: AISupportAgent.workflow_catalog.remediation_count,
        verification_procedure_count: AISupportAgent.workflow_catalog.verification_count,
        verification_run_count: AISupportAgent.verification_runs.size,
        escalation_procedure_count: AISupportAgent.workflow_catalog.escalation_count,
        escalation_record_count: AISupportAgent.escalations.size,
        maintenance_procedure_count: AISupportAgent.workflow_catalog.maintenance_count,
        maintenance_run_count: AISupportAgent.maintenance_runs.all.size,
        correlation_policy_count: AISupportAgent.workflow_catalog.correlation_count,
        correlation_finding_count: AISupportAgent.correlation_findings.all.size,
        feedback_count: AISupportAgent.feedback.all.size,
        trend_report_count: AISupportAgent.trend_reports.all.size,
        placeos_context_configured: AISupportAgent.context.configured?,
        placeos_context_error: AISupportAgent.context.configuration_error
      )
    end
  end
end
