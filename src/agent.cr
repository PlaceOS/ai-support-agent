require "json"
require "uuid"

require "./constants"
require "./agent/*"

module AISupportAgent
  @@persistence_schema_status = PersistenceSchemaStatus.unconfigured

  class_getter incidents : IncidentStore { IncidentStore.new }
  class_getter agent_runs : AgentRunStore { AgentRunStore.new }
  class_getter context : PlaceOSContext { PlaceOSContext.from_environment }
  class_getter ai_reporter : AIReporter { AIReporter.from_environment }
  class_getter workflow_catalog : WorkflowCatalog { WorkflowCatalog.from_environment }
  class_getter diagnostics : DiagnosticEngine { DiagnosticEngine.new(context, ai_reporter) }
  class_getter workflows : WorkflowRunner { WorkflowRunner.new(workflow_catalog, diagnostics) }
  class_getter deliveries : ReportDeliveryStore { ReportDeliveryStore.new }
  class_getter delivery : ReportDelivery { ReportDelivery.new(deliveries) }
  class_getter approvals : ApprovalRequestStore { ApprovalRequestStore.new }
  class_getter verification_runs : VerificationRunStore { VerificationRunStore.new }
  class_getter verification : VerificationEngine { VerificationEngine.new(workflow_catalog, context, verification_runs) }
  class_getter escalations : EscalationRecordStore { EscalationRecordStore.new }
  class_getter maintenance_runs : MaintenanceRunStore { MaintenanceRunStore.new }
  class_getter maintenance_runner : MaintenanceRunner do
    MaintenanceRunner.new(
      context,
      maintenance_runs,
      ->(event : IncidentEvent, diagnostic : ProcedureReference, deliver_report : Bool) {
        ingest(event, diagnostic_reference: diagnostic, deliver_report: deliver_report)
      }
    )
  end
  class_getter maintenance_scheduler : MaintenanceScheduler { MaintenanceScheduler.new(workflow_catalog, maintenance_runner) }
  class_getter correlation_findings : CorrelationFindingStore { CorrelationFindingStore.new }
  class_getter feedback : IncidentFeedbackStore { IncidentFeedbackStore.new }
  class_getter trend_reports : TrendReportStore { TrendReportStore.new }
  class_getter correlation : CorrelationEngine { CorrelationEngine.new(workflow_catalog, incidents, correlation_findings) }
  class_getter trends : TrendReporter { TrendReporter.new(workflow_catalog, incidents, correlation_findings, feedback, trend_reports) }
  class_getter module_runtime_error_resource : ModuleRuntimeErrorResource { ModuleRuntimeErrorResource.new }

  def self.ingest(
    event : IncidentEvent,
    verifier : VerificationEngine = verification,
    diagnostic_reference : ProcedureReference? = nil,
    deliver_report : Bool = true,
  ) : IncidentReport
    incidents.synchronize_correlation(event.correlation_key) do
      ingest_synchronized(event, verifier, diagnostic_reference, deliver_report)
    end
  end

  private def self.ingest_synchronized(
    event : IncidentEvent,
    verifier : VerificationEngine,
    diagnostic_reference : ProcedureReference?,
    deliver_report : Bool,
  ) : IncidentReport
    if existing = incidents.find_by_correlation_key(event.correlation_key)
      return update_existing(existing, event, verifier)
    end

    proposed_id = "aisup-#{UUID.random}"
    claim = incidents.claim(event, proposed_id)
    if claim && !claim.acquired?
      if existing = incidents.wait_for_report(claim.incident_id)
        return update_existing(existing, event, verifier)
      end

      claim = incidents.claim(event, proposed_id)
      unless claim && claim.acquired?
        incident_id = claim.try(&.incident_id) || proposed_id
        raise IncidentClaimInProgress.new(incident_id)
      end
    end

    incident = Incident.new(
      id: claim.try(&.incident_id) || proposed_id,
      event: event,
      created_at: Time.utc
    )
    heartbeat = claim.try { |current| IncidentClaimHeartbeat.new(incidents, current) if current.acquired? }
    begin
      report = workflows.report_for(incident, diagnostic_reference)
      saved = incidents.save(report, event, claim_token: claim.try(&.token))
    rescue error : IncidentClaimLost
      if existing = incidents.wait_for_report(error.incident_id)
        return update_existing(existing, event, verifier)
      end
      raise IncidentClaimInProgress.new(error.incident_id)
    ensure
      heartbeat.try(&.stop)
    end

    agent_runs.save(saved)
    delivery_records = if deliver_report
                         delivery.deliver(saved)
                       else
                         [deliveries.save(ReportDeliveryRecord.new(
                           incident_id: saved.incident_id,
                           status: ReportDeliveryStatus::Skipped,
                           destination: "maintenance_policy",
                           attempted_at: Time.utc,
                           error: "report delivery disabled by maintenance procedure"
                         ))]
                       end
    delivery_record = delivery_records.find(&.status.failed?) || delivery_records.first
    if escalation = EscalationRecord.from(saved, delivery_record)
      escalations.save(escalation)
    end
    correlate(saved)
    saved
  end

  private def self.update_existing(
    existing : IncidentReport,
    event : IncidentEvent,
    verifier : VerificationEngine,
  ) : IncidentReport
    if event.resolution?
      if existing.remediation_proposal.try(&.verification_procedure)
        verify(existing, event, force: true, verifier: verifier)
        return incidents.find(existing.incident_id) || raise "verified incident #{existing.incident_id} was not saved"
      end
      saved = incidents.save(existing.with_resolution_seen(Time.utc), event)
      agent_runs.save(saved)
      correlate(saved)
      return saved
    end

    saved = incidents.save(existing.with_duplicate_seen(Time.utc), event)
    agent_runs.save(saved)
    correlate(saved)
    saved
  end

  def self.verify(
    report : IncidentReport,
    event : IncidentEvent? = nil,
    force : Bool = false,
    verifier : VerificationEngine = verification,
  ) : VerificationRun
    verification_event = event || IncidentEvent.new(
      source: report.source,
      severity: report.severity,
      correlation_key: report.correlation_key,
      payload: JSON.parse({verification: "manual"}.to_json),
      tenant_id: report.tenant_id,
      system_id: report.system_id,
      module_id: report.module_id,
      module_name: report.module_name,
      module_index: report.module_index
    )
    run = verifier.verify(report, verification_event, force: force)
    saved = incidents.save(report.with_verification_result(run), event)
    agent_runs.save(saved)
    correlate(saved)
    run
  end

  private def self.correlate(report : IncidentReport) : Nil
    correlation.evaluate(report)
  rescue error
    Log.warn(exception: error) { "incident correlation failed; report remains available" }
  end

  def self.persistence_schema_status : PersistenceSchemaStatus
    @@persistence_schema_status
  end

  def self.reset_persistence_schema_status : Nil
    @@persistence_schema_status = PersistenceSchemaStatus.unconfigured
  end

  def self.configure_database : Bool
    if pg_url = ENV["PG_DATABASE_URL"]?
      PgORM::Database.parse(pg_url)
    else
      PgORM::Database.configure { |_| }
    end

    configure_persistence(PostgresIncidentRepository.new)
  rescue error
    @@persistence_schema_status = PersistenceSchemaStatus.unavailable(error)
    Log.error(exception: error) { "Postgres configuration failed; continuing without persistence or changefeed" }
    false
  end

  def self.configure_persistence(repository : PostgresIncidentRepository) : Bool
    disable_persistence
    status = repository.persistence_schema_status
    @@persistence_schema_status = status
    unless status.ready?
      Log.error { "#{status.summary}; continuing without persistence or changefeed" }
      return false
    end

    incidents.persist_with(repository)
    agent_runs.persist_with(repository)
    deliveries.persist_with(repository)
    approvals.persist_with(repository)
    verification_runs.persist_with(repository)
    escalations.persist_with(repository)
    maintenance_runs.persist_with(repository)
    correlation_findings.persist_with(repository)
    feedback.persist_with(repository)
    trend_reports.persist_with(repository)
    true
  end

  def self.disable_persistence : Nil
    incidents.disable_persistence
    agent_runs.disable_persistence
    deliveries.disable_persistence
    approvals.disable_persistence
    verification_runs.disable_persistence
    escalations.disable_persistence
    maintenance_runs.disable_persistence
    correlation_findings.disable_persistence
    feedback.disable_persistence
    trend_reports.disable_persistence
  end

  def self.database_configured? : Bool
    !!ENV["PG_HOST"]?.presence || !!ENV["PG_DATABASE"]?.presence || !!ENV["PG_DATABASE_URL"]?.presence
  end

  def self.start_resources : Nil
    catalog = workflow_catalog
    Log.info do
      "loaded #{catalog.workflow_count} workflows, #{catalog.diagnostic_count} diagnostic procedures, " \
      "#{catalog.remediation_count} remediation procedures, and " \
      "#{catalog.verification_count} verification procedures, and " \
      "#{catalog.escalation_count} escalation procedures, and " \
      "#{catalog.maintenance_count} maintenance procedures, and " \
      "#{catalog.correlation_count} correlation policies from #{catalog.root}"
    end

    if context.configured?
      maintenance_scheduler.start
    else
      Log.info { "maintenance scheduler disabled: #{context.configuration_error}" }
    end

    unless database_configured?
      Log.info { "module runtime-error changefeed disabled: no postgres configuration found" }
      return
    end

    unless configure_database
      Log.warn { "module runtime-error changefeed disabled: persistence schema is not ready" }
      return
    end
    module_runtime_error_resource.start
  end

  def self.stop_resources : Nil
    module_runtime_error_resource.stop if module_runtime_error_resource.startup_finished?
    maintenance_scheduler.stop
  end
end
