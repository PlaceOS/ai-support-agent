require "file_utils"
require "./helper"

module AISupportAgent
  class MaintenanceRepository < PostgresIncidentRepository
    def initialize(@runs = [] of MaintenanceRun)
    end

    def save_maintenance_run(run : MaintenanceRun) : MaintenanceRun
      if existing = find_maintenance_run(run.procedure.id, run.procedure.version, run.schedule_bucket)
        return existing
      end
      @runs << run
      run
    end

    def find_maintenance_run(procedure_id : String, procedure_version : Int32, schedule_bucket : Int64) : MaintenanceRun?
      @runs.find do |run|
        run.procedure.id == procedure_id &&
          run.procedure.version == procedure_version &&
          run.schedule_bucket == schedule_bucket
      end
    end

    def all_maintenance_runs : Array(MaintenanceRun)
      @runs
    end
  end

  class FailingMaintenanceRepository < PostgresIncidentRepository
    def save_maintenance_run(run : MaintenanceRun) : MaintenanceRun
      raise "database offline"
    end

    def find_maintenance_run(procedure_id : String, procedure_version : Int32, schedule_bucket : Int64) : MaintenanceRun?
      raise "database offline"
    end

    def all_maintenance_runs : Array(MaintenanceRun)
      raise "database offline"
    end
  end

  def self.with_maintenance_file(contents : String, & : String ->) : Nil
    directory = File.join(Dir.tempdir, "support-maintenance-#{UUID.random}")
    Dir.mkdir_p(directory)
    File.write(File.join(directory, "procedure.yml"), contents)
    yield directory
  ensure
    FileUtils.rm_rf(directory) if directory
  end

  def self.maintenance_report(event : IncidentEvent, classification = DiagnosticClassification::RuntimeError) : IncidentReport
    IncidentReport.new(
      incident_id: "aisup-#{UUID.random}",
      status: IncidentStatus::Open,
      summary: "Scheduled diagnosis",
      classification: classification,
      confidence: 0.8,
      severity: event.severity,
      source: event.source,
      correlation_key: event.correlation_key,
      created_at: Time.utc,
      evidence: [] of Evidence,
      actions_taken: ["report_only_no_remediation"],
      next_steps: [] of String,
      system_id: event.system_id,
      module_id: event.module_id
    )
  end

  def self.store_backed_ingest(incidents : IncidentStore, events : Array(IncidentEvent)) : Proc(IncidentEvent, ProcedureReference, Bool, IncidentReport)
    ->(event : IncidentEvent, _diagnostic : ProcedureReference, _deliver_report : Bool) do
      events << event
      if existing = incidents.find_by_correlation_key(event.correlation_key)
        updated = event.resolution? ? existing.with_resolution_seen(Time.utc) : existing.with_duplicate_seen(Time.utc)
        incidents.save(updated, event)
      else
        incidents.save(maintenance_report(event), event)
      end
    end
  end

  def self.scheduled_event(correlation_key : String, module_id : String) : IncidentEvent
    IncidentEvent.new(
      source: IncidentSource::Scheduled,
      severity: IncidentSeverity::Warning,
      correlation_key: correlation_key,
      payload: JSON.parse({maintenance_procedure: "sweep"}.to_json),
      system_id: "sys-1",
      module_id: module_id
    )
  end

  describe "IncidentStore#open_by_correlation_prefix" do
    {"in memory", "in Postgres"}.each do |backing|
      it "returns only unresolved incidents under the prefix #{backing}" do
        incidents = backing == "in memory" ? IncidentStore.new : AISupportAgent.incidents
        incidents.persistence_enabled?.should eq(backing == "in Postgres")
        open_event = AISupportAgent.scheduled_event("maintenance:sweep_a:mod-open:module-runtime-error", "mod-open")
        resolved_event = AISupportAgent.scheduled_event("maintenance:sweep_a:mod-resolved:module-runtime-error", "mod-resolved")
        decoy_event = AISupportAgent.scheduled_event("maintenance:sweepXa:mod-decoy:module-runtime-error", "mod-decoy")
        other_event = AISupportAgent.scheduled_event("webhook:mod-other", "mod-other")
        incidents.save(AISupportAgent.maintenance_report(open_event), open_event)
        incidents.save(AISupportAgent.maintenance_report(resolved_event).with_resolution_seen(Time.utc), resolved_event)
        incidents.save(AISupportAgent.maintenance_report(decoy_event), decoy_event)
        incidents.save(AISupportAgent.maintenance_report(other_event), other_event)

        matches = incidents.open_by_correlation_prefix("maintenance:sweep_a:")

        matches.map(&.correlation_key).should eq ["maintenance:sweep_a:mod-open:module-runtime-error"]
        incidents.open_by_correlation_prefix("maintenance:none:").should be_empty
      end
    end
  end

  describe MaintenanceProcedureRegistry do
    it "loads repository procedures and validates their diagnostic references" do
      diagnostics = DiagnosticProcedureRegistry.load("playbooks/diagnostics", live_reload: false)
      registry = MaintenanceProcedureRegistry.load("playbooks/maintenance", diagnostics)
      procedure = registry.find("runtime-error-sweep") || raise "maintenance procedure not loaded"

      registry.size.should eq 1
      procedure.reference.to_s.should eq "maintenance:runtime-error-sweep@1"
      procedure.diagnostic_references.map(&.to_s).should eq ["diagnostic:module-runtime-error@1"]
      procedure.content_hash.size.should eq 64
    end

    it "rejects unknown executable fields" do
      diagnostics = DiagnosticProcedureRegistry.load("playbooks/diagnostics", live_reload: false)
      contents = File.read("playbooks/maintenance/runtime-error-sweep.yml") + "\ncommand: restart modules\n"

      AISupportAgent.with_maintenance_file(contents) do |directory|
        expect_raises(MaintenanceProcedureRegistry::ValidationError, /command/) do
          MaintenanceProcedureRegistry.load(directory, diagnostics)
        end
      end
    end

    it "rejects invalid schedules and unresolved diagnostic references" do
      diagnostics = DiagnosticProcedureRegistry.load("playbooks/diagnostics", live_reload: false)
      contents = File.read("playbooks/maintenance/runtime-error-sweep.yml")
        .sub(%(cron: "0 */15 * * * *"), %(cron: "invalid"))

      AISupportAgent.with_maintenance_file(contents) do |directory|
        expect_raises(MaintenanceProcedureRegistry::ValidationError) do
          MaintenanceProcedureRegistry.load(directory, diagnostics)
        end
      end

      contents = File.read("playbooks/maintenance/runtime-error-sweep.yml")
        .sub("diagnostic:module-runtime-error@1", "diagnostic:not-present@1")
      AISupportAgent.with_maintenance_file(contents) do |directory|
        expect_raises(MaintenanceProcedureRegistry::ValidationError, /missing diagnostic/) do
          MaintenanceProcedureRegistry.load(directory, diagnostics)
        end
      end
    end
  end

  describe PlaceOSContext do
    it "resolves bounded runtime-error module scopes through PlaceOS::Client" do
      modules = [
        {id: "mod-failed", control_system_id: "sys-1", name: "Display", index: 2, has_runtime_error: true},
        {id: "mod-healthy", control_system_id: "sys-1", name: "Audio", index: 1, has_runtime_error: false},
      ]
      WebMock.stub(:get, "http://place.test/api/engine/v2/modules/?limit=500")
        .to_return(body: modules.to_json)
      client = ::PlaceOS::Client.new("http://place.test", x_api_key: "test-key")
      procedure = WorkflowCatalog.load("playbooks").maintenance("runtime-error-sweep") || raise "maintenance procedure not loaded"
      scope = procedure.scope

      targets = PlaceOSContext.new(client).maintenance_targets(scope)

      targets.map(&.module_id).should eq ["mod-failed"]
      targets.first.system_id.should eq "sys-1"
      targets.first.module_index.should eq 2
      targets.first.has_runtime_error?.should be_true
    end
  end

  describe MaintenanceRunner do
    it "runs the exact referenced diagnostic, deduplicates its window, and records trends" do
      target = MaintenanceTarget.new("mod-runtime", "sys-1", "Display", 1, has_runtime_error: true)
      context = PlaceOSContext.static([
        Evidence.new("placeos_rest_api", "runtime exception evidence"),
      ], [target])
      catalog = WorkflowCatalog.load("playbooks")
      procedure = catalog.maintenance("runtime-error-sweep") || raise "maintenance procedure not loaded"
      workflow = WorkflowRunner.new(catalog, DiagnosticEngine.new(context, AIReporter.disabled))
      reports = [] of IncidentReport
      delivery_policies = [] of Bool
      ingest = ->(event : IncidentEvent, diagnostic : ProcedureReference, deliver_report : Bool) do
        delivery_policies << deliver_report
        workflow.report_for(Incident.new("aisup-maintenance", event, Time.utc), diagnostic).tap do |report|
          reports << report
        end
      end
      runner = MaintenanceRunner.new(context, MaintenanceRunStore.new, ingest)
      scheduled_for = Time.utc(2026, 7, 21, 8, 30, 0)

      first = runner.run(procedure, scheduled_for)
      duplicate = runner.run(procedure, scheduled_for + 5.minutes)

      first.status.completed?.should be_true
      first.target_count.should eq 1
      first.classification_counts.should eq({"runtime_error" => 1})
      duplicate.id.should eq first.id
      reports.size.should eq 1
      reports.first.classification.runtime_error?.should be_true
      plan = reports.first.investigation_plan || raise "investigation plan not generated"
      plan.procedures.map(&.id).should contain "module-runtime-error"
      delivery_policies.should eq [true]
      reports.first.actions_taken.should eq ["report_only_no_remediation"]
    end

    it "keeps one open incident per module across sweep windows" do
      failing = MaintenanceTarget.new("mod-runtime", "sys-1", "Display", 1, has_runtime_error: true)
      other = MaintenanceTarget.new("mod-other", "sys-1", "Other", 2, has_runtime_error: true)
      context = PlaceOSContext.static([Evidence.new("placeos_rest_api", "runtime exception evidence")], [failing, other])
      procedure = WorkflowCatalog.load("playbooks").maintenance("runtime-error-sweep") || raise "maintenance procedure not loaded"
      incidents = IncidentStore.new
      events = [] of IncidentEvent
      runner = MaintenanceRunner.new(context, MaintenanceRunStore.new, AISupportAgent.store_backed_ingest(incidents, events), incidents)

      first = runner.run(procedure, Time.utc(2026, 7, 21, 8, 30, 0))
      second = runner.run(procedure, Time.utc(2026, 7, 21, 8, 45, 0))

      first.incident_ids.size.should eq 2
      second.id.should_not eq first.id
      second.incident_ids.sort.should eq first.incident_ids.sort
      events.map(&.correlation_key).uniq.sort.should eq [
        "maintenance:runtime-error-sweep:mod-other:module-runtime-error",
        "maintenance:runtime-error-sweep:mod-runtime:module-runtime-error",
      ]
      events.none?(&.resolution?).should be_true
      reports = incidents.all
      reports.size.should eq 2
      reports.all?(&.status.open?).should be_true
      reports.map(&.duplicate_count).should eq [1, 1]
    end

    it "resolves an incident once its module is no longer failing or no longer exists, and keeps a still-failing one open" do
      runtime = MaintenanceTarget.new("mod-runtime", "sys-1", "Display", 1, has_runtime_error: true)
      recovered = MaintenanceTarget.new("mod-recovered", "sys-1", "Recovered", 2, has_runtime_error: true)
      deleted = MaintenanceTarget.new("mod-deleted", "sys-1", "Deleted", 3, has_runtime_error: true)
      outside = MaintenanceTarget.new("mod-outside", "sys-1", "Outside", 4, has_runtime_error: true)
      evidence = [Evidence.new("placeos_rest_api", "runtime exception evidence")]
      procedure = MaintenanceProcedure.from_yaml(<<-YAML)
        schema_version: maintenance-procedure.v1
        id: runtime-error-sweep
        version: 1
        name: Scheduled module runtime-error sweep
        mode: maintenance
        schedule:
          cron: "0 */15 * * * *"
        scope:
          kind: modules
          filter: runtime_errors
          limit: 3
        diagnostics:
          - diagnostic:module-runtime-error@1
        deduplication_window_seconds: 900
        reporting:
          deliver_reports: true
        YAML
      incidents = IncidentStore.new
      events = [] of IncidentEvent
      runs = MaintenanceRunStore.new
      ingest = AISupportAgent.store_backed_ingest(incidents, events)

      first = MaintenanceRunner.new(PlaceOSContext.static(evidence, [runtime, recovered, deleted]), runs, ingest, incidents)
        .run(procedure, Time.utc(2026, 7, 21, 8, 30, 0))
      first.incident_ids.size.should eq 3

      later_targets = [
        runtime,
        MaintenanceTarget.new("mod-recovered", "sys-1", "Recovered", 2, has_runtime_error: false),
        MaintenanceTarget.new("mod-extra-1", "sys-1", "Extra 1", 5, has_runtime_error: true),
        MaintenanceTarget.new("mod-extra-2", "sys-1", "Extra 2", 6, has_runtime_error: true),
        outside,
      ]
      second = MaintenanceRunner.new(PlaceOSContext.static(evidence, later_targets), runs, ingest, incidents)
        .run(procedure, Time.utc(2026, 7, 21, 8, 45, 0))

      second.target_count.should eq 3
      by_key = incidents.all.to_h { |report| {report.correlation_key, report} }
      by_key["maintenance:runtime-error-sweep:mod-runtime:module-runtime-error"].status.open?.should be_true
      by_key["maintenance:runtime-error-sweep:mod-recovered:module-runtime-error"].status.resolved?.should be_true
      by_key["maintenance:runtime-error-sweep:mod-deleted:module-runtime-error"].status.resolved?.should be_true
      resolutions = events.select(&.resolution?)
      resolutions.map(&.module_id).compact.sort.should eq ["mod-deleted", "mod-recovered"]
      resolutions.map { |event| event.payload["module_health"].as_s }.sort.should eq ["healthy", "missing"]
      resolutions.all? { |event| event.payload["diagnostic"].as_s == "diagnostic:module-runtime-error@1" }.should be_true
      second.incident_ids.should contain by_key["maintenance:runtime-error-sweep:mod-recovered:module-runtime-error"].incident_id
      incidents.all.map(&.correlation_key).should_not contain "maintenance:runtime-error-sweep:mod-outside:module-runtime-error"
    end

    it "keeps an incident open when the direct module check still reports a runtime error" do
      first_targets = [
        MaintenanceTarget.new("mod-a", "sys-1", "A", 1, has_runtime_error: true),
        MaintenanceTarget.new("mod-b", "sys-1", "B", 2, has_runtime_error: true),
      ]
      evidence = [Evidence.new("placeos_rest_api", "runtime exception evidence")]
      procedure = MaintenanceProcedure.from_yaml(<<-YAML)
        schema_version: maintenance-procedure.v1
        id: runtime-error-sweep
        version: 1
        name: Scheduled module runtime-error sweep
        mode: maintenance
        schedule:
          cron: "0 */15 * * * *"
        scope:
          kind: modules
          filter: runtime_errors
          limit: 2
        diagnostics:
          - diagnostic:module-runtime-error@1
        deduplication_window_seconds: 900
        reporting:
          deliver_reports: true
        YAML
      incidents = IncidentStore.new
      events = [] of IncidentEvent
      runs = MaintenanceRunStore.new
      ingest = AISupportAgent.store_backed_ingest(incidents, events)

      MaintenanceRunner.new(PlaceOSContext.static(evidence, first_targets), runs, ingest, incidents)
        .run(procedure, Time.utc(2026, 7, 21, 8, 30, 0))
      crowded = [
        MaintenanceTarget.new("mod-c", "sys-1", "C", 3, has_runtime_error: true),
        MaintenanceTarget.new("mod-d", "sys-1", "D", 4, has_runtime_error: true),
      ] + first_targets
      second = MaintenanceRunner.new(PlaceOSContext.static(evidence, crowded), runs, ingest, incidents)
        .run(procedure, Time.utc(2026, 7, 21, 8, 45, 0))

      second.target_count.should eq 2
      events.none?(&.resolution?).should be_true
      incidents.all.size.should eq 4
      incidents.all.all?(&.status.open?).should be_true
    end

    it "records scope failures without crashing the scheduler" do
      context = PlaceOSContext.new(configuration_error: "PlaceOS unavailable")
      procedure = WorkflowCatalog.load("playbooks").maintenance("runtime-error-sweep") || raise "maintenance procedure not loaded"
      ingest = ->(event : IncidentEvent, _diagnostic : ProcedureReference, _deliver_report : Bool) do
        AISupportAgent.maintenance_report(event)
      end

      run = MaintenanceRunner.new(context, MaintenanceRunStore.new, ingest).run(procedure)

      run.status.failed?.should be_true
      run.error.try(&.should contain "PlaceOS unavailable")
    end
  end

  describe MaintenanceScheduler do
    it "registers and cancels Tasker cron jobs" do
      context = PlaceOSContext.static([] of Evidence, [] of MaintenanceTarget)
      ingest = ->(event : IncidentEvent, _diagnostic : ProcedureReference, _deliver_report : Bool) do
        AISupportAgent.maintenance_report(event)
      end
      runner = MaintenanceRunner.new(context, MaintenanceRunStore.new, ingest)
      scheduler = MaintenanceScheduler.new(WorkflowCatalog.load("playbooks"), runner)

      scheduler.start
      scheduler.size.should eq 1
      scheduler.stop
      scheduler.size.should eq 0
    ensure
      scheduler.try(&.stop)
    end
  end

  describe MaintenanceRunStore do
    it "loads durable history after memory is cleared" do
      store = MaintenanceRunStore.new
      store.persist_with(MaintenanceRepository.new)
      run = MaintenanceRun.new(
        id: "maintenance-persisted",
        procedure: ProcedureAudit.new("maintenance", "runtime-error-sweep", 1, "a" * 64),
        schedule_bucket: 42_i64,
        status: MaintenanceRunStatus::Completed,
        target_count: 1,
        incident_ids: ["aisup-1"],
        classification_counts: {"runtime_error" => 1},
        started_at: Time.utc,
        completed_at: Time.utc
      )

      store.save(run)
      store.clear

      store.find_window(ProcedureReference.parse("maintenance:runtime-error-sweep@1"), 42_i64).should eq run
      store.all.should eq [run]
    end

    it "continues in memory and exposes persistence failures" do
      store = MaintenanceRunStore.new
      store.persist_with(FailingMaintenanceRepository.new)
      run = MaintenanceRun.new(
        id: "maintenance-fallback",
        procedure: ProcedureAudit.new("maintenance", "runtime-error-sweep", 1, "a" * 64),
        schedule_bucket: 43_i64,
        status: MaintenanceRunStatus::Failed,
        target_count: 0,
        incident_ids: [] of String,
        classification_counts: {} of String => Int32,
        started_at: Time.utc,
        completed_at: Time.utc,
        error: "scope failed"
      )

      store.save(run).should eq run
      store.all.should eq [run]
      store.persistence_error.try(&.should contain "database offline")
    end
  end

  describe Maintenance do
    it "exposes manual execution and run history" do
      response = client.post("/api/ai-support/v1/maintenance/runtime-error-sweep/runs")
      response.status_code.should eq 201
      run = MaintenanceRun.from_json(response.body)
      run.status.failed?.should be_true

      history = client.get("/api/ai-support/v1/maintenance/runs")
      history.status_code.should eq 200
      Array(MaintenanceRun).from_json(history.body).map(&.id).should contain run.id
    end

    it "returns not found for unknown procedures" do
      client.post("/api/ai-support/v1/maintenance/not-present/runs").status_code.should eq 404
    end
  end
end
