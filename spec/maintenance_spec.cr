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
