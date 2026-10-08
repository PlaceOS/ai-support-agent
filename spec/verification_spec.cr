require "file_utils"
require "./helper"

module AISupportAgent
  class VerificationRepository < PostgresIncidentRepository
    def initialize(@runs = [] of VerificationRun)
    end

    def save_verification_run(run : VerificationRun) : VerificationRun
      @runs << run
      run
    end

    def verification_runs_for_incident(incident_id : String) : Array(VerificationRun)
      @runs.select { |run| run.incident_id == incident_id }
    end

    def all_verification_runs : Array(VerificationRun)
      @runs
    end
  end

  class FailingVerificationRepository < PostgresIncidentRepository
    def save_verification_run(run : VerificationRun) : VerificationRun
      raise "database offline"
    end

    def verification_runs_for_incident(incident_id : String) : Array(VerificationRun)
      raise "database offline"
    end

    def all_verification_runs : Array(VerificationRun)
      raise "database offline"
    end
  end

  def self.verification_event(correlation_key : String = "verification:test") : IncidentEvent
    IncidentEvent.new(
      source: IncidentSource::Webhook,
      severity: IncidentSeverity::Error,
      correlation_key: correlation_key,
      payload: JSON.parse({status: "resolved"}.to_json),
      module_id: "mod-verification"
    )
  end

  def self.verification_report(correlation_key : String = "verification:test") : IncidentReport
    IncidentReport.new(
      incident_id: "aisup-#{correlation_key.gsub(':', '-')}",
      status: IncidentStatus::Open,
      summary: "Runtime error",
      classification: DiagnosticClassification::RuntimeError,
      confidence: 0.8,
      severity: IncidentSeverity::Error,
      source: IncidentSource::Webhook,
      correlation_key: correlation_key,
      created_at: Time.utc,
      evidence: [] of Evidence,
      actions_taken: ["report_only_no_remediation"],
      next_steps: [] of String,
      remediation_proposal: RemediationProposal.new(
        action: "Restart the affected module",
        risk_level: "medium",
        approval_required: true,
        execution_mode: "proposal_only",
        policy_basis: "Operator approval required",
        verification_plan: [] of String,
        verification_procedure: "verification:module-runtime-recovery@1"
      ),
      module_id: "mod-verification"
    )
  end

  def self.verification_context(has_runtime_error : Bool) : PlaceOSContext
    PlaceOSContext.static([
      Evidence.new(
        source: "fixture",
        message: "Module state",
        data: JSON.parse({has_runtime_error: has_runtime_error}.to_json)
      ),
    ])
  end

  def self.with_verification_file(contents : String, & : String ->) : Nil
    directory = File.join(Dir.tempdir, "support-verification-#{UUID.random}")
    Dir.mkdir_p(directory)
    File.write(File.join(directory, "procedure.yml"), contents)
    yield directory
  ensure
    FileUtils.rm_rf(directory) if directory
  end

  def self.verification_yaml(criterion : String = "evidence_present") : String
    <<-YAML
    schema_version: verification-procedure.v1
    id: test-verification
    version: 1
    name: Test verification
    mode: verification
    checks:
      - id: check-state
        tool: module_state
        criterion: #{criterion}
        requires: [module_id]
    policy:
      retry_interval_seconds: 60
      max_attempts: 3
      timeout_seconds: 900
      failure_outcome: escalate
    YAML
  end

  describe VerificationProcedureRegistry do
    it "loads repository verification procedures" do
      registry = VerificationProcedureRegistry.load("playbooks/verification")

      registry.size.should eq 4
      procedure = registry.find(ProcedureReference.parse("verification:module-runtime-recovery@1"))
      procedure.should_not be_nil
      procedure.try(&.content_hash.size).should eq 64
    end

    it "rejects unknown criteria" do
      AISupportAgent.with_verification_file(AISupportAgent.verification_yaml("arbitrary_expression")) do |directory|
        expect_raises(VerificationProcedureRegistry::ValidationError, /unknown criterion/) do
          VerificationProcedureRegistry.load(directory)
        end
      end
    end

    it "rejects executable fields" do
      contents = AISupportAgent.verification_yaml.sub(
        "    criterion: evidence_present",
        "    criterion: evidence_present\n    command: curl example.com"
      )
      AISupportAgent.with_verification_file(contents) do |directory|
        expect_raises(VerificationProcedureRegistry::ValidationError, /command/) do
          VerificationProcedureRegistry.load(directory)
        end
      end
    end

    it "rejects missing cross-category references" do
      base = File.join(Dir.tempdir, "support-verification-catalog-#{UUID.random}")
      root = File.join(base, "playbooks")
      Dir.mkdir_p(base)
      FileUtils.cp_r("playbooks", root)
      remediation = File.join(root, "remediation", "restart-runtime-failure.yml")
      File.write(remediation, File.read(remediation).sub(
        "verification:module-runtime-recovery@1",
        "verification:not-present@1"
      ))

      expect_raises(RemediationProcedureRegistry::ValidationError, /missing verification procedure/) do
        WorkflowCatalog.load(root)
      end
    ensure
      FileUtils.rm_rf(base) if base
    end

    it "retains the complete last-known-good snapshot after an invalid live edit" do
      base = File.join(Dir.tempdir, "support-verification-reload-#{UUID.random}")
      root = File.join(base, "playbooks")
      Dir.mkdir_p(base)
      FileUtils.cp_r("playbooks", root)
      catalog = WorkflowCatalog.load(root)
      verification = File.join(root, "verification", "module-runtime-recovery.yml")
      File.write(verification, File.read(verification) + "\ncommand: curl example.com\n")

      catalog.verification_count.should eq 4
      catalog.remediation_count.should eq 6
      catalog.workflow_count.should eq 1
      catalog.reload_error.should_not be_nil
    ensure
      FileUtils.rm_rf(base) if base
    end
  end

  describe VerificationEngine do
    it "records successful read-only verification" do
      runs = VerificationRunStore.new
      engine = VerificationEngine.new(WorkflowCatalog.load("playbooks"), AISupportAgent.verification_context(false), runs)

      run = engine.verify(AISupportAgent.verification_report, AISupportAgent.verification_event)

      run.status.verified?.should be_true
      run.attempt.should eq 1
      run.checks.all?(&.passed?).should be_true
      run.procedure.category.should eq "verification"
      runs.for_incident(run.incident_id).should eq [run]
    end

    it "records a non-blocking retry when recovery checks fail" do
      runs = VerificationRunStore.new
      engine = VerificationEngine.new(WorkflowCatalog.load("playbooks"), AISupportAgent.verification_context(true), runs)

      run = engine.verify(AISupportAgent.verification_report, AISupportAgent.verification_event)

      run.status.retry_scheduled?.should be_true
      run.checks.any? { |check| !check.passed? }.should be_true
      run.next_retry_at.should_not be_nil
      expect_raises(VerificationEngine::Error, /retry is not due/) do
        engine.verify(AISupportAgent.verification_report, AISupportAgent.verification_event)
      end
    end
  end

  describe VerificationRunStore do
    it "loads durable verification history after memory is cleared" do
      repository = VerificationRepository.new
      runs = VerificationRunStore.new
      runs.persist_with(repository)
      engine = VerificationEngine.new(WorkflowCatalog.load("playbooks"), AISupportAgent.verification_context(false), runs)
      run = engine.verify(AISupportAgent.verification_report, AISupportAgent.verification_event)

      runs.clear

      runs.for_incident(run.incident_id).should eq [run]
      runs.size.should eq 1
    end

    it "continues in memory and exposes persistence failures" do
      runs = AISupportAgent.verification_runs
      runs.persist_with(FailingVerificationRepository.new)
      engine = VerificationEngine.new(WorkflowCatalog.load("playbooks"), AISupportAgent.verification_context(false), runs)
      run = engine.verify(AISupportAgent.verification_report, AISupportAgent.verification_event)

      runs.for_incident(run.incident_id).should eq [run]
      runs.persistence_error.try(&.should contain "database offline")

      status = Root::Status.from_json(client.get("/api/ai-support/v1/status").body)
      status.persistence_enabled?.should be_true
      status.verification_persistence_error.try(&.should contain "database offline")
    end
  end

  describe "verification lifecycle" do
    it "confirms a correlated resolution only after verification passes" do
      report = AISupportAgent.verification_report("verification:resolved")
      AISupportAgent.incidents.save(report)
      runs = VerificationRunStore.new
      engine = VerificationEngine.new(WorkflowCatalog.load("playbooks"), AISupportAgent.verification_context(false), runs)

      updated = AISupportAgent.ingest(AISupportAgent.verification_event(report.correlation_key), engine)

      updated.status.resolved?.should be_true
      updated.investigation.map(&.name).should contain "verification:module-runtime-recovery"
      updated.actions_taken.should eq ["report_only_no_remediation"]
    end

    it "does not resolve a correlated incident when verification fails" do
      report = AISupportAgent.verification_report("verification:not-resolved")
      AISupportAgent.incidents.save(report)
      runs = VerificationRunStore.new
      engine = VerificationEngine.new(WorkflowCatalog.load("playbooks"), AISupportAgent.verification_context(true), runs)

      updated = AISupportAgent.ingest(AISupportAgent.verification_event(report.correlation_key), engine)

      updated.status.open?.should be_true
      runs.for_incident(report.incident_id).first.status.retry_scheduled?.should be_true
      updated.actions_taken.should eq ["report_only_no_remediation"]
    end

    it "creates and lists manual verification runs through the incidents API" do
      report = AISupportAgent.verification_report("verification:api")
      AISupportAgent.incidents.save(report)

      created = client.post("/api/ai-support/v1/incidents/#{report.incident_id}/verifications")
      listed = client.get("/api/ai-support/v1/incidents/#{report.incident_id}/verifications")

      created.status_code.should eq 201
      VerificationRun.from_json(created.body).incident_id.should eq report.incident_id
      listed.status_code.should eq 200
      Array(VerificationRun).from_json(listed.body).size.should eq 1
    end
  end
end
