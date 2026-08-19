require "file_utils"
require "./helper"

module AISupportAgent
  class EscalationRepository < PostgresIncidentRepository
    def initialize(@records = [] of EscalationRecord)
    end

    def save_escalation_record(record : EscalationRecord) : EscalationRecord
      @records << record
      record
    end

    def escalation_records_for_incident(incident_id : String) : Array(EscalationRecord)
      @records.select { |record| record.incident_id == incident_id }
    end

    def all_escalation_records : Array(EscalationRecord)
      @records
    end
  end

  class FailingEscalationRepository < PostgresIncidentRepository
    def save_escalation_record(record : EscalationRecord) : EscalationRecord
      raise "database offline"
    end

    def escalation_records_for_incident(incident_id : String) : Array(EscalationRecord)
      raise "database offline"
    end

    def all_escalation_records : Array(EscalationRecord)
      raise "database offline"
    end
  end

  def self.escalation_report(severity : IncidentSeverity) : IncidentReport
    IncidentReport.new(
      incident_id: "aisup-escalation",
      status: IncidentStatus::Escalated,
      summary: "Insufficient evidence",
      classification: DiagnosticClassification::Unknown,
      confidence: 0.2,
      severity: severity,
      source: IncidentSource::Webhook,
      correlation_key: "escalation:test",
      created_at: Time.utc,
      evidence: [] of Evidence,
      actions_taken: ["report_only_no_remediation"],
      next_steps: [] of String
    )
  end

  def self.with_escalation_file(contents : String, & : String ->) : Nil
    directory = File.join(Dir.tempdir, "support-escalation-#{UUID.random}")
    Dir.mkdir_p(directory)
    File.write(File.join(directory, "procedure.yml"), contents)
    yield directory
  ensure
    FileUtils.rm_rf(directory) if directory
  end

  describe EscalationProcedureRegistry do
    it "selects critical and fallback ownership policies" do
      registry = EscalationProcedureRegistry.load("playbooks/escalation")
      allowed = [
        ProcedureReference.parse("escalation:critical-incident@1"),
        ProcedureReference.parse("escalation:support-fallback@1"),
      ]

      registry.size.should eq 2
      registry.select(AISupportAgent.escalation_report(IncidentSeverity::Critical), allowed).id.should eq "critical-incident"
      registry.select(AISupportAgent.escalation_report(IncidentSeverity::Warning), allowed).id.should eq "support-fallback"
    end

    it "rejects executable fields" do
      contents = File.read("playbooks/escalation/support-fallback.yml") + "\ncommand: notify now\n"
      AISupportAgent.with_escalation_file(contents) do |directory|
        expect_raises(EscalationProcedureRegistry::ValidationError, /command/) do
          EscalationProcedureRegistry.load(directory)
        end
      end
    end

    it "retains the last-known-good catalogue after an invalid live edit" do
      base = File.join(Dir.tempdir, "support-escalation-reload-#{UUID.random}")
      root = File.join(base, "playbooks")
      Dir.mkdir_p(base)
      FileUtils.cp_r("playbooks", root)
      catalog = WorkflowCatalog.load(root)
      procedure = File.join(root, "escalation", "support-fallback.yml")
      File.write(procedure, File.read(procedure) + "\ncommand: notify now\n")

      catalog.escalation_count.should eq 2
      catalog.workflow_count.should eq 1
      catalog.reload_error.should_not be_nil
    ensure
      FileUtils.rm_rf(base) if base
    end
  end

  describe "escalation workflow" do
    it "attaches ownership policy and records report delivery outcome" do
      report = AISupportAgent.ingest(IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Critical,
        correlation_key: "escalation:critical",
        payload: JSON.parse({message: "unclassified critical failure"}.to_json),
        module_id: "mod-escalation"
      ))

      report.status.escalated?.should be_true
      plan = report.investigation_plan.try(&.escalation)
      plan.try(&.owner_queue).should eq "placeos-critical-support"
      plan.try(&.response_sla_minutes).should eq 15
      report.investigation.map(&.name).should contain "workflow:escalate"
      report.investigation.map(&.name).should contain "workflow:escalated"

      records = AISupportAgent.escalations.for_incident(report.incident_id)
      records.size.should eq 1
      records.first.delivery_status.skipped?.should be_true
      records.first.response_due_at.should be > records.first.created_at

      response = client.get("/api/ai-support/v1/incidents/#{report.incident_id}/escalations")
      response.status_code.should eq 200
      Array(EscalationRecord).from_json(response.body).size.should eq 1
    end
  end

  describe EscalationRecordStore do
    it "loads durable escalation history after memory is cleared" do
      repository = EscalationRepository.new
      store = EscalationRecordStore.new
      store.persist_with(repository)
      plan = EscalationPlan.new(
        procedure: ProcedureAudit.new("escalation", "support-fallback", 1, "a" * 64),
        owner_queue: "placeos-support",
        response_sla_minutes: 60,
        required_artefacts: ["diagnostic_report"],
        reason: "Insufficient evidence"
      )
      record = EscalationRecord.new(
        id: "escalation-persisted",
        incident_id: "aisup-persisted",
        plan: plan,
        delivery_status: ReportDeliveryStatus::Delivered,
        delivery_destination: "generic_webhook",
        delivery_error: nil,
        created_at: Time.utc,
        response_due_at: Time.utc + 60.minutes
      )

      store.save(record)
      store.clear

      store.for_incident(record.incident_id).should eq [record]
      store.size.should eq 1
    end

    it "continues in memory and exposes persistence failures" do
      AISupportAgent.escalations.persist_with(FailingEscalationRepository.new)

      report = AISupportAgent.ingest(IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Critical,
        correlation_key: "escalation:persistence-fallback",
        payload: JSON.parse({message: "unclassified critical failure"}.to_json),
        module_id: "mod-escalation"
      ))

      AISupportAgent.escalations.for_incident(report.incident_id).size.should eq 1
      AISupportAgent.escalations.persistence_error.try(&.should contain "database offline")
      status = Root::Status.from_json(client.get("/api/ai-support/v1/status").body)
      status.persistence_enabled?.should be_true
      status.escalation_persistence_error.try(&.should contain "database offline")
    end
  end
end
