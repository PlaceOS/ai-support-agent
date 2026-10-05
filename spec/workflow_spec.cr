require "file_utils"
require "./helper"

module AISupportAgent
  def self.with_workflow_file(contents : String, & : String ->) : Nil
    directory = File.join(Dir.tempdir, "support-workflows-#{UUID.random}")
    Dir.mkdir_p(directory)
    File.write(File.join(directory, "workflow.yml"), contents)
    yield directory
  ensure
    FileUtils.rm_rf(directory) if directory
  end

  def self.workflow_yaml(reference : String = "diagnostic:module-runtime-error@1") : String
    <<-YAML
    schema_version: workflow.v1
    id: test-workflow
    version: 1
    name: Test workflow
    entrypoint: diagnose
    default: true
    stages:
      - id: diagnose
        type: diagnostic
        procedures: [#{reference}]
        transitions:
          diagnosed: propose
          insufficient_evidence: escalate
      - id: propose
        type: remediation
        procedures: [remediation:restart-runtime-failure@1]
        transitions:
          proposal_created: report
          no_proposal: report
      - id: report
        type: report
        terminal: true
      - id: escalate
        type: escalation
        procedures: [escalation:support-fallback@1]
        transitions:
          escalated: escalated
      - id: escalated
        type: escalated
        terminal: true
    YAML
  end

  describe WorkflowRegistry do
    it "loads workflows and validates procedure references" do
      procedures = DiagnosticProcedureRegistry.load("playbooks/diagnostics", live_reload: false)
      remediations = RemediationProcedureRegistry.load("playbooks/remediation")
      escalations = EscalationProcedureRegistry.load("playbooks/escalation")
      workflows = WorkflowRegistry.load("playbooks/workflows", procedures, remediations, escalations)

      workflows.size.should eq 1
      workflow = workflows.default
      workflow.id.should eq "report-only-incident"
      workflow.stage(workflow.entrypoint).procedure_references.size.should eq 8
      workflow.content_hash.size.should eq 64
    end

    it "rejects missing procedure references" do
      procedures = DiagnosticProcedureRegistry.load("playbooks/diagnostics", live_reload: false)
      remediations = RemediationProcedureRegistry.load("playbooks/remediation")
      escalations = EscalationProcedureRegistry.load("playbooks/escalation")
      AISupportAgent.with_workflow_file(AISupportAgent.workflow_yaml("diagnostic:not-present@1")) do |directory|
        expect_raises(WorkflowRegistry::ValidationError, /missing procedure/) do
          WorkflowRegistry.load(directory, procedures, remediations, escalations)
        end
      end
    end

    it "rejects missing remediation procedure references" do
      diagnostics = DiagnosticProcedureRegistry.load("playbooks/diagnostics", live_reload: false)
      remediations = RemediationProcedureRegistry.load("playbooks/remediation")
      escalations = EscalationProcedureRegistry.load("playbooks/escalation")
      contents = AISupportAgent.workflow_yaml.sub(
        "remediation:restart-runtime-failure@1",
        "remediation:not-present@1"
      )
      AISupportAgent.with_workflow_file(contents) do |directory|
        expect_raises(WorkflowRegistry::ValidationError, /missing procedure/) do
          WorkflowRegistry.load(directory, diagnostics, remediations, escalations)
        end
      end
    end

    it "rejects missing escalation procedure references" do
      diagnostics = DiagnosticProcedureRegistry.load("playbooks/diagnostics", live_reload: false)
      remediations = RemediationProcedureRegistry.load("playbooks/remediation")
      escalations = EscalationProcedureRegistry.load("playbooks/escalation")
      contents = AISupportAgent.workflow_yaml.sub(
        "escalation:support-fallback@1",
        "escalation:not-present@1"
      )
      AISupportAgent.with_workflow_file(contents) do |directory|
        expect_raises(WorkflowRegistry::ValidationError, /missing procedure/) do
          WorkflowRegistry.load(directory, diagnostics, remediations, escalations)
        end
      end
    end

    it "rejects undeclared transition targets" do
      procedures = DiagnosticProcedureRegistry.load("playbooks/diagnostics", live_reload: false)
      remediations = RemediationProcedureRegistry.load("playbooks/remediation")
      escalations = EscalationProcedureRegistry.load("playbooks/escalation")
      contents = AISupportAgent.workflow_yaml.sub("diagnosed: propose", "diagnosed: missing")
      AISupportAgent.with_workflow_file(contents) do |directory|
        expect_raises(WorkflowRegistry::ValidationError, /targets missing stage/) do
          WorkflowRegistry.load(directory, procedures, remediations, escalations)
        end
      end
    end

    it "rejects workflow cycles" do
      procedures = DiagnosticProcedureRegistry.load("playbooks/diagnostics", live_reload: false)
      remediations = RemediationProcedureRegistry.load("playbooks/remediation")
      escalations = EscalationProcedureRegistry.load("playbooks/escalation")
      contents = AISupportAgent.workflow_yaml
        .sub("diagnosed: propose", "diagnosed: diagnose")
      AISupportAgent.with_workflow_file(contents) do |directory|
        expect_raises(WorkflowRegistry::ValidationError, /cycle/) do
          WorkflowRegistry.load(directory, procedures, remediations, escalations)
        end
      end
    end
  end

  describe WorkflowRunner do
    it "escalates a missing target without a remediation proposal" do
      WebMock.stub(:get, "http://place.test/api/engine/v2/modules/mod-missing").to_return(status: 404)
      system = WebMock.stub(:get, "http://place.test/api/engine/v2/systems/sys-existing").to_return(body: "{}")
      context = PlaceOSContext.new(::PlaceOS::Client.new("http://place.test", x_api_key: "test-key"))
      runner = WorkflowRunner.new(WorkflowCatalog.load("playbooks"), DiagnosticEngine.new(context, AIReporter.disabled))
      event = IncidentEvent.new(source: IncidentSource::Webhook, severity: IncidentSeverity::Error,
        correlation_key: "missing-target-workflow", payload: JSON.parse({message: "runtime error"}.to_json),
        module_id: "mod-missing", system_id: "sys-existing")
      report = runner.report_for(Incident.new("aisup-missing-workflow", event, Time.utc))
      report.remediation_proposal.should be_nil
      report.status.escalated?.should be_true
      report.confidence.should eq 0.0
      delivery = ReportDeliveryRecord.new(report.incident_id, ReportDeliveryStatus::Skipped, "disabled", Time.utc)
      escalation = EscalationRecord.from(report, delivery)
      escalation.should_not be_nil
      escalation.not_nil!.incident_id.should eq report.incident_id
      system.calls.should eq 0
    end

    it "routes sufficient diagnostics to the declared report terminal" do
      catalog = WorkflowCatalog.load("playbooks")
      context = PlaceOSContext.static([Evidence.new(source: "fixture", message: "context available")])
      runner = WorkflowRunner.new(catalog, DiagnosticEngine.new(context, AIReporter.disabled))
      event = IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "workflow-report",
        payload: JSON.parse({message: "HTTP 401 Unauthorized"}.to_json),
        module_id: "mod-workflow",
        system_id: "sys-workflow"
      )

      report = runner.report_for(Incident.new("aisup-workflow-report", event, Time.utc))

      report.status.open?.should be_true
      report.investigation.map(&.name).should contain "workflow:diagnose"
      report.investigation.map(&.name).should contain "workflow:report"
      plan = report.investigation_plan
      plan.try(&.workflow_id).should eq "report-only-incident"
      plan.try(&.workflow_version).should eq 1
      plan.try(&.workflow_hash.to_s.size).should eq 64
      plan.try(&.workflow_stage).should eq "diagnose"
      plan.try(&.procedures.map(&.category)).should eq ["diagnostic", "remediation"]
      report.investigation.map(&.name).should contain "workflow:propose"
      report.investigation.map(&.name).should contain "remediation:update-http-credentials"
      report.remediation_proposal.should_not be_nil
      report.remediation_proposal.try(&.execution_mode).should eq "proposal_only"
      report.remediation_proposal.try(&.approval_required?).should be_true
    end

    it "routes unmatched remediation to the report without a proposal" do
      catalog = WorkflowCatalog.load("playbooks")
      context = PlaceOSContext.static([Evidence.new(source: "fixture", message: "context available")])
      runner = WorkflowRunner.new(catalog, DiagnosticEngine.new(context, AIReporter.disabled))
      event = IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "workflow-no-proposal",
        payload: JSON.parse({message: "connection closed by remote host"}.to_json),
        module_id: "mod-workflow"
      )

      report = runner.report_for(Incident.new("aisup-workflow-no-proposal", event, Time.utc))

      report.status.open?.should be_true
      report.classification.tcp_closed?.should be_true
      report.investigation.map(&.name).should contain "workflow:propose"
      report.investigation.map(&.name).should contain "workflow:report"
      report.remediation_proposal.should be_nil
      report.investigation_plan.try(&.procedures.map(&.category)).should eq ["diagnostic"]
    end

    it "routes insufficient diagnostics to the declared escalation terminal" do
      catalog = WorkflowCatalog.load("playbooks")
      runner = WorkflowRunner.new(catalog, DiagnosticEngine.new(PlaceOSContext.new, AIReporter.disabled))
      event = IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Warning,
        correlation_key: "workflow-escalate",
        payload: JSON.parse({message: "unclassified incident"}.to_json),
        module_id: "mod-workflow"
      )

      report = runner.report_for(Incident.new("aisup-workflow-escalate", event, Time.utc))

      report.status.escalated?.should be_true
      report.investigation.map(&.name).should contain "workflow:escalate"
      report.decision.try(&.escalation_required?).should be_true
    end
  end

  describe WorkflowCatalog do
    it "retains the complete last-known-good snapshot after an invalid remediation edit" do
      base = File.join(Dir.tempdir, "support-catalog-#{UUID.random}")
      root = File.join(base, "playbooks")
      Dir.mkdir_p(base)
      FileUtils.cp_r("playbooks", root)
      catalog = WorkflowCatalog.load(root)
      procedure = File.join(root, "remediation", "restart-runtime-failure.yml")
      File.write(procedure, File.read(procedure) + "\ncommand: restart now\n")

      catalog.remediation_count.should eq 3
      catalog.verification_count.should eq 2
      catalog.diagnostic_count.should eq 8
      catalog.workflow_count.should eq 1
      catalog.reload_error.should_not be_nil
    ensure
      FileUtils.rm_rf(base) if base
    end
  end
end
