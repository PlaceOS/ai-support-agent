require "file_utils"
require "./helper"

module AISupportAgent
  def self.with_remediation_file(contents : String, & : String ->) : Nil
    directory = File.join(Dir.tempdir, "support-remediation-#{UUID.random}")
    Dir.mkdir_p(directory)
    File.write(File.join(directory, "procedure.yml"), contents)
    yield directory
  ensure
    FileUtils.rm_rf(directory) if directory
  end

  def self.remediation_yaml(action : String = "restart-module") : String
    <<-YAML
    schema_version: remediation-procedure.v1
    id: test-remediation
    version: 1
    name: Test remediation
    mode: remediation
    matches:
      classifications: [runtime_error]
      minimum_confidence: 0.5
      required_context: [module_id]
    proposal:
      action: #{action}
      risk_level: medium
      approval_required: true
      policy_basis: Operator review is required.
      verification: verification:module-runtime-recovery@1
    YAML
  end

  describe RemediationProcedureRegistry do
    it "loads repository procedures with stable identities and hashes" do
      registry = RemediationProcedureRegistry.load("playbooks/remediation")
      event = IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "remediation:select",
        payload: JSON.parse({message: "runtime error"}.to_json),
        module_id: "mod-remediation"
      )
      report = IncidentReport.new(
        incident_id: "aisup-remediation",
        status: IncidentStatus::Open,
        summary: "Runtime error",
        classification: DiagnosticClassification::RuntimeError,
        confidence: 0.8,
        severity: IncidentSeverity::Error,
        source: IncidentSource::Webhook,
        correlation_key: event.correlation_key,
        created_at: Time.utc,
        evidence: [] of Evidence,
        actions_taken: ["report_only_no_remediation"],
        next_steps: [] of String
      )

      registry.size.should eq 3
      selected = registry.select(
        report,
        event,
        [ProcedureReference.parse("remediation:restart-runtime-failure@1")]
      )
      selected.should_not be_nil
      selected.try(&.content_hash.size).should eq 64
      selected.try(&.build_proposal.execution_mode).should eq "proposal_only"
    end

    it "rejects actions outside the reviewed catalogue" do
      AISupportAgent.with_remediation_file(AISupportAgent.remediation_yaml("arbitrary-shell")) do |directory|
        expect_raises(RemediationProcedureRegistry::ValidationError, /unknown action arbitrary-shell/) do
          RemediationProcedureRegistry.load(directory)
        end
      end
    end

    it "rejects execution fields in textual procedures" do
      contents = AISupportAgent.remediation_yaml.sub(
        "  policy_basis: Operator review is required.",
        "  policy_basis: Operator review is required.\n  command: restart now"
      )
      AISupportAgent.with_remediation_file(contents) do |directory|
        expect_raises(RemediationProcedureRegistry::ValidationError, /command/) do
          RemediationProcedureRegistry.load(directory)
        end
      end
    end
  end
end
