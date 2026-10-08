require "./helper"

module AISupportAgent
  describe Root do
    it "health checks" do
      result = client.get("/api/ai-support/v1/")
      result.status_code.should eq 200
    end

    it "returns version metadata" do
      result = client.get("/api/ai-support/v1/version")
      result.status_code.should eq 200

      version = Root::Version.from_json(result.body)
      version.service.should eq "ai-support-agent"
    end

    it "returns persistence status" do
      result = client.get("/api/ai-support/v1/status")
      result.status_code.should eq 200

      status = Root::Status.from_json(result.body)
      status.service.should eq "ai-support-agent"
      status.database_configured?.should be_true
      status.persistence_enabled?.should be_true
      status.persistence_schema.state.should eq "ready"
      status.persistence_schema.ready?.should be_true
      status.report_delivery_persistence_error.should be_nil
      status.verification_persistence_error.should be_nil
      status.escalation_persistence_error.should be_nil
      status.maintenance_persistence_error.should be_nil
      status.correlation_persistence_error.should be_nil
      status.feedback_persistence_error.should be_nil
      status.trend_persistence_error.should be_nil
      status.report_count.should eq 0
      status.playbook_count.should eq 1
      status.playbook_path.should eq "playbooks"
      status.playbook_reload_error.should be_nil
      status.workflow_count.should eq 1
      status.diagnostic_procedure_count.should eq 15
      status.remediation_procedure_count.should eq 6
      status.verification_procedure_count.should eq 4
      status.verification_run_count.should eq 0
      status.escalation_procedure_count.should eq 2
      status.escalation_record_count.should eq 0
      status.maintenance_procedure_count.should eq 1
      status.maintenance_run_count.should eq 0
      status.correlation_policy_count.should eq 1
      status.correlation_finding_count.should eq 0
      status.feedback_count.should eq 0
      status.trend_report_count.should eq 0
      status.placeos_context_configured?.should eq AISupportAgent.context.configured?
      status.placeos_context_error.should eq AISupportAgent.context.configuration_error
    end
  end
end
