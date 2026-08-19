require "./helper"

module AISupportAgent
  describe "report-only remediation boundary" do
    it "does not expose remediation routes" do
      response = client.post("/api/ai-support/v1/incidents/aisup-spec/remediate")
      response.status_code.should eq 404
    end

    it "does not expose approval execution routes" do
      response = client.post("/api/ai-support/v1/incidents/aisup-spec/approval_requests/appr-spec/execute")
      response.status_code.should eq 404
    end

    it "records that no remediation was attempted" do
      report = AISupportAgent.ingest(IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Critical,
        correlation_key: "boundary",
        payload: JSON.parse({message: "connection timed out"}.to_json),
        module_id: "mod-123"
      ))

      report.classification.tcp_timeout?.should be_true
      report.actions_taken.should eq ["report_only_no_remediation"]
      report.remediation_proposal.should be_nil
      report.investigation.map(&.name).should contain "workflow:diagnose"
      report.investigation.map(&.name).should contain "workflow:escalate"
    end
  end
end
