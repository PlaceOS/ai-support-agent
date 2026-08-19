require "./helper"

module AISupportAgent
  class FailingApprovalRepository < PostgresIncidentRepository
    def save_approval_request(request : ApprovalRequest) : ApprovalRequest
      raise "database offline"
    end

    def find_approval_request(id : String) : ApprovalRequest?
      nil
    end

    def approval_requests_for_incident(incident_id : String) : Array(ApprovalRequest)
      [] of ApprovalRequest
    end
  end

  def self.report_with_remediation_proposal(correlation_key : String) : IncidentReport
    report = IncidentReport.new(
      incident_id: "aisup-#{correlation_key.gsub(':', '-')}",
      status: IncidentStatus::Open,
      summary: "Remediation proposal awaiting review",
      classification: DiagnosticClassification::RuntimeError,
      confidence: 0.8,
      severity: IncidentSeverity::Error,
      source: IncidentSource::Webhook,
      correlation_key: correlation_key,
      created_at: Time.utc,
      evidence: [] of Evidence,
      actions_taken: ["report_only_no_remediation"],
      next_steps: ["Review the proposal"],
      remediation_proposal: RemediationProposal.new(
        action: "Review and restart the affected module",
        risk_level: "medium",
        approval_required: true,
        execution_mode: "proposal_only",
        policy_basis: "Synthetic remediation-stage fixture for approval audit tests",
        verification_plan: ["Confirm the module is running without runtime errors"]
      )
    )
    incidents.save(report)
  end

  describe ApprovalRequest do
    it "creates a pending approval request from an incident proposal" do
      report = AISupportAgent.report_with_remediation_proposal("approval:create")

      created = client.post(
        "/api/ai-support/v1/incidents/#{report.incident_id}/approval_requests",
        body: {requested_by: "operator@example.com", note: "Please review"}.to_json,
        headers: HTTP::Headers{"Content-Type" => "application/json"}
      )

      created.status_code.should eq 201
      approval = ApprovalRequest.from_json(created.body)
      approval.incident_id.should eq report.incident_id
      approval.status.pending?.should be_true
      approval.execution_mode.should eq "approval_only"
      approval.requested_by.should eq "operator@example.com"
      approval.proposal.should_not be_nil
      approval.executed_at.should be_nil

      approvals = AISupportAgent.approvals.for_incident(report.incident_id)
      approvals.size.should eq 1
      approvals.first.id.should eq approval.id
    end

    it "records approval decisions without executing remediation" do
      report = AISupportAgent.report_with_remediation_proposal("approval:approve")
      approval = AISupportAgent.approvals.create(report, requested_by: "operator@example.com")

      updated = client.post(
        "/api/ai-support/v1/incidents/#{report.incident_id}/approval_requests/#{approval.id}/approve",
        body: {decided_by: "lead@example.com", note: "Approved for later operator action"}.to_json,
        headers: HTTP::Headers{"Content-Type" => "application/json"}
      )

      updated.status_code.should eq 200
      approved = ApprovalRequest.from_json(updated.body)
      approved.status.approved?.should be_true
      approved.decided_by.should eq "lead@example.com"
      approved.decision_note.should eq "Approved for later operator action"
      approved.executed_at.should be_nil
      approved.execution_mode.should eq "approval_only"

      stored_report = AISupportAgent.incidents.find(report.incident_id)
      stored_report.should_not be_nil
      stored_report.try(&.actions_taken).should eq ["report_only_no_remediation"]
    end

    it "records rejection decisions and lists approval audit records" do
      report = AISupportAgent.report_with_remediation_proposal("approval:reject")
      approval = AISupportAgent.approvals.create(report, requested_by: "operator@example.com")

      rejected = client.post(
        "/api/ai-support/v1/incidents/#{report.incident_id}/approval_requests/#{approval.id}/reject",
        body: {decided_by: "lead@example.com", note: "Need more evidence"}.to_json,
        headers: HTTP::Headers{"Content-Type" => "application/json"}
      )
      fetched = client.get("/api/ai-support/v1/incidents/#{report.incident_id}/approval_requests")
      approvals = Array(ApprovalRequest).from_json(fetched.body)

      rejected.status_code.should eq 200
      ApprovalRequest.from_json(rejected.body).status.rejected?.should be_true
      fetched.status_code.should eq 200
      approvals.size.should eq 1
      approvals.first.status.rejected?.should be_true
      approvals.first.decision_note.should eq "Need more evidence"
    end

    it "does not decide an approval through another incident" do
      report = AISupportAgent.report_with_remediation_proposal("approval:ownership")
      other = AISupportAgent.ingest(IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "approval:other-incident",
        payload: JSON.parse({message: "runtime error"}.to_json),
        module_id: "mod-other"
      ))
      approval = AISupportAgent.approvals.create(report, requested_by: "operator@example.com")

      response = client.post(
        "/api/ai-support/v1/incidents/#{other.incident_id}/approval_requests/#{approval.id}/approve",
        body: {decided_by: "lead@example.com"}.to_json,
        headers: HTTP::Headers{"Content-Type" => "application/json"}
      )

      response.status_code.should eq 404
      AISupportAgent.approvals.find(approval.id).try(&.status.pending?).should be_true
    end

    it "does not create approval requests for incidents without proposals" do
      report = IncidentReport.new(
        incident_id: "aisup-no-proposal",
        status: IncidentStatus::Open,
        summary: "Legacy report",
        classification: DiagnosticClassification::Unknown,
        confidence: 0.2,
        severity: IncidentSeverity::Info,
        source: IncidentSource::Webhook,
        correlation_key: "approval:no-proposal",
        created_at: Time.utc,
        evidence: [] of Evidence,
        actions_taken: ["report_only_no_remediation"],
        next_steps: [] of String
      )
      AISupportAgent.incidents.save(report)

      created = client.post(
        "/api/ai-support/v1/incidents/#{report.incident_id}/approval_requests",
        body: {requested_by: "operator@example.com"}.to_json,
        headers: HTTP::Headers{"Content-Type" => "application/json"}
      )

      created.status_code.should eq 422
      AISupportAgent.approvals.for_incident(report.incident_id).should be_empty
    end

    it "continues in memory when approval persistence fails" do
      repository = FailingApprovalRepository.new
      AISupportAgent.approvals.persist_with(repository)
      report = AISupportAgent.report_with_remediation_proposal("approval:persistence-fallback")

      approval = AISupportAgent.approvals.create(report, requested_by: "operator@example.com")
      fetched = AISupportAgent.approvals.find(approval.id)

      fetched.should_not be_nil
      fetched.try(&.id).should eq approval.id
      AISupportAgent.approvals.persistence_error.try(&.should contain "database offline")
    end
  end
end
