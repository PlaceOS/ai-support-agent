require "../helper"

module AISupportAgent
  describe Webhooks do
    it "creates report-only incidents from Grafana alerts" do
      result = client.post(
        "/api/ai-support/v1/webhooks/grafana",
        body: {
          status:       "firing",
          groupKey:     "grafana:mod-456",
          commonLabels: {
            severity:    "critical",
            system_id:   "sys-123",
            module_id:   "mod-456",
            module_name: "Display",
          },
          commonAnnotations: {
            description: "Display driver has runtime error",
          },
        }.to_json,
        headers: HTTP::Headers{"Content-Type" => "application/json"}
      )

      result.status_code.should eq 202
      report = IncidentReport.from_json(result.body)
      report.incident_id.should start_with "aisup-"
      report.status.escalated?.should be_true
      report.classification.runtime_error?.should be_true
      report.actions_taken.should eq ["report_only_no_remediation"]
      AISupportAgent.incidents.all.size.should eq 1
    end

    it "creates incidents from generic webhooks and allows lookup" do
      created = client.post(
        "/api/ai-support/v1/webhooks/generic",
        body: {
          source:          "webhook",
          severity:        "error",
          system_id:       "sys-123",
          module_id:       "mod-456",
          correlation_key: "generic:mod-456",
          payload:         {message: "x509 certificate has expired"},
        }.to_json,
        headers: HTTP::Headers{"Content-Type" => "application/json"}
      )

      created.status_code.should eq 202
      report = IncidentReport.from_json(created.body)
      report.classification.tls_certificate?.should be_true

      fetched = client.get("/api/ai-support/v1/incidents/#{report.incident_id}")
      fetched.status_code.should eq 200
      IncidentReport.from_json(fetched.body).incident_id.should eq report.incident_id
    end

    it "raises no proposal for a webhook with a blank module id" do
      created = client.post(
        "/api/ai-support/v1/webhooks/generic",
        body: {
          source:          "webhook",
          severity:        "error",
          system_id:       "",
          module_id:       "",
          correlation_key: "generic:blank-module",
          payload:         {message: "HTTP 401 Unauthorized from upstream"},
        }.to_json,
        headers: HTTP::Headers{"Content-Type" => "application/json"}
      )

      created.status_code.should eq 202
      report = IncidentReport.from_json(created.body)
      report.classification.http_auth?.should be_true
      report.module_id.should be_nil
      report.system_id.should be_nil
      report.evidence.map(&.source).should_not contain "placeos_rest_api"
      report.remediation_proposal.should be_nil
    end

    it "exposes a markdown operator report artefact" do
      created = client.post(
        "/api/ai-support/v1/webhooks/generic",
        body: {
          source:          "webhook",
          severity:        "error",
          system_id:       "sys-123",
          module_id:       "mod-456",
          correlation_key: "generic:mod-456",
          payload:         {message: "runtime error"},
        }.to_json,
        headers: HTTP::Headers{"Content-Type" => "application/json"}
      )
      report = IncidentReport.from_json(created.body)

      fetched = client.get("/api/ai-support/v1/incidents/#{report.incident_id}/report")

      fetched.status_code.should eq 200
      fetched.content_type.should eq "text/markdown"
      fetched.body.should contain "# Incident Diagnostic Report"
      fetched.body.should contain "## Investigation Plan"
      fetched.body.should contain "## Agent Boundary"
      fetched.body.should_not contain "## Remediation Proposal"
      fetched.body.should contain "Workflow: `report-only-incident`"
      fetched.body.should contain "report-only mode"
    end

    it "exposes the agent-run audit trail for an incident" do
      created = client.post(
        "/api/ai-support/v1/webhooks/generic",
        body: {
          source:          "webhook",
          severity:        "error",
          system_id:       "sys-123",
          module_id:       "mod-456",
          correlation_key: "generic:agent-run",
          payload:         {message: "runtime error"},
        }.to_json,
        headers: HTTP::Headers{"Content-Type" => "application/json"}
      )
      report = IncidentReport.from_json(created.body)

      fetched = client.get("/api/ai-support/v1/incidents/#{report.incident_id}/run")
      run = AgentRun.from_json(fetched.body)

      fetched.status_code.should eq 200
      run.incident_id.should eq report.incident_id
      run.investigation_plan.should_not be_nil
      run.investigation.map(&.name).should contain "plan_investigation"
      run.investigation.map(&.name).should contain "tool:module_error_logs"
      run.decision.should_not be_nil
      run.investigation.map(&.name).should contain "workflow:diagnose"
      run.investigation.map(&.name).should contain "workflow:escalate"
      run.remediation_proposal.should be_nil
    end

    it "exposes delivery audit records for an incident" do
      created = client.post(
        "/api/ai-support/v1/webhooks/generic",
        body: {
          source:          "webhook",
          severity:        "error",
          system_id:       "sys-123",
          module_id:       "mod-456",
          correlation_key: "generic:delivery-audit",
          payload:         {message: "runtime error"},
        }.to_json,
        headers: HTTP::Headers{"Content-Type" => "application/json"}
      )
      report = IncidentReport.from_json(created.body)

      fetched = client.get("/api/ai-support/v1/incidents/#{report.incident_id}/deliveries")
      deliveries = Array(ReportDeliveryRecord).from_json(fetched.body)

      fetched.status_code.should eq 200
      deliveries.size.should eq 1
      deliveries.first.incident_id.should eq report.incident_id
      deliveries.first.status.skipped?.should be_true
    end

    it "updates a correlated incident when a resolution signal arrives" do
      created = client.post(
        "/api/ai-support/v1/webhooks/generic",
        body: {
          source:          "webhook",
          severity:        "error",
          system_id:       "sys-123",
          module_id:       "mod-456",
          correlation_key: "generic:resolved",
          payload:         {message: "runtime error"},
        }.to_json,
        headers: HTTP::Headers{"Content-Type" => "application/json"}
      )
      open_report = IncidentReport.from_json(created.body)

      resolved = client.post(
        "/api/ai-support/v1/webhooks/generic",
        body: {
          source:          "webhook",
          severity:        "info",
          system_id:       "sys-123",
          module_id:       "mod-456",
          correlation_key: "generic:resolved",
          payload:         {status: "resolved"},
        }.to_json,
        headers: HTTP::Headers{"Content-Type" => "application/json"}
      )
      resolved_report = IncidentReport.from_json(resolved.body)

      resolved_report.incident_id.should eq open_report.incident_id
      resolved_report.status.resolved?.should be_true
      resolved_report.resolved_at.should_not be_nil
      resolved_report.investigation.map(&.name).should contain "resolve_signal"
      AISupportAgent.incidents.all.size.should eq 1
    end
  end
end
