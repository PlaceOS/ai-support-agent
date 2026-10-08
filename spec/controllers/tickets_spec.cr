require "../helper"

module AISupportAgent
  def self.stub_placeos_for_tickets : Nil
    base = ENV["PLACE_URI"]? || "http://rest-api:3000"
    WebMock.stub(:get, /#{Regex.escape(base)}\/api\/engine\/v2\/domains\//).to_return(body: "[]")
    WebMock.stub(:get, /#{Regex.escape(base)}\/api\/engine\/v2\/(systems|modules|zones|drivers)\/\?/).to_return(body: "[]")
    WebMock.stub(:get, "#{base}/api/engine/v2/modules/mod-456")
      .to_return(body: {id: "mod-456", name: "Display", control_system_id: "sys-123", running: true, connected: false}.to_json)
    WebMock.stub(:get, "#{base}/api/engine/v2/modules/mod-456/state").to_return(body: {connected: false}.to_json)
    WebMock.stub(:get, "#{base}/api/engine/v2/modules/mod-456/error").to_return(body: ["HTTP 401 Unauthorized"].to_json)
    WebMock.stub(:get, "#{base}/api/engine/v2/systems/sys-123").to_return(body: {id: "sys-123", name: "Boardroom"}.to_json)
    WebMock.stub(:get, "#{base}/api/engine/v2/cluster/").to_return(body: "[]")
  end

  def self.post_ticket(ticket, headers = HTTP::Headers{"Content-Type" => "application/json"})
    client.post("/api/ai-support/v1/tickets/", body: ticket.to_json, headers: headers)
  end

  describe Tickets do
    it "turns a ticket into an incident under its reference" do
      AISupportAgent.stub_placeos_for_tickets

      result = AISupportAgent.post_ticket({
        reference:    "SD-9001",
        summary:      "Display mod-456 in sys-123 returns HTTP 401 Unauthorized",
        description:  "The display driver logs HTTP 401 Unauthorized after the password change.",
        priority:     "High",
        organisation: "Spec Org",
      })

      result.status_code.should eq 202
      report = IncidentReport.from_json(result.body)
      report.source.ticket?.should be_true
      report.correlation_key.should eq "ticket:SD-9001"
      report.classification.http_auth?.should be_true
      report.module_id.should eq "mod-456"
      report.system_id.should eq "sys-123"
      report.severity.error?.should be_true
      report.evidence.map(&.source).should contain "ticket"
      report.evidence.first.data.to_s.should contain "SD-9001"

      fetched = client.get("/api/ai-support/v1/tickets/SD-9001")
      fetched.status_code.should eq 200
      IncidentReport.from_json(fetched.body).incident_id.should eq report.incident_id
    end

    it "escalates a ticket that names nothing it can look up" do
      AISupportAgent.stub_placeos_for_tickets

      result = AISupportAgent.post_ticket({
        reference:   "SD-9002",
        summary:     "Booking panel shows a white screen",
        description: "The iPad in the lobby has shown a white screen since this morning.",
      })

      result.status_code.should eq 202
      report = IncidentReport.from_json(result.body)
      report.status.escalated?.should be_true
      report.module_id.should be_nil
      report.remediation_proposal.should be_nil
      report.evidence.first.data.to_s.should contain "resolution"
      AISupportAgent.escalations.for_incident(report.incident_id).should_not be_empty
    end

    it "treats a later comment as a repeat and a resolved ticket as recovery" do
      AISupportAgent.stub_placeos_for_tickets
      ticket = {reference: "SD-9003", summary: "Projector will not turn on", description: "Level 3 boardroom projector."}

      first = IncidentReport.from_json(AISupportAgent.post_ticket(ticket).body)
      repeat = IncidentReport.from_json(AISupportAgent.post_ticket(ticket.merge(event: "commented", comments: [{body: "Still broken", author: "Reporter"}])).body)
      resolved = IncidentReport.from_json(AISupportAgent.post_ticket(ticket.merge(event: "resolved", resolved: true)).body)

      repeat.incident_id.should eq first.incident_id
      repeat.duplicate_count.should eq 1
      resolved.incident_id.should eq first.incident_id
      resolved.resolved_at.should_not be_nil
      AISupportAgent.incidents.all.size.should eq 1
    end

    it "reads a Jira webhook" do
      AISupportAgent.stub_placeos_for_tickets
      body = {
        webhookEvent: "jira:issue_created",
        issue:        {key: "SD-9004", fields: {summary: "Core pods in CrashLoopBackOff", description: "core-0 restarts every few minutes in production.", priority: {name: "Very High"}, status: {name: "Open", statusCategory: {key: "new"}}}},
      }

      result = client.post("/api/ai-support/v1/tickets/jira", body: body.to_json, headers: HTTP::Headers{"Content-Type" => "application/json"})

      result.status_code.should eq 202
      report = IncidentReport.from_json(result.body)
      report.correlation_key.should eq "ticket:SD-9004"
      report.severity.critical?.should be_true
    end

    it "answers 422 for a ticket without a usable summary and 404 for an unknown reference" do
      AISupportAgent.post_ticket({reference: "SD-9005", summary: " "}).status_code.should eq 422
      client.get("/api/ai-support/v1/tickets/SD-0").status_code.should eq 404
    end

    it "requires the webhook token when one is configured" do
      AISupportAgent.stub_placeos_for_tickets
      Tickets.webhook_token = "spec-token"
      begin
        ticket = {reference: "SD-9006", summary: "Lights stay on overnight"}
        AISupportAgent.post_ticket(ticket).status_code.should eq 401
        AISupportAgent.post_ticket(ticket, HTTP::Headers{"Content-Type" => "application/json", "X-Ticket-Token" => "spec-token"}).status_code.should eq 202
        client.post("/api/ai-support/v1/tickets/?token=spec-token", body: ticket.merge(reference: "SD-9007").to_json, headers: HTTP::Headers{"Content-Type" => "application/json"}).status_code.should eq 202
      ensure
        Tickets.webhook_token = nil
      end
    end
  end
end
