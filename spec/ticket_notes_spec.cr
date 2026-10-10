require "./helper"

module AISupportAgent
  def self.stub_placeos_for_notes : Nil
    base = (ENV["PLACE_URI"]? || "http://rest-api:3000").rstrip('/')
    WebMock.stub(:get, /#{Regex.escape(base)}\/api\/engine\/v2\/domains\//).to_return(body: "[]")
    WebMock.stub(:get, /#{Regex.escape(base)}\/api\/engine\/v2\/(systems|modules|zones|drivers)\/\?/).to_return(body: "[]")
    WebMock.stub(:get, /#{Regex.escape(base)}\/api\/engine\/v2\/(version|platform|cluster\/.*)$/).to_return(body: "[]")
    WebMock.stub(:get, "#{base}/api/engine/v2/version").to_return(body: {service: "rest-api", version: "2.2509.1"}.to_json)
  end

  def self.with_jira_client(client : JiraClient?, &)
    previous = AISupportAgent.jira_client
    AISupportAgent.jira_client = client
    yield
  ensure
    AISupportAgent.jira_client = previous
  end

  def self.post_note_ticket(ticket)
    client.post("/api/ai-support/v1/tickets/", body: ticket.to_json, headers: HTTP::Headers{"Content-Type" => "application/json"})
  end

  describe TicketNotes do
    it "posts an internal triage note with a suggested reply when a ticket arrives" do
      AISupportAgent.stub_placeos_for_notes
      captured = [] of String
      WebMock.stub(:post, "http://jira.test/rest/api/3/issue/SD-NOTE-1/comment").to_return do |request|
        captured << (request.body.try(&.gets_to_end) || "")
        HTTP::Client::Response.new(201, body: {id: "1"}.to_json)
      end

      AISupportAgent.with_jira_client(JiraClient.new("http://jira.test", "agent@example.test", "token")) do
        result = AISupportAgent.post_note_ticket({
          reference:     "SD-NOTE-1",
          summary:       "Core Pods CrashLoopBackOff Causing System Slowness",
          description:   "core-0 restarts every few minutes and the module lists keep spinning.",
          reporter_name: "Jega Selvanayagam",
          priority:      "Very High",
          attachments:   [{filename: "events.png", mime_type: "image/png"}],
        })
        result.status_code.should eq 202
        report = IncidentReport.from_json(result.body)

        captured.size.should eq 1
        sent = JSON.parse(captured.first)
        sent["properties"][0]["value"]["internal"].as_bool.should be_true
        text = SupportTicket.jira_text(sent["body"]).to_s
        text.should contain "AI support agent triage"
        text.should contain "Classification platform_pods_unhealthy"
        text.should contain "Escalated"
        text.should contain "Hi Jega, thanks for reporting this."
        text.should contain "Which environment is this on"
        text.should contain report.incident_id

        deliveries = AISupportAgent.deliveries.for_incident(report.incident_id)
        note = deliveries.find(&.destination.==("jira:SD-NOTE-1:triage")).not_nil!
        note.status.delivered?.should be_true
        note.response_status.should eq 201

        AISupportAgent.post_note_ticket({reference: "SD-NOTE-1", summary: "Core Pods CrashLoopBackOff Causing System Slowness", event: "commented"}).status_code.should eq 202
        captured.size.should eq 1
      end
    end

    it "fills in Root cause when a person resolves the ticket without one, and leaves an existing one alone" do
      AISupportAgent.stub_placeos_for_notes
      WebMock.stub(:post, /jira\.test\/rest\/api\/3\/issue\/SD-NOTE-[23]\/comment/).to_return(status: 201, body: {id: "1"}.to_json)
      WebMock.stub(:get, "http://jira.test/rest/api/3/issue/SD-NOTE-2").with(query: {"fields" => "customfield_10035"})
        .to_return(body: {fields: {customfield_10035: nil}}.to_json)
      updated = nil.as(String?)
      WebMock.stub(:put, "http://jira.test/rest/api/3/issue/SD-NOTE-2").to_return do |request|
        updated = request.body.try(&.gets_to_end)
        HTTP::Client::Response.new(204)
      end
      WebMock.stub(:get, "http://jira.test/rest/api/3/issue/SD-NOTE-3").with(query: {"fields" => "customfield_10035"})
        .to_return(body: {fields: {customfield_10035: {type: "doc", version: 1, content: [{type: "paragraph", content: [{type: "text", text: "PoE adapter replaced"}]}]}}}.to_json)
      untouched = WebMock.stub(:put, "http://jira.test/rest/api/3/issue/SD-NOTE-3").to_return(status: 204)

      AISupportAgent.with_jira_client(JiraClient.new("http://jira.test", "agent@example.test", "token")) do
        open = {reference: "SD-NOTE-2", summary: "Display offline in Boardroom 2", description: "The display stopped responding."}
        AISupportAgent.post_note_ticket(open).status_code.should eq 202
        resolved = IncidentReport.from_json(AISupportAgent.post_note_ticket(open.merge(event: "resolved", resolved: true)).body)

        text = SupportTicket.jira_text(JSON.parse(updated.not_nil!)["fields"]["customfield_10035"]).to_s
        text.should contain "Agent classification:"
        AISupportAgent.deliveries.for_incident(resolved.incident_id).find(&.destination.==("jira:SD-NOTE-2:root_cause")).not_nil!.status.delivered?.should be_true

        filled = {reference: "SD-NOTE-3", summary: "White screen on the lobby iPad"}
        AISupportAgent.post_note_ticket(filled).status_code.should eq 202
        done = IncidentReport.from_json(AISupportAgent.post_note_ticket(filled.merge(event: "resolved", resolved: true)).body)
        untouched.calls.should eq 0
        AISupportAgent.deliveries.for_incident(done.incident_id).find(&.destination.==("jira:SD-NOTE-3:root_cause")).not_nil!.status.skipped?.should be_true
      end
    end

    it "records a failed note without failing the ticket, and a skipped note when Jira is not configured" do
      AISupportAgent.stub_placeos_for_notes
      WebMock.stub(:post, "http://jira.test/rest/api/3/issue/SD-NOTE-4/comment").to_return(status: 500, body: "boom")

      AISupportAgent.with_jira_client(JiraClient.new("http://jira.test", "agent@example.test", "token")) do
        result = AISupportAgent.post_note_ticket({reference: "SD-NOTE-4", summary: "Projector will not turn on"})
        result.status_code.should eq 202
        report = IncidentReport.from_json(result.body)
        failed = AISupportAgent.deliveries.for_incident(report.incident_id).find(&.destination.==("jira:SD-NOTE-4:triage")).not_nil!
        failed.status.failed?.should be_true
        failed.response_status.should eq 500
      end

      AISupportAgent.with_jira_client(nil) do
        report = IncidentReport.from_json(AISupportAgent.post_note_ticket({reference: "SD-NOTE-5", summary: "Lights stay on overnight"}).body)
        skipped = AISupportAgent.deliveries.for_incident(report.incident_id).find(&.destination.==("jira:SD-NOTE-5:triage")).not_nil!
        skipped.status.skipped?.should be_true
        skipped.error.to_s.should contain "not configured"
      end
    end

    it "asks the questions human support asked, from what the ticket leaves out" do
      ticket = SupportTicket.new(reference: "SD-Q", summary: "Panel comms error", attachments: [TicketAttachment.new("shot.png")])
      extraction = TicketExtraction.new(category: "device", evidence_requests: ["Which site is affected"])
      resolution = TicketResolution.new

      questions = TicketNotes.evidence_questions(ticket, extraction, resolution)

      questions.first.should eq "Which site is affected?"
      questions.should contain "Which environment is this on (production, PPE or UAT)?"
      questions.should contain "Which room or system and building is affected, or the Backoffice link to it?"
      questions.size.should eq 4
    end
  end
end
