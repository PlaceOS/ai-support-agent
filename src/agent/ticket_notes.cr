module AISupportAgent
  # Builds Atlassian Document Format bodies for Jira.
  class Adf
    @content = [] of JSON::Any

    def self.doc(& : Adf -> Nil) : JSON::Any
      builder = new
      yield builder
      builder.to_json_any
    end

    def heading(text : String, level : Int32 = 3) : Nil
      @content << JSON.parse({type: "heading", attrs: {level: level}, content: [{type: "text", text: text}]}.to_json)
    end

    def paragraph(text : String) : Nil
      @content << JSON.parse({type: "paragraph", content: [{type: "text", text: text}]}.to_json)
    end

    # a paragraph that starts with a bold label
    def labelled(label : String, text : String) : Nil
      @content << JSON.parse({
        type:    "paragraph",
        content: [{type: "text", text: label, marks: [{type: "strong"}]}, {type: "text", text: " " + text}],
      }.to_json)
    end

    def bullets(items : Array(String)) : Nil
      return if items.empty?
      list = items.map { |item| {type: "listItem", content: [{type: "paragraph", content: [{type: "text", text: item}]}]} }
      @content << JSON.parse({type: "bulletList", content: list}.to_json)
    end

    def to_json_any : JSON::Any
      JSON.parse({type: "doc", version: 1, content: @content}.to_json)
    end
  end

  # Writes what the agent found back to the service desk ticket: an internal
  # triage note with a suggested reply when a ticket arrives, and the Root cause
  # field when a person resolves the ticket without filling it in. Never raises;
  # every attempt leaves a delivery record on the incident.
  module TicketNotes
    extend self

    MAX_EVIDENCE   =   8
    MAX_QUESTIONS  =   4
    MAX_FACT_CHARS = 300

    def triage(ticket : SupportTicket, extraction : TicketExtraction, resolution : TicketResolution, report : IncidentReport) : ReportDeliveryRecord
      deliver(report, "jira:#{ticket.reference}:triage") do |client|
        client.add_comment(ticket.reference, triage_note(ticket, extraction, resolution, report), internal: true)
        201
      end
    end

    # Fills the ticket's Root cause field from the report when a person has resolved the ticket and left it empty.
    def record_resolution(ticket : SupportTicket, report : IncidentReport, field : String = JIRA_ROOT_CAUSE_FIELD) : ReportDeliveryRecord
      deliver(report, "jira:#{ticket.reference}:root_cause") do |client|
        current = client.fields(ticket.reference, [field])[field]?
        if current && !SupportTicket.jira_text(current).nil?
          next nil
        end
        body = Adf.doc { |adf| adf.paragraph(root_cause_text(report)) }
        client.update_fields(ticket.reference, {field => body})
        204
      end
    end

    # The internal note: what was read, what matched, what the evidence says, and a reply a person can send.
    def triage_note(ticket : SupportTicket, extraction : TicketExtraction, resolution : TicketResolution, report : IncidentReport) : JSON::Any
      Adf.doc do |adf|
        adf.heading("AI support agent triage", 3)
        adf.labelled("Read as:", extraction.summary || ticket.summary)
        adf.bullets([
          "Category #{extraction.category}; environment #{extraction.environment || "not stated"}; urgency #{extraction.urgency || "medium"}",
          match_line(resolution, report),
          "Classification #{report.classification} at confidence #{report.confidence.round(2)}; incident #{report.incident_id}",
          status_line(report),
        ])

        facts = facts(report)
        unless facts.empty?
          adf.heading("Evidence", 4)
          adf.bullets(facts)
        end

        steps = report.next_steps.first(5)
        proposal = report.remediation_proposal
        steps << "Proposed, approval required: #{proposal.action} (risk #{proposal.risk_level})" if proposal
        unless steps.empty?
          adf.heading("Next steps", 4)
          adf.bullets(steps)
        end

        adf.heading("Suggested reply to the reporter", 4)
        adf.paragraph(suggested_reply(ticket, extraction, resolution, report))
        adf.paragraph("Internal note from the agent. Nothing on the system was changed.")
      end
    end

    # A public reply a person can send as is: acknowledgement, what was understood, and the questions a support engineer would ask.
    def suggested_reply(ticket : SupportTicket, extraction : TicketExtraction, resolution : TicketResolution, report : IncidentReport) : String
      name = ticket.reporter_name.try(&.split.first?).try(&.strip.presence)
      greeting = name ? "Hi #{name}," : "Hi,"
      understood = extraction.summary || ticket.summary
      looking = if target = resolution.module_name || resolution.system_id
                  " We are looking at #{target} now."
                else
                  ""
                end
      questions = evidence_questions(ticket, extraction, resolution)
      ask = questions.empty? ? "" : " To narrow it down: " + questions.join(" ")
      "#{greeting} thanks for reporting this. We read it as: #{understood.rstrip(".")}.#{looking}#{ask} We will update this ticket as we find more."
    end

    # The questions human support asked before investigating, chosen from what the ticket leaves out.
    def evidence_questions(ticket : SupportTicket, extraction : TicketExtraction, resolution : TicketResolution) : Array(String)
      questions = extraction.evidence_requests.first(3).map { |question| question.rstrip("?.") + "?" }
      questions << "Which environment is this on (production, PPE or UAT)?" unless extraction.environment
      unless resolution.resolved?
        questions << "Which room or system and building is affected, or the Backoffice link to it?"
      end
      if !ticket.attachments.empty? && extraction.errors.empty?
        questions << "Could you paste the error text rather than a screenshot, so we can search for it?"
      end
      case extraction.category
      when "device"
        questions << "Is the device reachable from the network (does it answer a ping or telnet on its control port)?"
      when "auth"
        questions << "Does the same user see the problem in a private browser window, and when did they last sign in successfully?"
      end
      questions.uniq { |question| question.downcase }.first(MAX_QUESTIONS)
    end

    def root_cause_text(report : IncidentReport) : String
      summary = report.ai_summary || report.decision.try(&.recommended_action) || report.summary
      facts = facts(report).first(3)
      text = "Agent classification: #{report.classification} (confidence #{report.confidence.round(2)}). #{summary.rstrip(".")}."
      text += " Evidence: #{facts.join("; ")}." unless facts.empty?
      text
    end

    # Short facts pulled from the evidence the tools returned.
    def facts(report : IncidentReport) : Array(String)
      facts = [] of String
      report.evidence.each do |item|
        data = item.data.try(&.as_h?)
        next unless data
        if missing = strings(data["missing_settings"]?)
          facts << "Driver settings not set at any level: #{missing.join(", ")}" unless missing.empty?
        end
        if (compiled = data["compiled"]?) && compiled.as_bool? == false
          output = data["compilation_output"]?.try(&.as_s?).try(&.lines.first?).try(&.strip)
          facts << "Driver #{data["name"]?.try(&.as_s?) || data["driver_id"]?.try(&.as_s?)} is not compiled#{output ? ": #{output[0, 120]}" : ""}"
        end
        if data["index_stale"]?.try(&.as_bool?) == true
          facts << "System #{data["name"]?.try(&.as_s?) || data["system_id"]?.try(&.as_s?)} exists by id but is missing from search or its zone listing"
        end
        if summary = data["summary"]?.try(&.as_h?)
          stopped = summary["stopped"]?.try(&.as_i?)
          errors = summary["runtime_errors"]?.try(&.as_i?)
          total = summary["total"]?.try(&.as_i?)
          facts << "#{total} modules in the system, #{stopped} stopped, #{errors} with runtime errors" if total && stopped && errors
        end
        if nodes = data["node_count"]?.try(&.as_i?)
          facts << "#{nodes} core node(s) with #{data["total_modules_loaded"]?.try(&.as_i?) || 0} modules loaded"
        end
        if api = data["rest_api"]?.try(&.as_h?)
          version = api["version"]?.try(&.as_s?)
          facts << "Platform version #{version}" if version
        end
        if (logs = data["logs"]?) && (first = logs.as_a?.try(&.first?)).try(&.as_s?)
          facts << "Last error: #{first.as_s[0, MAX_FACT_CHARS]}"
        end
      end
      facts.uniq.first(MAX_EVIDENCE)
    end

    private def match_line(resolution : TicketResolution, report : IncidentReport) : String
      if report.module_id
        "Matched module #{report.module_name || report.module_id} (#{report.module_id})#{report.system_id ? " in system #{report.system_id}" : ""} by #{resolution.method}"
      elsif report.system_id
        "Matched system #{report.system_id} by #{resolution.method}"
      elsif resolution.ambiguous?
        names = resolution.candidates.first(5).map { |candidate| "#{candidate.name || candidate.id} (#{candidate.kind})" }
        "No single match; candidates: #{names.join(", ")}"
      else
        "No PlaceOS record matched: #{resolution.notes.first? || "the ticket names nothing to look up"}"
      end
    end

    private def status_line(report : IncidentReport) : String
      if report.status.escalated?
        queue = report.investigation_plan.try(&.escalation).try(&.owner_queue)
        "Escalated#{queue ? " to #{queue}" : ""}: a person needs to pick this up"
      else
        "Diagnosed; report ready"
      end
    end

    private def strings(value : JSON::Any?) : Array(String)?
      value.try(&.as_a?).try(&.compact_map(&.as_s?))
    end

    # Runs the write against the configured client and records the outcome on the incident.
    # The block returns the HTTP status to record, or nil when there was nothing to do.
    private def deliver(report : IncidentReport, destination : String, & : JiraClient -> Int32?) : ReportDeliveryRecord
      record = unless client = AISupportAgent.jira_client
        ReportDeliveryRecord.new(incident_id: report.incident_id, status: ReportDeliveryStatus::Skipped, destination: destination, attempted_at: Time.utc, error: "Jira is not configured")
      else
        begin
          if status = yield client
            ReportDeliveryRecord.new(incident_id: report.incident_id, status: ReportDeliveryStatus::Delivered, destination: destination, attempted_at: Time.utc, response_status: status)
          else
            ReportDeliveryRecord.new(incident_id: report.incident_id, status: ReportDeliveryStatus::Skipped, destination: destination, attempted_at: Time.utc, error: "the field is already filled in")
          end
        rescue error
          AISupportAgent::Log.warn(exception: error) { "writing to the service desk ticket failed" }
          ReportDeliveryRecord.new(incident_id: report.incident_id, status: ReportDeliveryStatus::Failed, destination: destination, attempted_at: Time.utc, response_status: error.as?(JiraClient::Error).try(&.status), error: "#{error.class}: #{error.message}")
        end
      end
      AISupportAgent.deliveries.save(record)
    end
  end
end
