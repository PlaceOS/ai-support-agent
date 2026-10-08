module AISupportAgent
  module TicketIngest
    extend self

    # The incident event a ticket becomes once it is read and matched to PlaceOS.
    def event_for(ticket : SupportTicket, extraction : TicketExtraction, resolution : TicketResolution) : IncidentEvent
      payload = JSON.parse({
        ticket:     ticket,
        extraction: extraction,
        resolution: resolution,
        status:     ticket.resolved? ? "resolved" : "open",
        event:      ticket.event,
      }.to_json)

      IncidentEvent.new(
        source: IncidentSource::Ticket,
        severity: severity_for(extraction),
        correlation_key: correlation_key(ticket.reference),
        payload: payload,
        tenant_id: resolution.tenant_id,
        system_id: resolution.system_id,
        module_id: resolution.module_id,
        module_name: resolution.module_name
      )
    end

    def correlation_key(reference : String) : String
      "ticket:#{reference.strip.upcase}"
    end

    def severity_for(extraction : TicketExtraction) : IncidentSeverity
      case extraction.urgency
      when "critical" then IncidentSeverity::Critical
      when "high"     then IncidentSeverity::Error
      when "low"      then IncidentSeverity::Info
      else                 IncidentSeverity::Warning
      end
    end
  end
end
