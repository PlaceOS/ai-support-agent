require "crypto/subtle"

module AISupportAgent
  class Tickets < Application
    base "/api/ai-support/v1/tickets"

    # the shared token a service desk must send as `X-Ticket-Token` or `?token=`; no check when unset
    class_property webhook_token : String? = TICKET_WEBHOOK_TOKEN

    class Unauthorized < Exception
    end

    @[AC::Route::Exception(Unauthorized, status_code: HTTP::Status::UNAUTHORIZED)]
    def unauthorized(error) : CommonError
      CommonError.new(error)
    end

    @[AC::Route::Filter(:before_action, only: [:create, :jira])]
    protected def check_token
      expected = Tickets.webhook_token
      return unless expected
      provided = request.headers["X-Ticket-Token"]? || params["token"]?
      return if provided && Crypto::Subtle.constant_time_compare(provided, expected)
      raise Unauthorized.new("a valid ticket webhook token is required")
    end

    # a ticket already normalised by the caller
    @[AC::Route::POST("/", status_code: HTTP::Status::ACCEPTED)]
    def create : IncidentReport
      ticket = read { SupportTicket.from_json(request_body) }
      AISupportAgent.ingest_ticket(ticket)
    end

    # a Jira Cloud webhook (issue created, updated or commented) or a Jira issue document
    @[AC::Route::POST("/jira", status_code: HTTP::Status::ACCEPTED)]
    def jira : IncidentReport
      ticket = read { SupportTicket.from_jira(request_body) }
      AISupportAgent.ingest_ticket(ticket)
    end

    # the open or most recent incident for a ticket reference
    @[AC::Route::GET("/:reference")]
    def show(reference : String) : IncidentReport
      AISupportAgent.incidents.find_by_correlation_key(TicketIngest.correlation_key(reference)) ||
        raise Error::NotFound.new("no incident for ticket #{reference}")
    end

    # @returns the ticket the block reads; a ticket the block rejects becomes a 422
    private def read(& : -> SupportTicket) : SupportTicket
      yield
    rescue error : ArgumentError
      raise Error::UnprocessableEntity.new(error.message)
    end

    private def request_body : String
      request.body.try(&.gets_to_end) || ""
    end
  end
end
