module AISupportAgent
  class Webhooks < Application
    base "/api/ai-support/v1/webhooks"

    @[AC::Route::POST("/grafana", status_code: HTTP::Status::ACCEPTED)]
    def grafana : IncidentReport
      AISupportAgent.ingest(WebhookIngest.grafana(request_body))
    end

    @[AC::Route::POST("/generic", status_code: HTTP::Status::ACCEPTED)]
    def generic : IncidentReport
      AISupportAgent.ingest(WebhookIngest.generic(request_body))
    end

    private def request_body : String
      request.body.try(&.gets_to_end) || ""
    end
  end
end
