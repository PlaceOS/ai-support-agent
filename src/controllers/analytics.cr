module AISupportAgent
  class Analytics < Application
    base "/api/ai-support/v1/analytics"

    @[AC::Route::GET("/correlations")]
    def correlations(limit : Int32 = 100) : Array(CorrelationFinding)
      validate_limit(limit)
      AISupportAgent.correlation_findings.all.last(limit)
    end

    @[AC::Route::POST("/trends", status_code: HTTP::Status::CREATED)]
    def create_trend : TrendReport
      body = TrendRequest.from_json(request_body)
      AISupportAgent.trends.generate(body.window_seconds)
    rescue error : ArgumentError
      raise Error::UnprocessableEntity.new(error.message)
    end

    @[AC::Route::GET("/trends")]
    def trend_reports(limit : Int32 = 100) : Array(TrendReport)
      validate_limit(limit)
      AISupportAgent.trend_reports.all.last(limit)
    end

    @[AC::Route::GET("/trends/:id")]
    def trend_report(id : String) : TrendReport
      AISupportAgent.trend_reports.find(id) || raise Error::NotFound.new("trend report #{id} not found")
    end

    @[AC::Route::GET("/trends/:id/report", content_type: "text/markdown")]
    def trend_report_markdown(id : String) : String
      trend_report(id).markdown
    end

    private def validate_limit(limit : Int32) : Nil
      return if (1..500).includes?(limit)
      raise Error::UnprocessableEntity.new("limit must be between 1 and 500")
    end

    private def request_body : String
      body = request.body.try(&.gets_to_end) || ""
      body.blank? ? "{}" : body
    end

    struct TrendRequest
      include JSON::Serializable

      getter window_seconds : Int32?
    end
  end
end
