module AISupportAgent
  class Incidents < Application
    base "/api/ai-support/v1/incidents"

    @[AC::Route::GET("/")]
    def index : Array(IncidentReport)
      AISupportAgent.incidents.all
    end

    @[AC::Route::GET("/:id/report", content_type: "text/markdown")]
    def operator_report(id : String) : String
      report = AISupportAgent.incidents.find(id) || raise Error::NotFound.new("incident #{id} not found")
      report.to_markdown
    end

    @[AC::Route::GET("/:id/run")]
    def run(id : String) : AgentRun
      AISupportAgent.agent_runs.find(id) || raise Error::NotFound.new("agent run #{id} not found")
    end

    @[AC::Route::GET("/:id/deliveries")]
    def deliveries(id : String) : Array(ReportDeliveryRecord)
      AISupportAgent.incidents.find(id) || raise Error::NotFound.new("incident #{id} not found")
      AISupportAgent.deliveries.for_incident(id)
    end

    @[AC::Route::GET("/:id/verifications")]
    def verifications(id : String) : Array(VerificationRun)
      AISupportAgent.incidents.find(id) || raise Error::NotFound.new("incident #{id} not found")
      AISupportAgent.verification_runs.for_incident(id)
    end

    @[AC::Route::GET("/:id/escalations")]
    def escalations(id : String) : Array(EscalationRecord)
      AISupportAgent.incidents.find(id) || raise Error::NotFound.new("incident #{id} not found")
      AISupportAgent.escalations.for_incident(id)
    end

    @[AC::Route::GET("/:id/feedback")]
    def feedback(id : String, limit : Int32 = 100) : Array(IncidentFeedback)
      AISupportAgent.incidents.find(id) || raise Error::NotFound.new("incident #{id} not found")
      unless (1..500).includes?(limit)
        raise Error::UnprocessableEntity.new("limit must be between 1 and 500")
      end
      AISupportAgent.feedback.for_incident(id).last(limit)
    end

    @[AC::Route::POST("/:id/feedback", status_code: HTTP::Status::CREATED)]
    def create_feedback(id : String) : IncidentFeedback
      AISupportAgent.incidents.find(id) || raise Error::NotFound.new("incident #{id} not found")
      body = FeedbackBody.from_json(request_body)
      AISupportAgent.feedback.create(
        incident_id: id,
        rating: FeedbackRating.from_api(body.rating),
        submitted_by: body.submitted_by,
        comment: body.comment
      )
    rescue error : ArgumentError | IncidentFeedbackStore::Error
      raise Error::UnprocessableEntity.new(error.message)
    end

    @[AC::Route::POST("/:id/verifications", status_code: HTTP::Status::CREATED)]
    def create_verification(id : String) : VerificationRun
      report = AISupportAgent.incidents.find(id) || raise Error::NotFound.new("incident #{id} not found")
      AISupportAgent.verify(report)
    rescue error : VerificationEngine::Error
      response.status = HTTP::Status::UNPROCESSABLE_ENTITY
      raise Error::UnprocessableEntity.new(error.message)
    end

    @[AC::Route::GET("/:id/approval_requests")]
    def approval_requests(id : String) : Array(ApprovalRequest)
      AISupportAgent.incidents.find(id) || raise Error::NotFound.new("incident #{id} not found")
      AISupportAgent.approvals.for_incident(id)
    end

    @[AC::Route::POST("/:id/approval_requests", status_code: HTTP::Status::CREATED)]
    def create_approval_request(id : String) : ApprovalRequest
      report = AISupportAgent.incidents.find(id) || raise Error::NotFound.new("incident #{id} not found")
      body = ApprovalRequestBody.from_json(request_body)
      AISupportAgent.approvals.create(report, requested_by: body.requested_by, note: body.note)
    rescue error : ApprovalRequestStore::Error
      response.status = HTTP::Status::UNPROCESSABLE_ENTITY
      raise Error::UnprocessableEntity.new(error.message)
    end

    @[AC::Route::POST("/:id/approval_requests/:approval_id/approve")]
    def approve_request(id : String, approval_id : String) : ApprovalRequest
      AISupportAgent.incidents.find(id) || raise Error::NotFound.new("incident #{id} not found")
      body = ApprovalDecisionBody.from_json(request_body)
      AISupportAgent.approvals.approve(approval_id, id, decided_by: body.decided_by, note: body.note) || raise Error::NotFound.new("approval request #{approval_id} not found")
    end

    @[AC::Route::POST("/:id/approval_requests/:approval_id/reject")]
    def reject_request(id : String, approval_id : String) : ApprovalRequest
      AISupportAgent.incidents.find(id) || raise Error::NotFound.new("incident #{id} not found")
      body = ApprovalDecisionBody.from_json(request_body)
      AISupportAgent.approvals.reject(approval_id, id, decided_by: body.decided_by, note: body.note) || raise Error::NotFound.new("approval request #{approval_id} not found")
    end

    @[AC::Route::GET("/:id")]
    def show(id : String) : IncidentReport
      AISupportAgent.incidents.find(id) || raise Error::NotFound.new("incident #{id} not found")
    end

    private def request_body : String
      request.body.try(&.gets_to_end) || ""
    end

    struct ApprovalRequestBody
      include JSON::Serializable

      getter requested_by : String
      getter note : String?
    end

    struct ApprovalDecisionBody
      include JSON::Serializable

      getter decided_by : String
      getter note : String?
    end

    struct FeedbackBody
      include JSON::Serializable

      getter rating : String
      getter submitted_by : String
      getter comment : String?
    end
  end
end
