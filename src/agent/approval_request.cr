require "uuid"

module AISupportAgent
  enum ApprovalRequestStatus
    Pending
    Approved
    Rejected
  end

  struct ApprovalRequest
    include JSON::Serializable

    getter id : String
    getter incident_id : String
    getter status : ApprovalRequestStatus
    getter requested_by : String
    getter request_note : String?
    getter decided_by : String?
    getter decision_note : String?
    getter proposal : RemediationProposal
    getter execution_mode : String
    getter created_at : Time
    getter decided_at : Time?
    getter executed_at : Time?

    def initialize(
      @id : String,
      @incident_id : String,
      @status : ApprovalRequestStatus,
      @requested_by : String,
      @request_note : String?,
      @decided_by : String?,
      @decision_note : String?,
      @proposal : RemediationProposal,
      @execution_mode : String,
      @created_at : Time,
      @decided_at : Time? = nil,
      @executed_at : Time? = nil,
    )
    end

    def approve(decided_by : String, note : String? = nil, at : Time = Time.utc) : ApprovalRequest
      with_decision(ApprovalRequestStatus::Approved, decided_by, note, at)
    end

    def reject(decided_by : String, note : String? = nil, at : Time = Time.utc) : ApprovalRequest
      with_decision(ApprovalRequestStatus::Rejected, decided_by, note, at)
    end

    private def with_decision(status : ApprovalRequestStatus, decided_by : String, note : String?, at : Time) : ApprovalRequest
      ApprovalRequest.new(
        id: id,
        incident_id: incident_id,
        status: status,
        requested_by: requested_by,
        request_note: request_note,
        decided_by: decided_by,
        decision_note: note,
        proposal: proposal,
        execution_mode: execution_mode,
        created_at: created_at,
        decided_at: at,
        executed_at: nil
      )
    end
  end

  class ApprovalRequestStore
    class Error < Exception
    end

    @requests = {} of String => ApprovalRequest
    @incident_index = {} of String => Array(String)
    @repository : PostgresIncidentRepository?
    @persistence_error : String?
    @lock = Mutex.new

    def persist_with(@repository : PostgresIncidentRepository) : Nil
    end

    def disable_persistence : Nil
      @repository = nil
      @persistence_error = nil
    end

    def persistence_enabled? : Bool
      !!@repository
    end

    def persistence_error : String?
      @persistence_error
    end

    def create(report : IncidentReport, requested_by : String, note : String? = nil) : ApprovalRequest
      proposal = report.remediation_proposal || raise Error.new("incident #{report.incident_id} has no remediation proposal")
      request = ApprovalRequest.new(
        id: "appr-#{UUID.random}",
        incident_id: report.incident_id,
        status: ApprovalRequestStatus::Pending,
        requested_by: requested_by,
        request_note: note,
        decided_by: nil,
        decision_note: nil,
        proposal: proposal,
        execution_mode: "approval_only",
        created_at: Time.utc
      )

      save(request)
    end

    def approve(id : String, incident_id : String, decided_by : String, note : String? = nil) : ApprovalRequest?
      find(id).try do |request|
        save(request.approve(decided_by, note)) if request.incident_id == incident_id
      end
    end

    def reject(id : String, incident_id : String, decided_by : String, note : String? = nil) : ApprovalRequest?
      find(id).try do |request|
        save(request.reject(decided_by, note)) if request.incident_id == incident_id
      end
    end

    def find(id : String) : ApprovalRequest?
      @lock.synchronize { @requests[id]? } || persist(&.find_approval_request(id))
    end

    def for_incident(incident_id : String) : Array(ApprovalRequest)
      persist(&.approval_requests_for_incident(incident_id)) || @lock.synchronize do
        (@incident_index[incident_id]? || [] of String).compact_map { |id| @requests[id]? }
      end
    end

    def clear : Nil
      @lock.synchronize do
        @requests.clear
        @incident_index.clear
      end
    end

    private def save(request : ApprovalRequest) : ApprovalRequest
      persist(&.save_approval_request(request))

      @lock.synchronize do
        @requests[request.id] = request
        ids = @incident_index[request.incident_id] ||= [] of String
        ids << request.id unless ids.includes?(request.id)
      end
      request
    end

    private def persist(& : PostgresIncidentRepository -> T) : T? forall T
      return unless repository = @repository

      yield repository
    rescue error
      @persistence_error = "#{error.class}: #{error.message}"
      AISupportAgent::Log.warn(exception: error) { "approval-request persistence failed; continuing with in-memory store" }
      nil
    end
  end
end
