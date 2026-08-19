require "uuid"

abstract class Application < ActionController::Base
  Log = ::AISupportAgent::Log.for("controller")
  @request_id : String? = nil

  @[AC::Route::Filter(:before_action)]
  protected def configure_request_logging
    @request_id = request_id = request.headers["X-Request-ID"]? || UUID.random.to_s

    Log.context.set(
      client_ip: client_ip,
      request_id: request_id,
    )
    response.headers["X-Request-ID"] = request_id
  end

  class Error < Exception
    class NotFound < Error
    end

    class UnprocessableEntity < Error
    end
  end

  struct CommonError
    include JSON::Serializable

    getter error : String?

    def initialize(error)
      @error = error.message
    end
  end

  @[AC::Route::Exception(Error::NotFound, status_code: HTTP::Status::NOT_FOUND)]
  def resource_not_found(error) : CommonError
    Log.debug(exception: error) { error.message }
    CommonError.new(error)
  end

  @[AC::Route::Exception(Error::UnprocessableEntity, status_code: HTTP::Status::UNPROCESSABLE_ENTITY)]
  def unprocessable_entity(error) : CommonError
    CommonError.new(error)
  end

  @[AC::Route::Exception(AISupportAgent::IncidentClaimInProgress, status_code: HTTP::Status::CONFLICT)]
  def incident_claim_in_progress(error : AISupportAgent::IncidentClaimInProgress) : CommonError
    response.headers["Retry-After"] = error.retry_after_seconds.to_s
    CommonError.new(error)
  end

  @[AC::Route::Exception(AISupportAgent::IncidentClaimUnavailable, status_code: HTTP::Status::SERVICE_UNAVAILABLE)]
  def incident_claim_unavailable(error : AISupportAgent::IncidentClaimUnavailable) : CommonError
    response.headers["Retry-After"] = error.retry_after_seconds.to_s
    CommonError.new(error)
  end

  @[AC::Route::Exception(JSON::ParseException, status_code: HTTP::Status::BAD_REQUEST)]
  def invalid_json(error) : CommonError
    CommonError.new(error)
  end

  struct ParameterError
    include JSON::Serializable

    getter error : String
    getter parameter : String? = nil
    getter restriction : String? = nil

    def initialize(@error, @parameter = nil, @restriction = nil)
    end
  end

  @[AC::Route::Exception(AC::Route::Param::MissingError, status_code: HTTP::Status::UNPROCESSABLE_ENTITY)]
  @[AC::Route::Exception(AC::Route::Param::ValueError, status_code: HTTP::Status::BAD_REQUEST)]
  def invalid_param(error) : ParameterError
    ParameterError.new error: error.message || error.class.name, parameter: error.parameter, restriction: error.restriction
  end
end
