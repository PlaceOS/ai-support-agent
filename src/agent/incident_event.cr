module AISupportAgent
  enum IncidentSource
    Grafana
    Webhook
    ModuleState
    Scheduled
    Ticket
  end

  enum IncidentSeverity
    Info
    Warning
    Error
    Critical
  end

  struct IncidentEvent
    include JSON::Serializable

    getter source : IncidentSource
    getter severity : IncidentSeverity
    getter tenant_id : String?
    getter system_id : String?
    getter module_id : String?
    getter module_name : String?
    getter module_index : Int32?
    getter correlation_key : String
    getter payload : JSON::Any

    def initialize(
      @source : IncidentSource,
      @severity : IncidentSeverity,
      @correlation_key : String,
      @payload : JSON::Any,
      tenant_id : String? = nil,
      system_id : String? = nil,
      module_id : String? = nil,
      module_name : String? = nil,
      @module_index : Int32? = nil,
    )
      @tenant_id = IncidentEvent.scope_value(tenant_id)
      @system_id = IncidentEvent.scope_value(system_id)
      @module_id = IncidentEvent.scope_value(module_id)
      @module_name = IncidentEvent.scope_value(module_name)
    end

    # runs after JSON deserialisation, which does not go through `initialize`
    def after_initialize
      @tenant_id = IncidentEvent.scope_value(@tenant_id)
      @system_id = IncidentEvent.scope_value(@system_id)
      @module_id = IncidentEvent.scope_value(@module_id)
      @module_name = IncidentEvent.scope_value(@module_name)
    end

    # blank and whitespace-only values come back as nil, anything else trimmed
    def self.scope_value(value : String?) : String?
      value.try(&.strip.presence)
    end

    def resolution? : Bool
      status = payload["status"]?.try(&.as_s?)
      status ||= payload["state"]?.try(&.as_s?)
      status ||= payload["event"]?.try(&.as_s?)
      !!status.try { |value| value.downcase.in?("resolved", "ok", "closed", "clear", "cleared") }
    rescue
      false
    end
  end
end
