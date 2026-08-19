require "placeos-resource"
require "placeos-models"

module AISupportAgent
  class ModuleRuntimeErrorResource < ::PlaceOS::Resource(::PlaceOS::Model::Module)
    def process_resource(action : Action, resource : ::PlaceOS::Model::Module) : Result
      case action
      when .created?
        ingest_runtime_error(resource)
      when .updated?
        if resource.has_runtime_error && (resource.has_runtime_error_changed? || resource.error_timestamp_changed?)
          ingest_runtime_error(resource)
        else
          Result::Skipped
        end
      else
        Result::Skipped
      end
    end

    private def ingest_runtime_error(resource : ::PlaceOS::Model::Module) : Result
      return Result::Skipped unless resource.has_runtime_error

      event = module_event(resource)
      AISupportAgent.ingest(event)
      Result::Success
    end

    private def module_event(mod : ::PlaceOS::Model::Module) : IncidentEvent
      payload = {
        event:             "module_runtime_error",
        module_id:         mod.id,
        module_name:       mod.custom_name || mod.name,
        has_runtime_error: mod.has_runtime_error,
        error_timestamp:   mod.error_timestamp.try(&.to_rfc3339),
        running:           mod.running,
        connected:         mod.connected,
      }

      IncidentEvent.new(
        source: IncidentSource::ModuleState,
        severity: IncidentSeverity::Error,
        system_id: mod.control_system_id,
        module_id: mod.id,
        module_name: mod.custom_name || mod.name,
        correlation_key: "module-runtime-error:#{mod.id}:#{mod.error_timestamp.try(&.to_unix) || "unknown"}",
        payload: JSON.parse(payload.to_json)
      )
    end
  end
end
