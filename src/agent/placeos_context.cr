module AISupportAgent
  struct ContextEvidence
    getter evidence : Array(Evidence)

    def initialize(@evidence = [] of Evidence)
    end
  end

  class PlaceOSContext
    class ToolError < Exception
      getter status_code : Int32?

      def initialize(message : String, @status_code : Int32? = nil)
        super(message)
      end
    end

    class TargetNotFound < ToolError
      getter module_id : String

      def initialize(@module_id : String)
        super("module #{module_id} was not found in PlaceOS", 404)
      end
    end

    def self.static(evidence : Array(Evidence), maintenance_targets = [] of MaintenanceTarget) : PlaceOSContext
      new(static_evidence: evidence, static_maintenance_targets: maintenance_targets)
    end

    def self.from_environment : PlaceOSContext
      unless ENV["PLACE_URI"]?.presence
        return new(configuration_error: "PLACE_URI is not configured; PlaceOS diagnostic enrichment is unavailable")
      end

      client = if api_key = ENV["PLACE_API_KEY"]?.presence
                 ::PlaceOS::Client.new(
                   ENV["PLACE_URI"],
                   x_api_key: api_key,
                   insecure: AISupportAgent.boolean_environment("PLACE_INSECURE")
                 )
               elsif user_auth_configured?
                 ::PlaceOS::Client.from_environment_user
               else
                 return new(configuration_error: "PlaceOS API credentials are incomplete; configure PLACE_API_KEY or PLACE_EMAIL, PLACE_PASSWORD, PLACE_AUTH_CLIENT_ID, and PLACE_AUTH_SECRET")
               end

      new(client)
    end

    private def self.user_auth_configured? : Bool
      ["PLACE_EMAIL", "PLACE_PASSWORD", "PLACE_AUTH_CLIENT_ID", "PLACE_AUTH_SECRET"].all? do |key|
        !!ENV[key]?.presence
      end
    end

    def initialize(
      @client : ::PlaceOS::Client? = nil,
      @static_evidence : Array(Evidence)? = nil,
      @static_maintenance_targets : Array(MaintenanceTarget)? = nil,
      @configuration_error : String? = nil,
    )
    end

    getter configuration_error : String?

    def configured? : Bool
      @configuration_error.nil?
    end

    def evidence_for(event : IncidentEvent) : ContextEvidence
      if evidence = @static_evidence
        return ContextEvidence.new(evidence)
      end

      evidence = [] of Evidence
      evidence.concat(execute("module_details", event).evidence)
      evidence.concat(execute("module_state", event).evidence)
      evidence.concat(execute("module_error_logs", event).evidence)
      evidence.concat(execute("system_details", event).evidence)
      evidence.concat(execute("core_loaded_processes", event).evidence)
      ContextEvidence.new(evidence)
    end

    def maintenance_targets(scope : MaintenanceScope, io_timeout_seconds : Int32 = 10) : Array(MaintenanceTarget)
      if targets = @static_maintenance_targets
        return filter_maintenance_targets(targets, scope)
      end
      if configuration_error = @configuration_error
        raise ToolError.new(configuration_error)
      end
      raise ToolError.new("PlaceOS REST API client is unavailable") unless client = @client

      targets = if scope.module_ids.empty?
                  maintenance_targets_for_scope(client, scope, io_timeout_seconds)
                else
                  scope.module_ids.map do |module_id|
                    details = rest_json(client, "/api/engine/v2/modules/#{URI.encode_path_segment(module_id)}", io_timeout_seconds)
                    maintenance_target(details)
                  end
                end
      filter_maintenance_targets(targets, scope)
    end

    def execute(target : String, event : IncidentEvent, io_timeout_seconds : Int32 = 10) : DiagnosticToolResult
      if evidence = @static_evidence
        return DiagnosticToolResult.new(target, evidence, "Used static PlaceOS evidence fixture")
      end
      if configuration_error = @configuration_error
        raise ToolError.new(configuration_error) unless target == "core_loaded_processes"
      end

      evidence = case target
                 when "module_details"
                   module_details(event, io_timeout_seconds)
                 when "module_state"
                   module_state(event, io_timeout_seconds)
                 when "module_error_logs", "debug_or_error_logs"
                   module_error_evidence(event, io_timeout_seconds)
                 when "system_details"
                   system_evidence(event, io_timeout_seconds)
                 when "core_loaded_processes"
                   core_evidence(event, io_timeout_seconds)
                 else
                   raise ToolError.new("unknown diagnostic tool #{target}")
                 end

      summary = evidence.empty? ? "No evidence collected for #{target}" : "Collected #{evidence.size} evidence item(s) for #{target}"
      DiagnosticToolResult.new(target, evidence, summary)
    rescue error
      evidence = if error.is_a?(TargetNotFound)
                   [Evidence.new(source: "diagnostic_target_missing", message: error.message.not_nil!)]
                 else
                   [Evidence.new(source: "diagnostic_tool_error", message: "#{target} failed: #{error.class}: #{error.message}")]
                 end
      DiagnosticToolResult.new(
        target,
        evidence,
        "Diagnostic tool #{target} failed",
        InvestigationStepStatus::Failed
      )
    end

    private def module_details(event : IncidentEvent, io_timeout_seconds : Int32) : Array(Evidence)
      return [] of Evidence unless client = @client
      return [] of Evidence unless module_id = event.module_id.presence

      details = rest_json(client, "/api/engine/v2/modules/#{URI.encode_path_segment(module_id)}", io_timeout_seconds)
      [
        Evidence.new(
          source: "placeos_rest_api",
          message: "Fetched module details through PlaceOS::Client",
          data: Redactor.redact(details)
        ),
      ]
    rescue error : ToolError
      raise TargetNotFound.new(event.module_id.not_nil!) if error.status_code == 404
      raise error
    end

    private def module_state(event : IncidentEvent, io_timeout_seconds : Int32) : Array(Evidence)
      return [] of Evidence unless client = @client
      return [] of Evidence unless module_id = event.module_id.presence

      state = rest_json(client, "/api/engine/v2/modules/#{URI.encode_path_segment(module_id)}/state", io_timeout_seconds)
      [
        Evidence.new(
          source: "placeos_rest_api",
          message: "Fetched module state through PlaceOS::Client",
          data: Redactor.redact(state)
        ),
      ]
    rescue error : ToolError
      raise TargetNotFound.new(event.module_id.not_nil!) if error.status_code == 404
      raise error
    end

    private def module_error_evidence(event : IncidentEvent, io_timeout_seconds : Int32) : Array(Evidence)
      return [] of Evidence unless client = @client
      return [] of Evidence unless module_id = event.module_id.presence

      logs = rest_json(client, "/api/engine/v2/modules/#{URI.encode_path_segment(module_id)}/error", io_timeout_seconds)
      [
        Evidence.new(
          source: "placeos_rest_api",
          message: "Fetched module runtime-error logs through PlaceOS::Client",
          data: Redactor.redact(JSON.parse({logs: logs}.to_json))
        ),
      ]
    end

    private def system_evidence(event : IncidentEvent, io_timeout_seconds : Int32) : Array(Evidence)
      return [] of Evidence unless client = @client
      return [] of Evidence unless system_id = event.system_id.presence

      system = rest_json(client, "/api/engine/v2/systems/#{URI.encode_path_segment(system_id)}", io_timeout_seconds)
      [
        Evidence.new(
          source: "placeos_rest_api",
          message: "Fetched system details through PlaceOS::Client",
          data: Redactor.redact(system)
        ),
      ]
    end

    private def core_evidence(event : IncidentEvent, io_timeout_seconds : Int32) : Array(Evidence)
      return [] of Evidence unless client = @client
      return [] of Evidence unless module_id = event.module_id.presence

      nodes = rest_json(client, "/api/engine/v2/cluster/", io_timeout_seconds).as_a
      matches = nodes.compact_map do |node|
        node_id = node.as_h["id"]?.try(&.as_s?)
        next unless node_id

        drivers = rest_json(
          client,
          "/api/engine/v2/cluster/#{URI.encode_path_segment(node_id)}",
          io_timeout_seconds
        ).as_a
        loaded = drivers.select { |driver| driver_contains_module?(driver, module_id) }
        next if loaded.empty?

        {core_id: node_id, drivers: loaded}
      end

      [
        Evidence.new(
          source: "placeos_rest_api",
          message: "Fetched loaded module process view through PlaceOS::Client",
          data: Redactor.redact(JSON.parse({module_id: module_id, core_nodes: matches}.to_json))
        ),
      ]
    end

    private def driver_contains_module?(driver : JSON::Any, module_id : String) : Bool
      data = driver.as_h
      return true if process_group_contains_module?(data["local"]?, module_id)

      data["edge"]?.try(&.as_h?).try do |edges|
        return true if edges.values.any? { |group| process_group_contains_module?(group, module_id) }
      end
      false
    end

    private def process_group_contains_module?(group : JSON::Any?, module_id : String) : Bool
      modules = group.try(&.as_h?).try(&.["modules"]?).try(&.as_a?)
      modules.try(&.any? { |id| id.as_s? == module_id }) || false
    end

    private def maintenance_targets_for_scope(
      client : ::PlaceOS::Client,
      scope : MaintenanceScope,
      io_timeout_seconds : Int32,
    ) : Array(MaintenanceTarget)
      if scope.system_ids.empty?
        modules = rest_json(client, "/api/engine/v2/modules/?limit=#{scope.limit}", io_timeout_seconds).as_a
        modules.map { |mod| maintenance_target(mod) }
      else
        scope.system_ids.flat_map do |system_id|
          path = "/api/engine/v2/modules/?control_system_id=#{URI.encode_path_segment(system_id)}&limit=#{scope.limit}"
          rest_json(client, path, io_timeout_seconds).as_a.map do |mod|
            maintenance_target(mod, system_id)
          end
        end
      end
    end

    private def maintenance_target(details : JSON::Any, system_id : String? = nil) : MaintenanceTarget
      data = details.as_h
      module_id = data["id"]?.try(&.as_s?) || raise ToolError.new("PlaceOS module response is missing id")
      name = data["custom_name"]?.try(&.as_s?) || data["name"]?.try(&.as_s?)
      MaintenanceTarget.new(
        module_id: module_id,
        system_id: system_id || data["control_system_id"]?.try(&.as_s?),
        module_name: name,
        module_index: data["index"]?.try(&.as_i?).try(&.to_i32),
        has_runtime_error: data["has_runtime_error"]?.try(&.as_bool?) || false
      )
    end

    private def filter_maintenance_targets(targets : Array(MaintenanceTarget), scope : MaintenanceScope) : Array(MaintenanceTarget)
      selected = targets
      unless scope.module_ids.empty?
        selected = selected.select { |target| scope.module_ids.includes?(target.module_id) }
      end
      unless scope.system_ids.empty?
        selected = selected.select { |target| target.system_id.try { |id| scope.system_ids.includes?(id) } || false }
      end
      if scope.filter == "runtime_errors"
        selected = selected.select(&.has_runtime_error?)
      end
      selected.uniq(&.module_id).first(scope.limit)
    end

    private def rest_json(client : ::PlaceOS::Client, path : String, io_timeout_seconds : Int32) : JSON::Any
      client.api_wrapper.connection do |http|
        request_timeout = io_timeout_seconds.seconds
        http.connect_timeout = request_timeout
        http.read_timeout = request_timeout
        http.write_timeout = request_timeout

        response = http.get(path)
        unless response.success?
          raise ToolError.new("PlaceOS REST API returned HTTP #{response.status_code} for #{path}", response.status_code)
        end
        JSON.parse(response.body)
      end
    end
  end
end
