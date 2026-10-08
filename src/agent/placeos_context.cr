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

    enum ModuleHealth
      Healthy
      Failing
      Missing
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

    def rest_available? : Bool
      configured? && !@client.nil?
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

    # Current health of one module, read from `GET /modules/:id`. A static context answers from its
    # maintenance targets: listed with a runtime error is Failing, listed without one is Healthy, unlisted is Missing.
    def module_health(module_id : String, io_timeout_seconds : Int32 = 10) : ModuleHealth
      if targets = @static_maintenance_targets
        target = targets.find(&.module_id.==(module_id))
        return ModuleHealth::Missing unless target
        return target.has_runtime_error? ? ModuleHealth::Failing : ModuleHealth::Healthy
      end
      if configuration_error = @configuration_error
        raise ToolError.new(configuration_error)
      end
      client = @client || raise ToolError.new("PlaceOS client is not configured")

      details = rest_json(client, "/api/engine/v2/modules/#{URI.encode_path_segment(module_id)}", io_timeout_seconds)
      failing = details.as_h["has_runtime_error"]?.try(&.as_bool?) || false
      failing ? ModuleHealth::Failing : ModuleHealth::Healthy
    rescue error : ToolError
      raise error unless error.status_code == 404
      ModuleHealth::Missing
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

    # A GET against the PlaceOS REST API, parsed. Raises `ToolError` when the API
    # is not configured or answers with an error status.
    def get_json(path : String, io_timeout_seconds : Int32 = 10) : JSON::Any
      if configuration_error = @configuration_error
        raise ToolError.new(configuration_error)
      end
      raise ToolError.new("PlaceOS REST API client is unavailable") unless client = @client
      rest_json(client, path, io_timeout_seconds)
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
                 when "module_settings"
                   module_settings_evidence(event, io_timeout_seconds)
                 when "driver_details"
                   driver_evidence(event, io_timeout_seconds)
                 when "system_modules"
                   system_modules_evidence(event, io_timeout_seconds)
                 when "search_consistency"
                   search_consistency_evidence(event, io_timeout_seconds)
                 when "cluster_status"
                   cluster_status_evidence(io_timeout_seconds)
                 when "platform_version"
                   platform_version_evidence(io_timeout_seconds)
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

    # Collated settings keys at every level above the module, against the keys
    # the driver's settings schema declares. A key the driver declares that no
    # level sets is a default added to the driver after the module was created.
    # Field names avoid the word "key" because `Redactor` blanks such fields.
    private def module_settings_evidence(event : IncidentEvent, io_timeout_seconds : Int32) : Array(Evidence)
      return [] of Evidence unless client = @client
      return [] of Evidence unless module_id = event.module_id.presence

      settings = rest_json(client, "/api/engine/v2/modules/#{URI.encode_path_segment(module_id)}/settings", io_timeout_seconds).as_a
      levels = settings.map do |setting|
        data = setting.as_h
        {
          parent_id:        data["parent_id"]?,
          parent_type:      data["parent_type"]?,
          encryption_level: data["encryption_level"]?,
          settings:         string_array(data["keys"]?),
        }
      end
      effective = levels.flat_map(&.[:settings]).uniq!

      details = rest_json(client, "/api/engine/v2/modules/#{URI.encode_path_segment(module_id)}", io_timeout_seconds).as_h
      driver_id = details["driver_id"]?.try(&.as_s?)
      declared = [] of String
      required = [] of String
      if driver_id
        driver = rest_json(client, "/api/engine/v2/drivers/#{URI.encode_path_segment(driver_id)}", io_timeout_seconds).as_h
        schema = settings_schema(driver["json_schema"]?)
        declared = schema.try(&.["properties"]?).try(&.as_h?).try(&.keys) || [] of String
        required = string_array(schema.try(&.["required"]?))
      end

      [
        Evidence.new(
          source: "placeos_rest_api",
          message: "Fetched collated module settings through PlaceOS::Client",
          data: Redactor.redact(JSON.parse({
            module_id:                 module_id,
            driver_id:                 driver_id,
            levels:                    levels,
            effective_settings:        effective,
            driver_settings:           declared,
            driver_required_settings:  required,
            missing_settings:          declared - effective,
            missing_required_settings: required - effective,
          }.to_json))
        ),
      ]
    end

    # The driver behind the module: identity, commit, update state and whether
    # the build service has a compiled binary for it.
    private def driver_evidence(event : IncidentEvent, io_timeout_seconds : Int32) : Array(Evidence)
      return [] of Evidence unless client = @client
      return [] of Evidence unless module_id = event.module_id.presence

      details = rest_json(client, "/api/engine/v2/modules/#{URI.encode_path_segment(module_id)}", io_timeout_seconds).as_h
      driver_id = details["driver_id"]?.try(&.as_s?) || raise ToolError.new("module #{module_id} has no driver id")
      driver = rest_json(client, "/api/engine/v2/drivers/#{URI.encode_path_segment(driver_id)}", io_timeout_seconds).as_h

      compiled = true
      compile_message = nil.as(String?)
      begin
        result = rest_json(client, "/api/engine/v2/drivers/#{URI.encode_path_segment(driver_id)}/compiled", io_timeout_seconds)
        compile_message = result.as_h?.try(&.["compilation_output"]?).try(&.as_s?).try(&.[0, 2000])
      rescue error : ToolError
        compiled = false
        compile_message = error.message
      end

      [
        Evidence.new(
          source: "placeos_rest_api",
          message: "Fetched driver details through PlaceOS::Client",
          data: Redactor.redact(JSON.parse({
            module_id:          module_id,
            driver_id:          driver_id,
            name:               driver["name"]?,
            module_name:        driver["module_name"]?,
            role:               driver["role"]?,
            commit:             driver["commit"]?,
            repository_id:      driver["repository_id"]?,
            file_name:          driver["file_name"]?,
            update_available:   driver["update_available"]?,
            update_info:        driver["update_info"]?,
            compiled:           compiled,
            compilation_output: compile_message || driver["compilation_output"]?.try(&.as_s?).try(&.[0, 2000]),
          }.to_json))
        ),
      ]
    end

    # Every module in the system with its running, connected and error flags.
    private def system_modules_evidence(event : IncidentEvent, io_timeout_seconds : Int32) : Array(Evidence)
      return [] of Evidence unless client = @client
      return [] of Evidence unless system_id = event.system_id.presence

      path = "/api/engine/v2/modules/?control_system_id=#{URI.encode_path_segment(system_id)}&limit=500"
      modules = rest_json(client, path, io_timeout_seconds).as_a.map do |mod|
        data = mod.as_h
        {
          id:                data["id"]?,
          name:              data["custom_name"]?.try(&.as_s?).presence || data["name"]?.try(&.as_s?),
          driver_id:         data["driver_id"]?,
          role:              data["role"]?,
          running:           data["running"]?,
          connected:         data["connected"]?,
          ignore_connected:  data["ignore_connected"]?,
          has_runtime_error: data["has_runtime_error"]?,
        }
      end
      summary = {
        total:          modules.size,
        stopped:        modules.count { |mod| mod[:running].try(&.as_bool?) == false },
        disconnected:   modules.count { |mod| mod[:connected].try(&.as_bool?) == false && mod[:ignore_connected].try(&.as_bool?) != true },
        runtime_errors: modules.count { |mod| mod[:has_runtime_error].try(&.as_bool?) == true },
      }

      [
        Evidence.new(
          source: "placeos_rest_api",
          message: "Fetched the system's modules through PlaceOS::Client",
          data: Redactor.redact(JSON.parse({system_id: system_id, summary: summary, modules: modules}.to_json))
        ),
      ]
    end

    # Whether the system that exists by id is also returned by name search and
    # by its zone listing; a system found only by id has a stale search index.
    private def search_consistency_evidence(event : IncidentEvent, io_timeout_seconds : Int32) : Array(Evidence)
      return [] of Evidence unless client = @client
      return [] of Evidence unless system_id = event.system_id.presence

      system = rest_json(client, "/api/engine/v2/systems/#{URI.encode_path_segment(system_id)}", io_timeout_seconds).as_h
      name = system["name"]?.try(&.as_s?) || ""
      zones = string_array(system["zones"]?)

      by_search = rest_json(client, "/api/engine/v2/systems/?#{URI::Params.encode({"q" => name, "limit" => "50"})}", io_timeout_seconds).as_a
      found_by_search = by_search.any? { |item| item.as_h["id"]?.try(&.as_s?) == system_id }
      zone_checked = zones.first?
      found_by_zone = nil.as(Bool?)
      if zone_checked
        by_zone = rest_json(client, "/api/engine/v2/systems/?#{URI::Params.encode({"zone_id" => zone_checked, "limit" => "1000"})}", io_timeout_seconds).as_a
        found_by_zone = by_zone.any? { |item| item.as_h["id"]?.try(&.as_s?) == system_id }
      end

      [
        Evidence.new(
          source: "placeos_rest_api",
          message: "Checked the system against search and zone listings through PlaceOS::Client",
          data: Redactor.redact(JSON.parse({
            system_id:       system_id,
            name:            name,
            found_by_id:     true,
            found_by_search: found_by_search,
            zone_checked:    zone_checked,
            found_by_zone:   found_by_zone,
            index_stale:     !found_by_search || found_by_zone == false,
          }.to_json))
        ),
      ]
    end

    # Core nodes with load and the number of drivers and modules each has loaded.
    private def cluster_status_evidence(io_timeout_seconds : Int32) : Array(Evidence)
      return [] of Evidence unless client = @client

      nodes = rest_json(client, "/api/engine/v2/cluster/?include_status=true", io_timeout_seconds).as_a.map do |node|
        data = node.as_h
        node_id = data["id"]?.try(&.as_s?)
        drivers = [] of JSON::Any
        if node_id
          drivers = rest_json(client, "/api/engine/v2/cluster/#{URI.encode_path_segment(node_id)}", io_timeout_seconds).as_a
        end
        modules_loaded = drivers.sum do |driver|
          groups = [driver.as_h["local"]?] + (driver.as_h["edge"]?.try(&.as_h?).try(&.values) || [] of JSON::Any)
          groups.sum { |group| group.try(&.as_h?).try(&.["modules"]?).try(&.as_a?).try(&.size) || 0 }
        end
        {id: node_id, uri: data["uri"]?, load: data["load"]?, status: data["status"]?, drivers_loaded: drivers.size, modules_loaded: modules_loaded}
      end

      [
        Evidence.new(
          source: "placeos_rest_api",
          message: "Fetched core cluster status through PlaceOS::Client",
          data: Redactor.redact(JSON.parse({
            node_count:           nodes.size,
            total_modules_loaded: nodes.sum(&.[:modules_loaded]),
            nodes:                nodes,
          }.to_json))
        ),
      ]
    end

    # The running versions of the REST API, the core nodes and the platform release.
    private def platform_version_evidence(io_timeout_seconds : Int32) : Array(Evidence)
      return [] of Evidence unless client = @client

      api = rest_json(client, "/api/engine/v2/version", io_timeout_seconds)
      cores = begin
        rest_json(client, "/api/engine/v2/cluster/versions", io_timeout_seconds)
      rescue error : ToolError
        JSON.parse({error: error.message}.to_json)
      end
      platform = begin
        rest_json(client, "/api/engine/v2/platform", io_timeout_seconds)
      rescue error : ToolError
        JSON.parse({error: error.message}.to_json)
      end

      [
        Evidence.new(
          source: "placeos_rest_api",
          message: "Fetched platform versions through PlaceOS::Client",
          data: Redactor.redact(JSON.parse({rest_api: api, core_nodes: cores, platform: platform}.to_json))
        ),
      ]
    end

    private def settings_schema(value : JSON::Any?) : JSON::Any?
      return unless value
      case raw = value.raw
      when String then JSON.parse(raw) rescue nil
      when Hash   then value
      end
    end

    private def string_array(value : JSON::Any?) : Array(String)
      value.try(&.as_a?).try(&.compact_map(&.as_s?)) || [] of String
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
