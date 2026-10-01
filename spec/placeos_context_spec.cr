require "./helper"

module AISupportAgent
  def self.module_payload
    {
      id:               "mod-runtime",
      driver_id:        "driver-1",
      control_sytem_id: nil,
      ip:               "10.0.0.10",
      tls:              false,
      udp:              false,
      port:             23,
      makebreak:        false,
      uri:              nil,
      custom_name:      nil,
      name:             "Display",
      role:             1,
      connected:        false,
      running:          true,
      ignore_connected: false,
      ignore_startstop: false,
      created_at:       Time.utc.to_unix,
      updated_at:       Time.utc.to_unix,
    }
  end

  describe PlaceOSContext do
    it "adds PlaceOS context evidence to diagnostic reports" do
      event = IncidentEvent.new(
        source: IncidentSource::ModuleState,
        severity: IncidentSeverity::Error,
        correlation_key: "context-spec",
        payload: JSON.parse({message: "runtime error"}.to_json),
        module_id: "mod-context"
      )
      context = PlaceOSContext.static([
        Evidence.new(source: "placeos_rest_api", message: "Fetched module details through PlaceOS::Client"),
      ])
      report = DiagnosticEngine.new(context, AIReporter.disabled).report_for(Incident.new("aisup-context", event, Time.utc))

      report.evidence.map(&.source).should contain "placeos_rest_api"
    end

    it "fetches module runtime-error logs through the PlaceOS REST client" do
      WebMock.stub(:get, "http://place.test/api/engine/v2/modules/mod-runtime/error")
        .to_return(body: ["Runtime exception line"].to_json)

      WebMock.stub(:get, "http://place.test/api/engine/v2/modules/mod-runtime")
        .to_return(body: AISupportAgent.module_payload.to_json)

      WebMock.stub(:get, "http://place.test/api/engine/v2/modules/mod-runtime/state")
        .to_return(body: {connected: false}.to_json)

      client = ::PlaceOS::Client.new("http://place.test", x_api_key: "test-key")
      context = PlaceOSContext.new(client)
      event = IncidentEvent.new(
        source: IncidentSource::ModuleState,
        severity: IncidentSeverity::Error,
        correlation_key: "runtime-error-context",
        payload: JSON.parse({event: "module_runtime_error", has_runtime_error: true}.to_json),
        module_id: "mod-runtime"
      )

      evidence = context.evidence_for(event).evidence

      evidence.map(&.message).should contain "Fetched module runtime-error logs through PlaceOS::Client"
      evidence.compact_map(&.data).map(&.to_json).join("\n").should contain "Runtime exception line"
    end

    it "makes no request when the module and system ids are blank" do
      modules = WebMock.stub(:get, "http://place.test/api/engine/v2/modules/")
        .to_return(body: [AISupportAgent.module_payload].to_json)
      systems = WebMock.stub(:get, "http://place.test/api/engine/v2/systems/")
        .to_return(body: "[]")

      client = ::PlaceOS::Client.new("http://place.test", x_api_key: "test-key")
      context = PlaceOSContext.new(client)
      event = IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "blank-ids-context",
        payload: JSON.parse({message: "HTTP 401"}.to_json),
        system_id: " ",
        module_id: ""
      )

      %w(module_details module_state module_error_logs system_details).each do |tool|
        context.execute(tool, event, 5).evidence.should be_empty
      end

      modules.calls.should eq 0
      systems.calls.should eq 0
    end

    it "sends an id as a single path segment" do
      encoded = WebMock.stub(:get, "http://place.test/api/engine/v2/modules/mod-1%2F..%2F..%2Fusers")
        .to_return(status: 404, body: "")
      users = WebMock.stub(:get, "http://place.test/api/engine/v2/users")
        .to_return(body: "[]")
      raw = WebMock.stub(:get, "http://place.test/api/engine/v2/modules/mod-1/../../users")
        .to_return(body: "[]")

      client = ::PlaceOS::Client.new("http://place.test", x_api_key: "test-key")
      context = PlaceOSContext.new(client)
      event = IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "encoded-id-context",
        payload: JSON.parse({message: "HTTP 401"}.to_json),
        module_id: "mod-1/../../users"
      )

      result = context.execute("module_details", event, 5)

      result.status.failed?.should be_true
      encoded.calls.should eq 1
      users.calls.should eq 0
      raw.calls.should eq 0
    end

    it "marks failed PlaceOS lookups as failed evidence" do
      WebMock.stub(:get, "http://place.test/api/engine/v2/modules/mod-runtime")
        .to_return(status: 503, body: "unavailable")

      client = ::PlaceOS::Client.new("http://place.test", x_api_key: "test-key")
      context = PlaceOSContext.new(client)
      event = IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "failed-context",
        payload: JSON.parse({message: "HTTP 401"}.to_json),
        module_id: "mod-runtime"
      )

      result = context.execute("module_details", event, 5)

      result.status.failed?.should be_true
      result.evidence.map(&.source).should eq ["diagnostic_tool_error"]
    end

    it "does not increase diagnosis confidence from failed lookups" do
      WebMock.stub(:get, "http://place.test/api/engine/v2/modules/mod-runtime")
        .to_return(status: 503, body: "unavailable")

      client = ::PlaceOS::Client.new("http://place.test", x_api_key: "test-key")
      context = PlaceOSContext.new(client)
      event = IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "failed-confidence",
        payload: JSON.parse({message: "HTTP 401 Unauthorized"}.to_json),
        module_id: "mod-runtime"
      )

      report = DiagnosticEngine.new(context, AIReporter.disabled)
        .report_for(Incident.new("aisup-failed-confidence", event, Time.utc))

      report.confidence.should eq 0.4
      report.evidence.map(&.source).should contain "diagnostic_tool_error"
      report.decision.try(&.escalation_required?).should be_true
    end

    it "does not let AI override a failure-penalized confidence ceiling" do
      WebMock.stub(:get, "http://place.test/api/engine/v2/modules/mod-runtime")
        .to_return(status: 503, body: "unavailable")

      client = ::PlaceOS::Client.new("http://place.test", x_api_key: "test-key")
      context = PlaceOSContext.new(client)
      event = IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "failed-ai-confidence",
        payload: JSON.parse({message: "HTTP 401 Unauthorized"}.to_json),
        module_id: "mod-runtime"
      )
      reporter = AIReporter.fake(AgentAnalysis.new("Overconfident AI analysis", confidence: 0.9))

      report = DiagnosticEngine.new(context, reporter)
        .report_for(Incident.new("aisup-failed-ai-confidence", event, Time.utc))

      report.confidence.should eq 0.4
      report.decision.try(&.escalation_required?).should be_true
      report.remediation_proposal.should be_nil
    end

    it "reports missing PlaceOS client configuration as a failed tool state" do
      place_uri = ENV.delete("PLACE_URI")
      context = PlaceOSContext.from_environment
      event = IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "missing-placeos-context",
        payload: JSON.parse({message: "HTTP 401 Unauthorized"}.to_json),
        module_id: "mod-runtime"
      )

      result = context.execute("module_details", event, 5)

      context.configured?.should be_false
      context.configuration_error.try(&.should contain "PLACE_URI")
      result.status.failed?.should be_true
    ensure
      ENV["PLACE_URI"] = place_uri if place_uri
    end

    it "reports incomplete password authentication without terminating" do
      original = {
        "PLACE_API_KEY"        => ENV["PLACE_API_KEY"]?,
        "PLACE_URI"            => ENV["PLACE_URI"]?,
        "PLACE_EMAIL"          => ENV["PLACE_EMAIL"]?,
        "PLACE_PASSWORD"       => ENV["PLACE_PASSWORD"]?,
        "PLACE_AUTH_CLIENT_ID" => ENV["PLACE_AUTH_CLIENT_ID"]?,
        "PLACE_AUTH_SECRET"    => ENV["PLACE_AUTH_SECRET"]?,
      }
      ENV["PLACE_URI"] = "http://place.test"
      ENV["PLACE_EMAIL"] = "support@example.test"
      ENV["PLACE_PASSWORD"] = "secret"
      ENV.delete("PLACE_API_KEY")
      ENV.delete("PLACE_AUTH_CLIENT_ID")
      ENV.delete("PLACE_AUTH_SECRET")

      context = PlaceOSContext.from_environment

      context.configured?.should be_false
      context.configuration_error.try(&.should contain "PLACE_AUTH_CLIENT_ID")
    ensure
      original.try &.each do |key, value|
        if value
          ENV[key] = value
        else
          ENV.delete(key)
        end
      end
    end

    it "fetches requested error logs for non-runtime classifications" do
      WebMock.stub(:get, "http://place.test/api/engine/v2/modules/mod-runtime/error")
        .to_return(body: ["device response timeout"].to_json)

      client = ::PlaceOS::Client.new("http://place.test", x_api_key: "test-key")
      context = PlaceOSContext.new(client)
      event = IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "response-timeout-context",
        payload: JSON.parse({message: "response timeout"}.to_json),
        module_id: "mod-runtime"
      )

      result = context.execute("debug_or_error_logs", event, 5)

      result.status.completed?.should be_true
      result.evidence.compact_map(&.data).map(&.to_json).join("\n").should contain "device response timeout"
    end

    it "fetches loaded module processes through the authenticated REST API" do
      WebMock.stub(:get, "http://place.test/api/engine/v2/cluster/")
        .with(headers: {"X-API-Key" => "test-key"})
        .to_return(body: [{id: "core-1", uri: "http://core:3000"}].to_json)
      WebMock.stub(:get, "http://place.test/api/engine/v2/cluster/core-1")
        .with(headers: {"X-API-Key" => "test-key"})
        .to_return(body: [
          {
            driver: "drivers/display",
            local:  {modules: ["mod-runtime"]},
            edge:   {} of String => JSON::Any,
          },
        ].to_json)

      client = ::PlaceOS::Client.new("http://place.test", x_api_key: "test-key")
      context = PlaceOSContext.new(client)
      event = IncidentEvent.new(
        source: IncidentSource::ModuleState,
        severity: IncidentSeverity::Error,
        correlation_key: "core-process-context",
        payload: JSON.parse({event: "module_runtime_error"}.to_json),
        module_id: "mod-runtime"
      )

      result = context.execute("core_loaded_processes", event, 5)

      result.status.completed?.should be_true
      result.evidence.map(&.source).should eq ["placeos_rest_api"]
      data = (result.evidence.first.data || raise "missing loaded-process evidence data").to_json
      data.should contain "mod-runtime"
      data.should contain "core-1"
    end
  end
end
