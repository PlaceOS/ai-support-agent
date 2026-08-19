require "./helper"

module AISupportAgent
  describe "PlaceOS service integration" do
    it "authenticates with REST API and discovers Core" do
      place_uri = ENV["PLACE_URI"]
      token = ENV["PLACE_API_KEY"]
      WebMock.allow_net_connect = true

      unauthorized = HTTP::Client.get(
        "#{place_uri}/api/engine/v2/cluster/",
        HTTP::Headers{"X-API-Key" => "invalid.invalid"}
      )
      unauthorized.status_code.should eq 401

      headers = HTTP::Headers{"X-API-Key" => token}
      nodes = [] of JSON::Any
      20.times do
        response = HTTP::Client.get("#{place_uri}/api/engine/v2/cluster/", headers)
        response.success?.should be_true
        nodes = JSON.parse(response.body).as_a
        break unless nodes.empty?
        sleep 500.milliseconds
      end
      nodes.should_not be_empty

      context = PlaceOSContext.from_environment
      result = context.execute("core_loaded_processes", IncidentEvent.new(
        source: IncidentSource::ModuleState,
        severity: IncidentSeverity::Error,
        correlation_key: "compose-core-discovery",
        payload: JSON.parse({event: "module_runtime_error"}.to_json),
        module_id: "mod-not-loaded"
      ))

      result.status.completed?.should be_true
      result.evidence.map(&.source).should eq ["placeos_rest_api"]
    ensure
      WebMock.allow_net_connect = false
    end
  end
end
