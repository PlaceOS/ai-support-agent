require "./helper"

module AISupportAgent
  def self.evidence_tool_context : PlaceOSContext
    PlaceOSContext.new(::PlaceOS::Client.new("http://place.test", x_api_key: "test-key"))
  end

  def self.evidence_tool_event(module_id : String? = nil, system_id : String? = nil) : IncidentEvent
    IncidentEvent.new(
      source: IncidentSource::Ticket,
      severity: IncidentSeverity::Warning,
      correlation_key: "ticket:TOOLS",
      payload: JSON.parse({ticket: {summary: "evidence tool fixture"}}.to_json),
      module_id: module_id,
      system_id: system_id
    )
  end

  def self.evidence_tool_data(result : DiagnosticToolResult) : JSON::Any
    result.evidence.first.data || raise "the tool returned no data"
  end

  describe "evidence tools" do
    it "compares the module's settings keys with the keys the driver declares" do
      WebMock.stub(:get, "http://place.test/api/engine/v2/modules/mod-1/settings")
        .to_return(body: [
          {parent_id: "zone-org", parent_type: "Zone", encryption_level: 0, keys: ["smtp_host"]},
          {parent_id: "mod-1", parent_type: "Module", encryption_level: 2, keys: ["username", "password"]},
        ].to_json)
      WebMock.stub(:get, "http://place.test/api/engine/v2/modules/mod-1").to_return(body: {id: "mod-1", driver_id: "driver-1"}.to_json)
      schema = {properties: {smtp_host: {type: "string"}, username: {type: "string"}, from_domain: {type: "string"}}, required: ["from_domain"]}
      WebMock.stub(:get, "http://place.test/api/engine/v2/drivers/driver-1").to_return(body: {id: "driver-1", json_schema: schema.to_json}.to_json)

      result = AISupportAgent.evidence_tool_context.execute("module_settings", AISupportAgent.evidence_tool_event(module_id: "mod-1"), 5)

      result.status.completed?.should be_true
      data = AISupportAgent.evidence_tool_data(result)
      data["effective_settings"].as_a.map(&.as_s).sort.should eq ["password", "smtp_host", "username"]
      data["missing_settings"].as_a.map(&.as_s).should eq ["from_domain"]
      data["missing_required_settings"].as_a.map(&.as_s).should eq ["from_domain"]
      data["levels"].as_a.size.should eq 2
    end

    it "reads the driver behind a module and whether it compiled" do
      WebMock.stub(:get, "http://place.test/api/engine/v2/modules/mod-1").to_return(body: {id: "mod-1", driver_id: "driver-1"}.to_json)
      WebMock.stub(:get, "http://place.test/api/engine/v2/drivers/driver-1")
        .to_return(body: {id: "driver-1", name: "Azure AD Sync", module_name: "AzureAD", commit: "abc1234", update_available: true}.to_json)
      WebMock.stub(:get, "http://place.test/api/engine/v2/drivers/driver-1/compiled").to_return(status: 404, body: {error: "Driver not compiled yet"}.to_json)

      result = AISupportAgent.evidence_tool_context.execute("driver_details", AISupportAgent.evidence_tool_event(module_id: "mod-1"), 5)

      result.status.completed?.should be_true
      data = AISupportAgent.evidence_tool_data(result)
      data["name"].as_s.should eq "Azure AD Sync"
      data["commit"].as_s.should eq "abc1234"
      data["compiled"].as_bool.should be_false
      data["compilation_output"].as_s.should contain "404"
    end

    it "lists the system's modules with their running and connected state" do
      WebMock.stub(:get, "http://place.test/api/engine/v2/modules/").with(query: {"control_system_id" => "sys-1", "limit" => "500"})
        .to_return(body: [
          {id: "mod-1", name: "Display", running: true, connected: false, ignore_connected: false, has_runtime_error: false},
          {id: "mod-2", name: "Bookings", custom_name: "Desk sync", running: false, connected: true, ignore_connected: true, has_runtime_error: true},
        ].to_json)

      result = AISupportAgent.evidence_tool_context.execute("system_modules", AISupportAgent.evidence_tool_event(system_id: "sys-1"), 5)

      result.status.completed?.should be_true
      summary = AISupportAgent.evidence_tool_data(result)["summary"]
      summary["total"].as_i.should eq 2
      summary["stopped"].as_i.should eq 1
      summary["disconnected"].as_i.should eq 1
      summary["runtime_errors"].as_i.should eq 1
    end

    it "flags a system that exists by id but is missing from search and zone listings" do
      WebMock.stub(:get, "http://place.test/api/engine/v2/systems/sys-1").to_return(body: {id: "sys-1", name: "Room 13.15", zones: ["zone-1"]}.to_json)
      WebMock.stub(:get, "http://place.test/api/engine/v2/systems/").with(query: {"q" => "Room 13.15", "limit" => "50"}).to_return(body: "[]")
      WebMock.stub(:get, "http://place.test/api/engine/v2/systems/").with(query: {"zone_id" => "zone-1", "limit" => "1000"}).to_return(body: [{id: "sys-other"}].to_json)

      result = AISupportAgent.evidence_tool_context.execute("search_consistency", AISupportAgent.evidence_tool_event(system_id: "sys-1"), 5)

      result.status.completed?.should be_true
      data = AISupportAgent.evidence_tool_data(result)
      data["found_by_search"].as_bool.should be_false
      data["found_by_zone"].as_bool.should be_false
      data["index_stale"].as_bool.should be_true
    end

    it "reads core node load and loaded module counts" do
      WebMock.stub(:get, "http://place.test/api/engine/v2/cluster/").with(query: {"include_status" => "true"})
        .to_return(body: [{id: "core-1", uri: "http://core-1:3000", load: {local: {cpu: 0.5}}, status: nil}].to_json)
      WebMock.stub(:get, "http://place.test/api/engine/v2/cluster/core-1")
        .to_return(body: [{driver: "drivers/display", local: {modules: ["mod-1", "mod-2"]}, edge: {"edge-1" => {modules: ["mod-3"]}}}].to_json)

      result = AISupportAgent.evidence_tool_context.execute("cluster_status", AISupportAgent.evidence_tool_event, 5)

      result.status.completed?.should be_true
      data = AISupportAgent.evidence_tool_data(result)
      data["node_count"].as_i.should eq 1
      data["total_modules_loaded"].as_i.should eq 3
      data["nodes"][0]["drivers_loaded"].as_i.should eq 1
    end

    it "reads the platform versions and tolerates a missing endpoint" do
      WebMock.stub(:get, "http://place.test/api/engine/v2/version").to_return(body: {service: "rest-api", version: "2.2509.1", commit: "abc"}.to_json)
      WebMock.stub(:get, "http://place.test/api/engine/v2/cluster/versions").to_return(body: [{service: "core", version: "2.2509.1"}].to_json)
      WebMock.stub(:get, "http://place.test/api/engine/v2/platform").to_return(status: 404, body: "")

      result = AISupportAgent.evidence_tool_context.execute("platform_version", AISupportAgent.evidence_tool_event, 5)

      result.status.completed?.should be_true
      data = AISupportAgent.evidence_tool_data(result)
      data["rest_api"]["version"].as_s.should eq "2.2509.1"
      data["core_nodes"][0]["service"].as_s.should eq "core"
      data["platform"]["error"].as_s.should contain "404"
    end

    it "skips module and system scoped tools without their context" do
      context = AISupportAgent.evidence_tool_context
      event = AISupportAgent.evidence_tool_event

      context.execute("module_settings", event, 5).status.skipped?.should be_true
      context.execute("driver_details", event, 5).status.skipped?.should be_true
      context.execute("system_modules", event, 5).status.skipped?.should be_true
      context.execute("search_consistency", event, 5).status.skipped?.should be_true
    end
  end
end
