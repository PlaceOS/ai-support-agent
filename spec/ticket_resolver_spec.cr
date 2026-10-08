require "./helper"

module AISupportAgent
  def self.ticket_resolver_context : PlaceOSContext
    PlaceOSContext.new(::PlaceOS::Client.new("http://place.test", x_api_key: "test-key"))
  end

  describe TicketResolver do
    it "resolves a module by name when the search returns one match" do
      WebMock.stub(:get, "http://place.test/api/engine/v2/domains/").with(query: {"limit" => "50"})
        .to_return(body: [{id: "authority-1", domain: "myoffice.suncorp.com.au", name: "Suncorp"}].to_json)
      WebMock.stub(:get, "http://place.test/api/engine/v2/modules/").with(query: {"q" => "azure ad", "limit" => "10"})
        .to_return(body: [{id: "mod-aad", name: "AzureADUserSync", custom_name: "Azure AD Sync", control_system_id: "sys-org", driver_id: "driver-aad"}].to_json)
      extraction = TicketExtraction.new(category: "module", modules: ["azure ad"], hosts: ["myoffice.suncorp.com.au"])

      resolution = TicketResolver.new(AISupportAgent.ticket_resolver_context).resolve(extraction)

      resolution.tenant_id.should eq "authority-1"
      resolution.module_id.should eq "mod-aad"
      resolution.module_name.should eq "Azure AD Sync"
      resolution.system_id.should eq "sys-org"
      resolution.method.should eq "module_name"
      resolution.resolved?.should be_true
      resolution.candidates.map(&.kind).should eq ["authority", "module"]
    end

    it "records candidates instead of choosing between equally good systems" do
      WebMock.stub(:get, "http://place.test/api/engine/v2/domains/").with(query: {"limit" => "50"}).to_return(body: "[]")
      WebMock.stub(:get, "http://place.test/api/engine/v2/systems/").with(query: {"q" => "13.15", "limit" => "5"})
        .to_return(body: [{id: "sys-qv1", name: "QV1 - Room 13.15", zones: ["zone-qv1"]}, {id: "sys-hl", name: "HL - Room 13.15", zones: ["zone-hl"]}].to_json)
      extraction = TicketExtraction.new(systems: ["13.15"])

      resolution = TicketResolver.new(AISupportAgent.ticket_resolver_context).resolve(extraction)

      resolution.resolved?.should be_false
      resolution.ambiguous?.should be_true
      resolution.candidates.select(&.kind.==("system")).size.should eq 2
      resolution.notes.any?(&.starts_with?("ambiguous system")).should be_true
    end

    it "prefers the system inside a zone named in the ticket" do
      WebMock.stub(:get, "http://place.test/api/engine/v2/domains/").with(query: {"limit" => "50"}).to_return(body: "[]")
      WebMock.stub(:get, "http://place.test/api/engine/v2/zones/").with(query: {"q" => "QV1", "limit" => "5"})
        .to_return(body: [{id: "zone-qv1", name: "QV1"}].to_json)
      WebMock.stub(:get, "http://place.test/api/engine/v2/systems/").with(query: {"q" => "13.15", "limit" => "5"})
        .to_return(body: [{id: "sys-qv1", name: "QV1 - Room 13.15", zones: ["zone-qv1"]}, {id: "sys-hl", name: "HL - Room 13.15", zones: ["zone-hl"]}].to_json)
      extraction = TicketExtraction.new(systems: ["13.15"], locations: ["QV1"])

      resolution = TicketResolver.new(AISupportAgent.ticket_resolver_context).resolve(extraction)

      resolution.system_id.should eq "sys-qv1"
      resolution.method.should eq "system_name"
    end

    it "uses ids from the ticket and reads the module's system" do
      WebMock.stub(:get, "http://place.test/api/engine/v2/domains/").with(query: {"limit" => "50"}).to_return(body: "[]")
      WebMock.stub(:get, "http://place.test/api/engine/v2/modules/mod-direct")
        .to_return(body: {id: "mod-direct", name: "Display", control_system_id: "sys-direct"}.to_json)
      extraction = TicketExtraction.new(module_ids: ["mod-direct"])

      resolution = TicketResolver.new(AISupportAgent.ticket_resolver_context).resolve(extraction)

      resolution.module_id.should eq "mod-direct"
      resolution.module_name.should eq "Display"
      resolution.system_id.should eq "sys-direct"
      resolution.method.should eq "module_id"
    end

    it "notes a module id the API does not know" do
      WebMock.stub(:get, "http://place.test/api/engine/v2/domains/").with(query: {"limit" => "50"}).to_return(body: "[]")
      WebMock.stub(:get, "http://place.test/api/engine/v2/modules/mod-missing").to_return(status: 404, body: "")
      extraction = TicketExtraction.new(module_ids: ["mod-missing"])

      resolution = TicketResolver.new(AISupportAgent.ticket_resolver_context).resolve(extraction)

      resolution.module_id.should be_nil
      resolution.notes.any?(&.includes?("mod-missing")).should be_true
    end

    it "explains when the REST API is not configured" do
      context = PlaceOSContext.new(configuration_error: "PLACE_URI is not configured")
      extraction = TicketExtraction.new(module_ids: ["mod-from-ticket"])

      resolution = TicketResolver.new(context).resolve(extraction)

      resolution.module_id.should eq "mod-from-ticket"
      resolution.method.should eq "ticket_ids"
      resolution.notes.first.should contain "not configured"
    end
  end
end
