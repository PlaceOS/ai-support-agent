require "./helper"

module AISupportAgent
  TICKET_OPENAI_BASE = "http://openai.test/v1"

  describe TicketExtractor do
    it "reads ids, hosts, integrations and an environment out of ticket text" do
      ticket = SupportTicket.new(
        reference: "SD-1",
        summary: "AAD Sync Module Error in PPE",
        description: "The AAD sync module (mod-KZFTybzS9G in sys-KD7-LDBmSS) is throwing an error.\nSee https://myoffice.suncorp.com.au/backoffice/#/modules/mod-KZFTybzS9G\nError: undefined method from_domain (runtime error)"
      )

      extraction = TicketExtractor.deterministic(ticket)

      extraction.module_ids.should eq ["mod-KZFTybzS9G"]
      extraction.system_ids.should eq ["sys-KD7-LDBmSS"]
      extraction.hosts.should eq ["myoffice.suncorp.com.au"]
      extraction.environment.should eq "ppe"
      extraction.modules.map(&.downcase).should contain "azure ad"
      extraction.modules.map(&.downcase).should contain "aad sync"
      extraction.category.should eq "module"
      extraction.errors.any?(&.includes?("runtime error")).should be_true
      extraction.urgency.should eq "medium"
      extraction.method.should eq "deterministic"
    end

    it "keeps room names, zone ids and the environment from a summary and description" do
      ticket = SupportTicket.new(
        reference: "SD-2",
        summary: "Newly Added Room(QV1-Room 13.15) Not Reflected in Systems API's response",
        description: "Request url: https://myoffice.suncorp.com.au/api/engine/v2/systems?zone_id=zone-Hq~FYkh7au&limit=5000 in prod",
        priority: "Very High"
      )

      extraction = TicketExtractor.deterministic(ticket)

      extraction.systems.should contain "QV1-Room 13.15"
      extraction.systems.should contain "13.15"
      extraction.zone_ids.should eq ["zone-Hq~FYkh7au"]
      extraction.environment.should eq "production"
      extraction.urgency.should eq "critical"
    end

    it "layers a model extraction over the deterministic one" do
      ticket = SupportTicket.new(reference: "SD-3", summary: "User sync stopped", description: "The Azure AD user sync has not run since Monday.")
      extractor = TicketExtractor.fake(TicketExtraction.new(
        summary: "The Azure AD user sync module has stopped running",
        category: "module",
        systems: ["Head Office"],
        modules: ["Azure AD user sync"],
        method: "ai"
      ))

      extraction = extractor.extract(ticket)

      extraction.method.should eq "deterministic+ai"
      extraction.summary.should eq "The Azure AD user sync module has stopped running"
      extraction.category.should eq "module"
      extraction.systems.should eq ["Head Office"]
      extraction.modules.map(&.downcase).should contain "azure ad"
      extraction.modules.should contain "Azure AD user sync"
    end

    it "keeps the deterministic extraction when the model reply is unusable" do
      WebMock.stub(:post, "#{TICKET_OPENAI_BASE}/chat/completions")
        .to_return(body: {choices: [{message: {role: "assistant", content: "not json"}}]}.to_json, headers: HTTP::Headers{"Content-Type" => "application/json"})
      ticket = SupportTicket.new(reference: "SD-4", summary: "Display offline in Boardroom 2", description: "mod-123456789 is not responding")
      extractor = TicketExtractor.new(::OpenAI::Client.new("spec-key", TICKET_OPENAI_BASE), "gpt-test")

      extraction = extractor.extract(ticket)

      extraction.method.should eq "deterministic"
      extraction.module_ids.should eq ["mod-123456789"]
      extraction.systems.should contain "2"
    end

    it "parses a model reply with the expected keys" do
      extraction = TicketExtractor.parse(<<-JSON)
        ```json
        {"summary": "Projector will not power on", "category": "device", "environment": "unknown",
         "systems": ["Boardroom 2"], "modules": ["Epson projector"], "locations": ["Level 3"],
         "errors": ["comms error"], "hosts": [], "urgency": "High", "evidence_requests": ["Which site?"]}
        ```
        JSON

      extraction.category.should eq "device"
      extraction.environment.should be_nil
      extraction.systems.should eq ["Boardroom 2"]
      extraction.modules.should eq ["Epson projector"]
      extraction.locations.should eq ["Level 3"]
      extraction.urgency.should eq "high"
      extraction.evidence_requests.should eq ["Which site?"]
    end
  end
end
