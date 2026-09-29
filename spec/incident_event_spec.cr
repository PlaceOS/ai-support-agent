require "./helper"

module AISupportAgent
  describe IncidentEvent do
    it "stores blank and whitespace-only scope values as nil" do
      event = IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "blank-scope",
        payload: JSON.parse({message: "HTTP 401 Unauthorized"}.to_json),
        tenant_id: "",
        system_id: "   ",
        module_id: "",
        module_name: "\t\n"
      )

      event.tenant_id.should be_nil
      event.system_id.should be_nil
      event.module_id.should be_nil
      event.module_name.should be_nil
    end

    it "trims scope values" do
      event = IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "padded-scope",
        payload: JSON.parse({message: "HTTP 401 Unauthorized"}.to_json),
        system_id: " sys-123 ",
        module_id: "mod-456\n"
      )

      event.system_id.should eq "sys-123"
      event.module_id.should eq "mod-456"
    end

    it "applies the same rule to events read back from JSON" do
      stored = IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "stored-scope",
        payload: JSON.parse({message: "HTTP 401 Unauthorized"}.to_json),
        system_id: "sys-123",
        module_id: "mod-456"
      )
      json = JSON.parse(stored.to_json).as_h
      json["module_id"] = JSON::Any.new("")
      json["system_id"] = JSON::Any.new(" sys-123 ")

      event = IncidentEvent.from_json(json.to_json)

      event.module_id.should be_nil
      event.system_id.should eq "sys-123"
    end

    it "does not count a blank value as present context" do
      event = IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "blank-context",
        payload: JSON.parse({message: "HTTP 401 Unauthorized"}.to_json),
        system_id: "",
        module_id: " ",
        module_name: ""
      )

      %w(tenant_id system_id module_id module_name).each do |field|
        DiagnosticProcedure.context_present?(field, event).should be_false
      end
    end
  end
end
