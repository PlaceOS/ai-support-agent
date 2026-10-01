require "./helper"

module AISupportAgent
  describe WebhookIngest do
    it "normalizes Grafana payloads" do
      event = WebhookIngest.grafana({
        status:       "firing",
        groupKey:     "grafana:display-offline",
        commonLabels: {
          alertname:    "Display offline",
          severity:     "critical",
          tenant_id:    "tenant-1",
          system_id:    "sys-123",
          module_id:    "mod-456",
          module_name:  "Display",
          module_index: "2",
        },
      }.to_json)

      event.source.grafana?.should be_true
      event.severity.critical?.should be_true
      event.system_id.should eq "sys-123"
      event.module_id.should eq "mod-456"
      event.module_index.should eq 2
      event.correlation_key.should eq "grafana:display-offline"
    end

    it "normalizes generic payloads" do
      event = WebhookIngest.generic({
        source:          "webhook",
        severity:        "warning",
        tenant_id:       "tenant-1",
        system_id:       "sys-123",
        module_id:       "mod-456",
        module_name:     "Display",
        module_index:    1,
        correlation_key: "manual:mod-456",
        payload:         {message: "connection refused"},
      }.to_json)

      event.source.webhook?.should be_true
      event.severity.warning?.should be_true
      event.module_name.should eq "Display"
      event.payload["message"].as_s.should eq "connection refused"
    end

    it "treats blank scope values in generic payloads as missing" do
      event = WebhookIngest.generic({
        source:          "webhook",
        severity:        "error",
        tenant_id:       "",
        system_id:       " ",
        module_id:       "",
        module_name:     "",
        correlation_key: "",
        payload:         {message: "HTTP 401 Unauthorized"},
      }.to_json)

      event.tenant_id.should be_nil
      event.system_id.should be_nil
      event.module_id.should be_nil
      event.module_name.should be_nil
      UUID.parse?(event.correlation_key).should_not be_nil
    end

    it "treats blank Grafana labels as missing" do
      event = WebhookIngest.grafana({
        status:       "firing",
        groupKey:     "",
        commonLabels: {
          alertname:   "Display offline",
          system_id:   " ",
          module_id:   "",
          module_name: "",
        },
      }.to_json)

      event.system_id.should be_nil
      event.module_id.should be_nil
      event.module_name.should be_nil
      event.correlation_key.should eq "Display offline"
    end
  end
end
