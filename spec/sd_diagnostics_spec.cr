require "./helper"

module AISupportAgent
  # the report the catalogue produces for a ticket that reads `text`, with every tool answering from a fixture
  def self.sd_report(text : String, module_id : String? = "mod-1", system_id : String? = "sys-1") : IncidentReport
    event = IncidentEvent.new(
      source: IncidentSource::Ticket,
      severity: IncidentSeverity::Warning,
      correlation_key: "ticket:SD-SPEC",
      payload: JSON.parse({ticket: {summary: text}}.to_json),
      module_id: module_id,
      system_id: system_id
    )
    context = PlaceOSContext.static([Evidence.new(source: "placeos_rest_api", message: "fixture evidence")])
    catalog = WorkflowCatalog.from_environment
    WorkflowRunner.new(catalog, DiagnosticEngine.new(context, AIReporter.disabled)).report_for(Incident.new("aisup-sd", event, Time.utc))
  end

  describe "service desk shaped diagnostics" do
    it "classifies a stalled sync module and keeps the device diagnostics for device text" do
      AISupportAgent.sd_report("Module Error Stopping Azure AD to PlaceOS User Sync. One of the modules was throwing an error and stopping the process responsible for syncing users from Azure to PlaceOS.").classification.value.should eq "sync_stalled"
      AISupportAgent.sd_report("HTTP 401 Unauthorized from the display").classification.http_auth?.should be_true
    end

    it "classifies a missing driver setting ahead of a generic runtime error and proposes adding it" do
      report = AISupportAgent.sd_report("AAD sync module throwing a runtime error: undefined method from_domain for Nil")

      report.classification.value.should eq "missing_setting"
      report.remediation_proposal.should_not be_nil
      report.investigation.map(&.name).should contain "remediation:add-missing-setting"
      report.investigation.map(&.name).should contain "tool:module_settings"
      report.investigation.map(&.name).should contain "tool:driver_details"
    end

    it "classifies a driver that will not compile" do
      report = AISupportAgent.sd_report("Unable to update the driver in PPE environment. The build service is returning a compile error for the commit.")

      report.classification.value.should eq "driver_compile_failure"
      report.investigation.map(&.name).should contain "tool:platform_version"
    end

    it "classifies a record missing from the listings and proposes a re-index" do
      report = AISupportAgent.sd_report("Newly Added Room (QV1-Room 13.15) Not Reflected in Systems API's response. We performed a re-index but it did not resolve the problem.")

      report.classification.value.should eq "search_index_stale"
      report.remediation_proposal.should_not be_nil
      report.investigation.map(&.name).should contain "remediation:reindex-search"
      report.investigation.map(&.name).should contain "tool:search_consistency"
    end

    it "classifies modules that did not load after a core restart and proposes a service restart" do
      report = AISupportAgent.sd_report("Outage this morning post overnight restarts: the desk booking sync module did not load after the core restart and NTT restarted cores to resolve it.", module_id: nil)

      report.classification.value.should eq "modules_not_loaded"
      report.remediation_proposal.should_not be_nil
      report.investigation.map(&.name).should contain "remediation:restart-core-service"
      report.investigation.map(&.name).should contain "tool:system_modules"
      report.investigation.map(&.name).should contain "tool:cluster_status"
    end

    it "escalates unhealthy pods to a person with the cluster snapshot" do
      report = AISupportAgent.sd_report("Core Pods CrashLoopBackOff Causing System Slowness", module_id: nil, system_id: nil)

      report.classification.value.should eq "platform_pods_unhealthy"
      report.status.escalated?.should be_true
      report.remediation_proposal.should be_nil
      report.investigation.map(&.name).should contain "tool:cluster_status"
    end

    it "classifies a request cut by an ingress timeout" do
      report = AISupportAgent.sd_report("Event API throwing timeout error when fetching data for the HL80A building", module_id: nil)

      report.classification.value.should eq "api_timeout"
      report.investigation.map(&.name).should contain "tool:platform_version"
    end
  end
end
