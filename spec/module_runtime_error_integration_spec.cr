require "./helper"

module AISupportAgent
  describe "module runtime-error pipeline" do
    it "generates and persists a diagnostic report from a module changefeed event" do
      WebMock.allow_net_connect = true
      AISupportAgent.delivery.configure(ReportDeliveryConfig.from_environment)

      driver = ::PlaceOS::Model::Generator.driver(
        role: ::PlaceOS::Model::Driver::Role::Service,
        module_name: "RuntimeErrorFixture"
      ).save!
      repository = driver.repository
      mod = ::PlaceOS::Model::Generator.module(driver: driver)
      mod.custom_name = "Runtime Error Fixture"
      mod.save!

      resource = ModuleRuntimeErrorResource.new
      resource.start

      error_timestamp = Time.utc
      PgORM::Database.connection do |database|
        database.exec(
          <<-SQL,
            UPDATE mod
            SET running = true,
                has_runtime_error = true,
                error_timestamp = $1
            WHERE id = $2
            SQL
          error_timestamp,
          mod.id
        )
      end

      correlation_key = "module-runtime-error:#{mod.id}:#{error_timestamp.to_unix}"
      report = wait_for_report(correlation_key)

      report.source.module_state?.should be_true
      report.module_id.should eq mod.id
      report.module_name.should eq mod.custom_name
      report.classification.runtime_error?.should be_true
      report.investigation_plan.try(&.playbook_id).should eq "module-runtime-error"
      report.investigation.map(&.name).should contain "tool:module_details"
      report.investigation.map(&.name).should contain "tool:core_loaded_processes"
      report.evidence.map(&.source).should contain "placeos_rest_api"
      report.evidence.any? do |evidence|
        evidence.message == "Fetched module details through PlaceOS::Client" &&
          evidence.data.try(&.["has_runtime_error"]?.try(&.as_bool?)) == true
      end.should be_true

      markdown = report.to_markdown
      markdown.should contain "# Incident Diagnostic Report"
      markdown.should contain "Runtime Error Fixture"
      markdown.should contain "module-runtime-error"
      markdown.should contain "report-only mode"

      AISupportAgent.incidents.clear
      AISupportAgent.agent_runs.clear
      persisted_report = AISupportAgent.incidents.find(report.incident_id)
      persisted_run = AISupportAgent.agent_runs.find(report.incident_id)
      persisted_report.should_not be_nil
      persisted_run.should_not be_nil
      persisted_report.try(&.classification.runtime_error?).should be_true
      persisted_report.try(&.to_markdown).try(&.should contain "Runtime Error Fixture")
      persisted_run.try(&.investigation_plan.try(&.playbook_id)).should eq "module-runtime-error"

      stored_artifact = ::PlaceOS::Model::AiIncidentReport
        .where(incident_id: report.incident_id)
        .order(created_at: :desc)
        .limit(1)
        .to_a
        .first?
      stored_artifact.should_not be_nil
      stored_markdown = stored_artifact.try(&.markdown).to_s
      stored_markdown.should contain "# Incident Diagnostic Report"
      stored_markdown.should contain "Runtime Error Fixture"
      stored_markdown.should contain "module-runtime-error"
      stored_markdown.should contain "report-only mode"

      delivery = wait_for_email_delivery(report.incident_id)
      delivery.status.delivered?.should be_true
      delivery.error.should be_nil

      email = wait_for_email(report.incident_id)
      email["From"]["Address"].as_s.should eq "support-agent@example.test"
      email["To"].as_a.map { |recipient| recipient["Address"].as_s }.should eq ["operator@example.test"]
      email["Subject"].as_s.should contain report.incident_id

      email_body = captured_email(email["ID"].as_s)["Text"].as_s
      email_body.should contain "# Incident Diagnostic Report"
      email_body.should contain "Runtime Error Fixture"
      email_body.should contain "module-runtime-error"

    ensure
      resource.try(&.stop)
      mod.try(&.delete)
      driver.try(&.delete)
      repository.try(&.delete)
      WebMock.allow_net_connect = false
    end
  end

  private def self.wait_for_report(correlation_key : String, timeout : Time::Span = 30.seconds) : IncidentReport
    deadline = Time.instant + timeout
    loop do
      if report = AISupportAgent.incidents.find_by_correlation_key(correlation_key)
        return report
      end
      raise "timed out waiting for incident report #{correlation_key}" if Time.instant >= deadline
      sleep 100.milliseconds
    end
  end

  private def self.wait_for_email(incident_id : String, timeout : Time::Span = 10.seconds) : JSON::Any
    deadline = Time.instant + timeout
    loop do
      body = HTTP::Client.exec("GET", "http://mailpit:8025/api/v1/messages") do |response|
        response.success?.should be_true
        response.consume_body_io
        response.body
      end
      messages = JSON.parse(body)["messages"].as_a
      if email = messages.find { |message| message["Subject"].as_s.includes?(incident_id) }
        return email
      end
      raise "timed out waiting for incident email #{incident_id}" if Time.instant >= deadline
      sleep 100.milliseconds
    end
  end

  private def self.captured_email(id : String) : JSON::Any
    body = HTTP::Client.exec("GET", "http://mailpit:8025/api/v1/message/#{id}") do |response|
      response.success?.should be_true
      response.consume_body_io
      response.body
    end
    JSON.parse(body)
  end

  private def self.wait_for_email_delivery(incident_id : String, timeout : Time::Span = 10.seconds) : ReportDeliveryRecord
    deadline = Time.instant + timeout
    loop do
      if delivery = AISupportAgent.deliveries.for_incident(incident_id).find(&.destination.==("email"))
        return delivery
      end
      raise "timed out waiting for incident email delivery #{incident_id}" if Time.instant >= deadline
      sleep 100.milliseconds
    end
  end
end
