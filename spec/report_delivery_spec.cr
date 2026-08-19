require "file_utils"
require "./helper"

module AISupportAgent
  struct SmtpCaptureAddress
    include JSON::Serializable

    @[JSON::Field(key: "Address")]
    getter address : String
  end

  struct SmtpCaptureMessageSummary
    include JSON::Serializable

    @[JSON::Field(key: "ID")]
    getter id : String

    @[JSON::Field(key: "From")]
    getter from : SmtpCaptureAddress

    @[JSON::Field(key: "To")]
    getter to : Array(SmtpCaptureAddress)

    @[JSON::Field(key: "Subject")]
    getter subject : String
  end

  struct SmtpCaptureMessageList
    include JSON::Serializable

    getter messages : Array(SmtpCaptureMessageSummary)
  end

  struct SmtpCaptureMessageBody
    include JSON::Serializable

    @[JSON::Field(key: "Text")]
    getter text : String
  end

  class RecordingReportEmailSender < ReportEmailSender
    getter emails = [] of ReportEmail

    def send(email : ReportEmail) : Nil
      @emails << email
    end
  end

  class FailingReportEmailSender < ReportEmailSender
    def send(email : ReportEmail) : Nil
      raise "SMTP offline"
    end
  end

  class ReportDeliveryRepository < PostgresIncidentRepository
    def initialize(@records : Array(ReportDeliveryRecord))
    end

    def deliveries_for_incident(incident_id : String) : Array(ReportDeliveryRecord)
      @records.select { |record| record.incident_id == incident_id }
    end

    def all_deliveries : Array(ReportDeliveryRecord)
      @records
    end
  end

  class FailingReportDeliveryRepository < PostgresIncidentRepository
    def save_delivery(record : ReportDeliveryRecord) : ReportDeliveryRecord
      raise "database offline"
    end

    def deliveries_for_incident(incident_id : String) : Array(ReportDeliveryRecord)
      [] of ReportDeliveryRecord
    end

    def all_deliveries : Array(ReportDeliveryRecord)
      [] of ReportDeliveryRecord
    end
  end

  describe ReportDelivery do
    it "records a skipped delivery when no channel is configured" do
      report = AISupportAgent.ingest(IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "delivery:disabled",
        payload: JSON.parse({message: "runtime error"}.to_json),
        module_id: "mod-delivery"
      ))

      deliveries = AISupportAgent.deliveries.for_incident(report.incident_id)
      deliveries.size.should eq 1
      deliveries.first.status.skipped?.should be_true
      deliveries.first.destination.should eq "disabled"
    end

    it "posts generated reports to a configured generic webhook" do
      WebMock.stub(:post, "https://hooks.example.test/reports")
        .with(headers: {"Content-Type" => "application/json"})
        .to_return(status: 202, body: "accepted")

      AISupportAgent.delivery.configure(ReportDeliveryConfig.new(
        generic_webhook_url: URI.parse("https://hooks.example.test/reports")
      ))

      report = AISupportAgent.ingest(IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "delivery:webhook",
        payload: JSON.parse({message: "x509 certificate expired"}.to_json),
        module_id: "mod-delivery"
      ))

      deliveries = AISupportAgent.deliveries.for_incident(report.incident_id)
      deliveries.size.should eq 1
      delivery = deliveries.first
      delivery.status.delivered?.should be_true
      delivery.destination.should eq "generic_webhook"
      delivery.response_status.should eq 202
      delivery.error.should be_nil
    end

    it "records failed generic webhook delivery without failing ingestion" do
      WebMock.stub(:post, "https://hooks.example.test/reports")
        .to_return(status: 500, body: "boom")

      AISupportAgent.delivery.configure(ReportDeliveryConfig.new(
        generic_webhook_url: URI.parse("https://hooks.example.test/reports")
      ))

      report = AISupportAgent.ingest(IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "delivery:failed",
        payload: JSON.parse({message: "runtime error"}.to_json),
        module_id: "mod-delivery"
      ))

      report.incident_id.should start_with "aisup-"
      deliveries = AISupportAgent.deliveries.for_incident(report.incident_id)
      deliveries.size.should eq 1
      delivery = deliveries.first
      delivery.status.failed?.should be_true
      delivery.response_status.should eq 500
      if error = delivery.error
        error.should contain "HTTP 500"
      else
        fail "expected delivery error"
      end
    end

    it "does not deliver duplicate correlated signals" do
      WebMock.stub(:post, "https://hooks.example.test/reports")
        .to_return(status: 202, body: "accepted")

      AISupportAgent.delivery.configure(ReportDeliveryConfig.new(
        generic_webhook_url: URI.parse("https://hooks.example.test/reports")
      ))

      event = IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "delivery:duplicate",
        payload: JSON.parse({message: "runtime error"}.to_json),
        module_id: "mod-delivery"
      )

      report = AISupportAgent.ingest(event)
      AISupportAgent.ingest(event)

      AISupportAgent.deliveries.for_incident(report.incident_id).size.should eq 1
    end

    it "continues in memory when delivery persistence fails" do
      AISupportAgent.deliveries.persist_with(FailingReportDeliveryRepository.new)

      report = AISupportAgent.ingest(IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "delivery:persistence-fallback",
        payload: JSON.parse({message: "runtime error"}.to_json),
        module_id: "mod-delivery"
      ))

      deliveries = AISupportAgent.deliveries.for_incident(report.incident_id)
      deliveries.size.should eq 1
      deliveries.first.status.skipped?.should be_true
      AISupportAgent.deliveries.persistence_error.try(&.should contain "database offline")

      status = Root::Status.from_json(client.get("/api/ai-support/v1/status").body)
      status.persistence_enabled?.should be_true
      status.report_delivery_persistence_error.try(&.should contain "database offline")
    end

    it "loads persisted delivery records when memory is empty" do
      record = ReportDeliveryRecord.new(
        incident_id: "aisup-persisted",
        status: ReportDeliveryStatus::Delivered,
        destination: "generic_webhook",
        attempted_at: Time.utc,
        response_status: 202
      )
      AISupportAgent.deliveries.persist_with(ReportDeliveryRepository.new([record]))

      deliveries = AISupportAgent.deliveries.for_incident(record.incident_id)
      deliveries.should eq [record]
      AISupportAgent.deliveries.all.should eq [record]
    end

    it "discovers and rereads repository-style report templates at runtime" do
      directory = File.join(Dir.tempdir, "support-report-templates-#{UUID.random}")
      Dir.mkdir_p(directory)
      template_path = File.join(directory, "custom.yml")
      File.write(template_path, <<-YAML)
        schema_version: report-template.v1
        id: custom-report
        version: 1
        subject: "Incident {{incident_id}} is {{status}}"
        body: "{{summary}}\n\n{{report}}"
        YAML

      report = AISupportAgent.ingest(IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "delivery:template",
        payload: JSON.parse({message: "runtime error"}.to_json),
        module_id: "mod-delivery"
      ))
      catalog = ReportTemplateCatalog.new(directory)
      rendered = catalog.render("custom-report", report)
      rendered.subject.should eq "Incident #{report.incident_id} is #{report.status}"
      rendered.body.should contain report.summary
      rendered.body.should contain "# Incident Diagnostic Report"

      File.write(template_path, <<-YAML)
        schema_version: report-template.v1
        id: custom-report
        version: 2
        subject: "Updated {{severity}} report"
        body: "{{incident_id}}"
        YAML
      updated = catalog.render("custom-report", report)
      updated.template_version.should eq 2
      updated.subject.should eq "Updated #{report.severity} report"
    ensure
      FileUtils.rm_rf(directory) if directory
    end

    it "delivers rendered reports by email" do
      sender = RecordingReportEmailSender.new
      AISupportAgent.delivery.configure(
        ReportDeliveryConfig.new(email_recipients: ["support@example.test"]),
        sender
      )

      report = AISupportAgent.ingest(IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "delivery:email",
        payload: JSON.parse({message: "runtime error"}.to_json),
        module_id: "mod-delivery"
      ))

      sender.emails.size.should eq 1
      email = sender.emails.first
      email.recipients.should eq ["support@example.test"]
      email.subject.should contain report.incident_id
      email.body.should contain "# Incident Diagnostic Report"

      delivery = AISupportAgent.deliveries.for_incident(report.incident_id).first
      delivery.status.delivered?.should be_true
      delivery.destination.should eq "email"
    end

    it "sends rendered reports through the configured SMTP server" do
      capture_api_url = "http://mailpit:8025"
      WebMock.allow_net_connect = true

      AISupportAgent.delivery.configure(ReportDeliveryConfig.from_environment)

      report = AISupportAgent.ingest(IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "delivery:smtp",
        payload: JSON.parse({message: "runtime error"}.to_json),
        module_id: "mod-smtp"
      ))

      messages_json = HTTP::Client.exec("GET", "#{capture_api_url}/api/v1/messages") do |response|
        response.success?.should be_true
        response.consume_body_io
        response.body
      end
      messages = SmtpCaptureMessageList.from_json(messages_json).messages
      message = messages.find! { |candidate| candidate.subject.includes?(report.incident_id) }
      message.from.address.should eq "support-agent@example.test"
      message.to.map(&.address).should eq ["operator@example.test"]
      message.subject.should contain report.incident_id

      body_json = HTTP::Client.exec("GET", "#{capture_api_url}/api/v1/message/#{message.id}") do |response|
        response.success?.should be_true
        response.consume_body_io
        response.body
      end
      body = SmtpCaptureMessageBody.from_json(body_json)
      body.text.should contain "# Incident Diagnostic Report"
      body.text.should contain report.summary

      delivery = AISupportAgent.deliveries.for_incident(report.incident_id).first
      delivery.status.delivered?.should be_true
      delivery.destination.should eq "email"
      delivery.error.should be_nil
    ensure
      WebMock.allow_net_connect = false
    end

    it "attempts every configured channel independently" do
      WebMock.stub(:post, "https://hooks.example.test/reports")
        .to_return(status: 202, body: "accepted")
      AISupportAgent.delivery.configure(
        ReportDeliveryConfig.new(
          generic_webhook_url: URI.parse("https://hooks.example.test/reports"),
          email_recipients: ["support@example.test"]
        ),
        FailingReportEmailSender.new
      )

      report = AISupportAgent.ingest(IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "delivery:fan-out",
        payload: JSON.parse({message: "runtime error"}.to_json),
        module_id: "mod-delivery"
      ))

      deliveries = AISupportAgent.deliveries.for_incident(report.incident_id)
      deliveries.size.should eq 2
      deliveries.find!(&.destination.==("generic_webhook")).status.delivered?.should be_true
      failed = deliveries.find!(&.destination.==("email"))
      failed.status.failed?.should be_true
      failed.error.try(&.should contain "SMTP offline")
    end
  end
end
