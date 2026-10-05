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

  class RecoveringReportEmailSender < ReportEmailSender
    getter attempts = 0
    getter emails = [] of ReportEmail

    def send(email : ReportEmail) : Nil
      @attempts += 1
      raise "SMTP offline" if @attempts == 1
      @emails << email
    end
  end

  class PrimaryFailingReportEmailSender < ReportEmailSender
    getter emails = [] of ReportEmail

    def send(email : ReportEmail) : Nil
      raise "primary SMTP offline" if email.recipients.includes?("primary@example.test")
      @emails << email
    end
  end

  private def self.delivery_report : IncidentReport
    AISupportAgent.ingest(IncidentEvent.new(
      source: IncidentSource::Webhook,
      severity: IncidentSeverity::Error,
      correlation_key: "delivery:#{UUID.random}",
      payload: JSON.parse({message: "runtime error"}.to_json),
      module_id: "mod-delivery"
    ))
  end

  private def self.await_delivery_count(store : ReportDeliveryStore, count : Int32) : Array(ReportDeliveryRecord)
    deadline = Time.instant + 1.second
    loop do
      records = store.all
      return records if records.size >= count
      fail "expected #{count} delivery records, got #{records.size}" if Time.instant >= deadline
      sleep 1.millisecond
    end
  end

  private def self.stays_at_delivery_count(store : ReportDeliveryStore, count : Int32) : Nil
    deadline = Time.instant + 20.milliseconds
    while Time.instant < deadline
      store.all.size.should eq count
      sleep 1.millisecond
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
        generic_webhook_url: URI.parse("https://hooks.example.test/reports"),
        max_attempts: 1
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
          email_recipients: ["support@example.test"],
          max_attempts: 1
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
    describe "retry policy" do
      {"greeting", "recipient"}.each do |failure_stage|
        it "retries an SMTP #{failure_stage} rejection instead of recording delivery" do
          server = TCPServer.new("127.0.0.1", 0)
          connections = 0
          spawn do
            2.times do
              socket = server.accept
              connections += 1
              rejecting = connections == 1
              socket.print(rejecting && failure_stage == "greeting" ? "421 unavailable\r\n" : "220 localhost ready\r\n")
              while line = socket.gets
                command = line.strip
                case command
                when .starts_with?("EHLO"), .starts_with?("HELO"), "RSET", .starts_with?("MAIL FROM")
                  socket.print "250 OK\r\n"
                when .starts_with?("RCPT TO")
                  socket.print(rejecting && failure_stage == "recipient" ? "450 try later\r\n" : "250 OK\r\n")
                when "DATA"
                  socket.print "354 send message\r\n"
                  while data = socket.gets
                    break if data.strip == "."
                  end
                  socket.print "250 queued\r\n"
                when "QUIT"
                  socket.print "221 bye\r\n"
                  break
                end
              end
              socket.close
            end
          rescue error : Socket::Error
            raise error unless server.closed?
          end
          store = ReportDeliveryStore.new
          smtp = SmtpSettings.new("127.0.0.1", server.local_address.port, "example.test", "support@example.test")
          delivery = ReportDelivery.new(store, ReportDeliveryConfig.new(
            email_recipients: ["operator@example.test"], smtp: smtp, max_attempts: 2, retry_base: 1.millisecond
          ))
          first = delivery.deliver(delivery_report).first
          first.status.failed?.should be_true
          records = await_delivery_count(store, 2)
          records.last.status.delivered?.should be_true
          connections.should eq 2
        ensure
          server.try(&.close)
        end
      end

      it "retries a 503 and returns only first-attempt records before the retry" do
        calls = 0
        WebMock.stub(:post, "https://hooks.example.test/reports").to_return do |_request|
          calls += 1
          HTTP::Client::Response.new(calls == 1 ? 503 : 200, body: "result")
        end
        store = ReportDeliveryStore.new
        store.persist_with(PostgresIncidentRepository.new)
        delivery = ReportDelivery.new(store, ReportDeliveryConfig.new(
          generic_webhook_url: URI.parse("https://hooks.example.test/reports"), retry_base: 5.milliseconds
        ))
        report = delivery_report

        returned = delivery.deliver(report)
        calls.should eq 1
        returned.size.should eq 1
        returned.first.status.failed?.should be_true
        returned.first.error.not_nil!.should start_with "attempt 1 of 3: "
        records = await_delivery_count(store, 3).reject(&.status.skipped?)
        records.map(&.destination).should eq ["generic_webhook", "generic_webhook"]
        records.last.status.delivered?.should be_true
        calls.should eq 2
        returned.size.should eq 1
        returned.first.status.failed?.should be_true
      end

      it "records three failures and gives up after exponential delays" do
        times = [] of Time::Instant
        WebMock.stub(:post, "https://hooks.example.test/reports").to_return do |_request|
          times << Time.instant
          HTTP::Client::Response.new(503, body: "offline")
        end
        store = ReportDeliveryStore.new
        delivery = ReportDelivery.new(store, ReportDeliveryConfig.new(
          generic_webhook_url: URI.parse("https://hooks.example.test/reports"), retry_base: 5.milliseconds
        ))
        delivery.deliver(delivery_report)
        records = await_delivery_count(store, 3)
        records.all?(&.status.failed?).should be_true
        records.last.error.not_nil!.should start_with "attempt 3 of 3, giving up: "
        (times[1] - times[0]).should be >= 4.milliseconds
        (times[2] - times[1]).should be >= 9.milliseconds
        stays_at_delivery_count(store, 3)
      end

      it "does not retry a 400" do
        WebMock.stub(:post, "https://hooks.example.test/reports").to_return(status: 400)
        store = ReportDeliveryStore.new
        delivery = ReportDelivery.new(store, ReportDeliveryConfig.new(
          generic_webhook_url: URI.parse("https://hooks.example.test/reports"), retry_base: 1.millisecond
        ))
        delivery.deliver(delivery_report).first.error.not_nil!.should start_with "attempt 1 of 3, not retryable: "
        stays_at_delivery_count(store, 1)
      end

      {408, 425, 429, 500, 599}.each do |status|
        it "retries HTTP #{status}" do
          calls = 0
          WebMock.stub(:post, "https://hooks.example.test/reports").to_return do |_request|
            calls += 1
            HTTP::Client::Response.new(calls == 1 ? status : 200)
          end
          store = ReportDeliveryStore.new
          delivery = ReportDelivery.new(store, ReportDeliveryConfig.new(
            generic_webhook_url: URI.parse("https://hooks.example.test/reports"), retry_base: 1.millisecond
          ))
          delivery.deliver(delivery_report)
          await_delivery_count(store, 2).last.status.delivered?.should be_true
        end
      end

      it "retries a connection exception" do
        calls = 0
        WebMock.stub(:post, "https://hooks.example.test/reports").to_return do |_request|
          calls += 1
          raise Socket::ConnectError.new("connection refused") if calls == 1
          HTTP::Client::Response.new(200)
        end
        store = ReportDeliveryStore.new
        delivery = ReportDelivery.new(store, ReportDeliveryConfig.new(
          generic_webhook_url: URI.parse("https://hooks.example.test/reports"), retry_base: 1.millisecond
        ))
        delivery.deliver(delivery_report)
        await_delivery_count(store, 2).last.status.delivered?.should be_true
      end

      it "makes just one attempt when max_attempts is one" do
        WebMock.stub(:post, "https://hooks.example.test/reports").to_return(status: 503)
        store = ReportDeliveryStore.new
        delivery = ReportDelivery.new(store, ReportDeliveryConfig.new(
          generic_webhook_url: URI.parse("https://hooks.example.test/reports"), max_attempts: 1, retry_base: 1.millisecond
        ))
        delivery.deliver(delivery_report).first.error.not_nil!.should start_with "attempt 1 of 1, giving up: "
        stays_at_delivery_count(store, 1)
      end

      it "retries email failures with the same rendered content" do
        sender = RecoveringReportEmailSender.new
        store = ReportDeliveryStore.new
        delivery = ReportDelivery.new(store, ReportDeliveryConfig.new(
          email_recipients: ["support@example.test"], retry_base: 1.millisecond
        ), email_sender: sender)
        report = delivery_report
        delivery.deliver(report).first.status.failed?.should be_true
        records = await_delivery_count(store, 2)
        records.map(&.destination).should eq ["email", "email"]
        records.last.status.delivered?.should be_true
        sender.attempts.should eq 2
        sender.emails.first.body.should contain report.summary
      end

      it "does not retry missing SMTP configuration or invalid webhook URLs" do
        store = ReportDeliveryStore.new
        delivery = ReportDelivery.new(store, ReportDeliveryConfig.new(
          email_recipients: ["support@example.test"], generic_webhook_url: URI.parse("ftp://hooks.example.test/reports"), retry_base: 1.millisecond
        ))
        returned = delivery.deliver(delivery_report)
        returned.size.should eq 2
        returned.all? { |record| record.error.not_nil!.starts_with?("attempt 1 of 3, not retryable: ") }.should be_true
        stays_at_delivery_count(store, 2)
      end

      it "does not retry rendering failures" do
        store = ReportDeliveryStore.new
        delivery = ReportDelivery.new(store, ReportDeliveryConfig.new(
          generic_webhook_url: URI.parse("https://hooks.example.test/reports"), template_id: "missing", retry_base: 1.millisecond
        ))
        returned = delivery.deliver(delivery_report)
        returned.first.error.not_nil!.should contain "report template not found"
        stays_at_delivery_count(store, 1)
      end

      it "runs at most one retry fiber for an incident and channel" do
        WebMock.stub(:post, "https://hooks.example.test/reports").to_return(status: 503)
        store = ReportDeliveryStore.new
        delivery = ReportDelivery.new(store, ReportDeliveryConfig.new(
          generic_webhook_url: URI.parse("https://hooks.example.test/reports"), retry_base: 5.milliseconds
        ))
        report = delivery_report
        delivery.deliver(report)
        delivery.deliver(report)
        await_delivery_count(store, 4)
        stays_at_delivery_count(store, 4)
      end

      it "bounds a stalled HTTP response and retries the timeout" do
        calls = 0
        WebMock.allow_net_connect = true
        server = HTTP::Server.new do |context|
          calls += 1
          sleep 50.milliseconds if calls == 1
          context.response.print "ok"
        end
        address = server.bind_tcp("127.0.0.1", 0)
        spawn server.listen
        store = ReportDeliveryStore.new
        delivery = ReportDelivery.new(store, ReportDeliveryConfig.new(
          generic_webhook_url: URI.parse("http://127.0.0.1:#{address.port}/reports"),
          timeout: 5.milliseconds, retry_base: 1.millisecond
        ))
        returned = delivery.deliver(delivery_report)
        returned.first.status.failed?.should be_true
        returned.first.error.not_nil!.should contain "Timeout"
        await_delivery_count(store, 2).last.status.delivered?.should be_true
      ensure
        server.try(&.close)
        WebMock.allow_net_connect = false
      end

      it "sets SMTP socket timeouts and clamps the attempt limit" do
        smtp = SmtpSettings.new("smtp.example.test", 25, "example.test", "support@example.test")
        config = smtp.client_config(4.seconds)
        config.dns_timeout.should eq 4.seconds
        config.connect_timeout.should eq 4.seconds
        config.read_timeout.should eq 4.seconds
        config.write_timeout.should eq 4.seconds
        ReportDeliveryConfig.new(max_attempts: 0).max_attempts.should eq 1
        ReportDeliveryConfig.new(max_attempts: 100).max_attempts.should eq 10
      end
    end
    describe "fallback channels" do
      it "delivers both fallbacks in the background after primary retries give up" do
        primary_payloads = [] of String
        fallback_payloads = [] of String
        WebMock.stub(:post, "https://hooks.example.test/reports").to_return do |request|
          primary_payloads << request.body.to_s
          HTTP::Client::Response.new(503)
        end
        WebMock.stub(:post, "https://fallback.example.test/reports").to_return do |request|
          fallback_payloads << request.body.to_s
          HTTP::Client::Response.new(200)
        end
        sender = RecordingReportEmailSender.new
        store = ReportDeliveryStore.new
        store.persist_with(PostgresIncidentRepository.new)
        delivery = ReportDelivery.new(store, ReportDeliveryConfig.new(
          generic_webhook_url: URI.parse("https://hooks.example.test/reports"),
          fallback_webhook_url: URI.parse("https://fallback.example.test/reports"),
          fallback_email_recipients: ["fallback@example.test"], max_attempts: 2, retry_base: 1.millisecond
        ), email_sender: sender)
        report = delivery_report
        returned = delivery.deliver(report)
        returned.size.should eq 1
        returned.first.status.failed?.should be_true
        fallback_payloads.should be_empty
        records = await_delivery_count(store, 5).reject(&.status.skipped?)
        records.map(&.destination).should eq ["generic_webhook", "generic_webhook", "fallback_generic_webhook", "fallback_email"]
        records.last(2).all?(&.status.delivered?).should be_true
        primary_payloads.size.should eq 2
        fallback_payloads.should eq [primary_payloads.first]
        payload = JSON.parse(fallback_payloads.first)
        sender.emails.first.body.should eq payload["markdown"].as_s
        sender.emails.first.subject.should eq payload["subject"].as_s
        store.for_incident(report.incident_id).reject(&.status.skipped?).map(&.destination).should eq records.map(&.destination)
      end

      it "does not use fallbacks when a primary recovers on retry" do
        calls = 0
        fallback_calls = 0
        WebMock.stub(:post, "https://hooks.example.test/reports").to_return do |_request|
          calls += 1
          HTTP::Client::Response.new(calls == 1 ? 503 : 200)
        end
        WebMock.stub(:post, "https://fallback.example.test/reports").to_return do |_request|
          fallback_calls += 1
          HTTP::Client::Response.new(200)
        end
        sender = RecordingReportEmailSender.new
        store = ReportDeliveryStore.new
        delivery = ReportDelivery.new(store, ReportDeliveryConfig.new(
          generic_webhook_url: URI.parse("https://hooks.example.test/reports"),
          fallback_webhook_url: URI.parse("https://fallback.example.test/reports"),
          fallback_email_recipients: ["fallback@example.test"], retry_base: 1.millisecond
        ), email_sender: sender)
        delivery.deliver(delivery_report)
        await_delivery_count(store, 2).last.status.delivered?.should be_true
        stays_at_delivery_count(store, 2)
        fallback_calls.should eq 0
        sender.emails.should be_empty
      end

      it "starts fallbacks only once when both primaries give up" do
        fallback_calls = 0
        WebMock.stub(:post, "https://hooks.example.test/reports").to_return(status: 400)
        WebMock.stub(:post, "https://fallback.example.test/reports").to_return do |_request|
          fallback_calls += 1
          HTTP::Client::Response.new(200)
        end
        sender = PrimaryFailingReportEmailSender.new
        store = ReportDeliveryStore.new
        delivery = ReportDelivery.new(store, ReportDeliveryConfig.new(
          generic_webhook_url: URI.parse("https://hooks.example.test/reports"), email_recipients: ["primary@example.test"],
          fallback_webhook_url: URI.parse("https://fallback.example.test/reports"),
          fallback_email_recipients: ["fallback@example.test"], max_attempts: 1, retry_base: 1.millisecond
        ), email_sender: sender)
        returned = delivery.deliver(delivery_report)
        returned.size.should eq 2
        returned.all?(&.status.failed?).should be_true
        fallback_calls.should eq 0
        records = await_delivery_count(store, 4)
        records.count(&.destination.==("fallback_generic_webhook")).should eq 1
        records.count(&.destination.==("fallback_email")).should eq 1
        stays_at_delivery_count(store, 4)
        fallback_calls.should eq 1
        sender.emails.size.should eq 1
      end

      it "retries a failing fallback and stops without triggering more fallbacks" do
        fallback_calls = 0
        WebMock.stub(:post, "https://hooks.example.test/reports").to_return(status: 400)
        WebMock.stub(:post, "https://fallback.example.test/reports").to_return do |_request|
          fallback_calls += 1
          HTTP::Client::Response.new(503)
        end
        store = ReportDeliveryStore.new
        delivery = ReportDelivery.new(store, ReportDeliveryConfig.new(
          generic_webhook_url: URI.parse("https://hooks.example.test/reports"),
          fallback_webhook_url: URI.parse("https://fallback.example.test/reports"), retry_base: 1.millisecond
        ))
        delivery.deliver(delivery_report)
        records = await_delivery_count(store, 4)
        records.last.error.not_nil!.should start_with "attempt 3 of 3, giving up: "
        records.last(3).map(&.destination).should eq ["fallback_generic_webhook"] * 3
        stays_at_delivery_count(store, 4)
        fallback_calls.should eq 3
      end

      it "uses fallbacks for non-retryable missing SMTP configuration" do
        WebMock.stub(:post, "https://fallback.example.test/reports").to_return(status: 200)
        store = ReportDeliveryStore.new
        delivery = ReportDelivery.new(store, ReportDeliveryConfig.new(
          email_recipients: ["primary@example.test"],
          fallback_webhook_url: URI.parse("https://fallback.example.test/reports"), retry_base: 1.millisecond
        ))
        returned = delivery.deliver(delivery_report)
        returned.first.error.not_nil!.should contain "not retryable: SMTP is not configured"
        records = await_delivery_count(store, 2)
        records.last.destination.should eq "fallback_generic_webhook"
        records.last.status.delivered?.should be_true
        stays_at_delivery_count(store, 2)
      end

      it "does not use fallbacks for a rendering failure" do
        sender = RecordingReportEmailSender.new
        store = ReportDeliveryStore.new
        delivery = ReportDelivery.new(store, ReportDeliveryConfig.new(
          generic_webhook_url: URI.parse("https://hooks.example.test/reports"), template_id: "missing",
          fallback_webhook_url: URI.parse("https://fallback.example.test/reports"),
          fallback_email_recipients: ["fallback@example.test"], retry_base: 1.millisecond
        ), email_sender: sender)
        delivery.deliver(delivery_report).first.error.not_nil!.should contain "report template not found"
        stays_at_delivery_count(store, 1)
        sender.emails.should be_empty
      end

      it "leaves delivery disabled when only fallbacks are configured" do
        sender = RecordingReportEmailSender.new
        store = ReportDeliveryStore.new
        config = ReportDeliveryConfig.new(
          fallback_webhook_url: URI.parse("https://fallback.example.test/reports"), fallback_email_recipients: ["fallback@example.test"]
        )
        config.configured?.should be_false
        delivery = ReportDelivery.new(store, config, email_sender: sender)
        delivery.deliver(delivery_report).first.status.skipped?.should be_true
        stays_at_delivery_count(store, 1)
        sender.emails.should be_empty
      end

      it "does not use fallbacks when maintenance disables delivery" do
        sender = RecordingReportEmailSender.new
        AISupportAgent.delivery.configure(ReportDeliveryConfig.new(
          generic_webhook_url: URI.parse("https://hooks.example.test/reports"),
          fallback_webhook_url: URI.parse("https://fallback.example.test/reports"), fallback_email_recipients: ["fallback@example.test"]
        ), sender)
        report = AISupportAgent.ingest(IncidentEvent.new(
          source: IncidentSource::Webhook, severity: IncidentSeverity::Error,
          correlation_key: "delivery:maintenance", payload: JSON.parse({message: "runtime error"}.to_json), module_id: "mod-delivery"
        ), deliver_report: false)
        stays_at_delivery_count(AISupportAgent.deliveries, 1)
        record = AISupportAgent.deliveries.for_incident(report.incident_id).first
        record.status.skipped?.should be_true
        record.destination.should eq "maintenance_policy"
        sender.emails.should be_empty
      end
    end
  end
end
