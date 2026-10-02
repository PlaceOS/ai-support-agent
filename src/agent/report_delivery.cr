require "email"
require "http/client"
require "uri"
require "yaml"

module AISupportAgent
  enum ReportDeliveryStatus
    Skipped
    Delivered
    Failed
  end

  struct ReportDeliveryRecord
    include JSON::Serializable

    getter incident_id : String
    getter status : ReportDeliveryStatus
    getter destination : String
    getter attempted_at : Time
    getter response_status : Int32?
    getter error : String?

    def initialize(
      @incident_id : String,
      @status : ReportDeliveryStatus,
      @destination : String,
      @attempted_at : Time,
      @response_status : Int32? = nil,
      @error : String? = nil,
    )
    end
  end

  struct SmtpSettings
    getter host : String
    getter port : Int32
    getter helo_domain : String
    getter from_address : String
    getter from_name : String
    getter username : String?
    getter password : String?
    getter tls_mode : EMail::Client::TLSMode

    def self.from_environment : SmtpSettings?
      return unless host = SMTP_SERVER
      return unless from_address = SMTP_FROM_EMAIL

      tls_mode = case SMTP_SECURE.upcase
                 when "SMTPS"
                   EMail::Client::TLSMode::SMTPS
                 when "STARTTLS"
                   EMail::Client::TLSMode::STARTTLS
                 when "", "NONE"
                   EMail::Client::TLSMode::NONE
                 else
                   raise ArgumentError.new("SMTP_SECURE must be NONE, STARTTLS, or SMTPS")
                 end

      new(
        host: host,
        port: SMTP_PORT,
        helo_domain: SMTP_HELO_DOMAIN || from_address.split('@').last,
        from_address: from_address,
        from_name: SMTP_FROM_NAME,
        username: SMTP_USER,
        password: SMTP_PASS,
        tls_mode: tls_mode
      )
    end

    def initialize(
      @host : String,
      @port : Int32,
      @helo_domain : String,
      @from_address : String,
      @from_name : String = "PlaceOS Support Agent",
      @username : String? = nil,
      @password : String? = nil,
      @tls_mode : EMail::Client::TLSMode = EMail::Client::TLSMode::NONE,
    )
      if username.nil? != password.nil?
        raise ArgumentError.new("SMTP_USER and SMTP_PASS must be configured together")
      end
    end

    def client_config(timeout : Time::Span = REPORT_DELIVERY_TIMEOUT_SECONDS.seconds) : EMail::Client::Config
      config = EMail::Client::Config.new(host, port, helo_domain: helo_domain)
      seconds = timeout.total_seconds.ceil.to_i.clamp(1, 120)
      config.dns_timeout = seconds
      config.connect_timeout = seconds
      config.read_timeout = seconds
      config.write_timeout = seconds
      config.use_tls(tls_mode)
      if username = self.username
        if password = self.password
          config.use_auth(username, password)
        end
      end
      config
    end
  end

  struct ReportDeliveryConfig
    getter generic_webhook_url : URI?
    getter email_recipients : Array(String)
    getter smtp : SmtpSettings?
    getter template_id : String
    getter timeout : Time::Span
    getter max_attempts : Int32
    getter retry_base : Time::Span

    def self.from_environment : ReportDeliveryConfig
      new(
        generic_webhook_url: REPORT_WEBHOOK_URL.try { |url| URI.parse(url) },
        email_recipients: REPORT_EMAIL_TO,
        smtp: SmtpSettings.from_environment,
        template_id: REPORT_TEMPLATE_ID
      )
    end

    def initialize(
      @generic_webhook_url : URI? = nil,
      @email_recipients : Array(String) = [] of String,
      @smtp : SmtpSettings? = nil,
      @template_id : String = "operator-report",
      @timeout : Time::Span = REPORT_DELIVERY_TIMEOUT_SECONDS.seconds,
      max_attempts : Int32 = REPORT_DELIVERY_MAX_ATTEMPTS,
      @retry_base : Time::Span = REPORT_DELIVERY_RETRY_BASE_SECONDS.seconds,
    )
      @max_attempts = max_attempts.clamp(1, 10)
    end

    def configured? : Bool
      !!generic_webhook_url || !email_recipients.empty?
    end
  end

  class ReportTemplate
    include YAML::Serializable
    include YAML::Serializable::Strict

    getter schema_version : String
    getter id : String
    getter version : Int32
    getter subject : String
    getter body : String
  end

  struct RenderedReport
    getter template_id : String
    getter template_version : Int32
    getter subject : String
    getter body : String

    def initialize(@template_id : String, @template_version : Int32, @subject : String, @body : String)
    end
  end

  class ReportTemplateCatalog
    SCHEMA_VERSION = "report-template.v1"
    DEFAULT_PATH   = "templates/reports"
    SOURCE_PATH    = File.expand_path("../../templates/reports", __DIR__)
    PLACEHOLDER    = /\{\{([a-z_]+)\}\}/
    AVAILABLE_KEYS = Set{"incident_id", "status", "severity", "summary", "report"}

    getter path : String

    def self.from_environment : ReportTemplateCatalog
      path = REPORT_TEMPLATES_PATH || begin
        paths = [DEFAULT_PATH]
        if executable = Process.executable_path
          paths << File.join(File.dirname(executable), DEFAULT_PATH)
        end
        paths << SOURCE_PATH
        paths.find { |candidate| Dir.exists?(candidate) } || DEFAULT_PATH
      end
      new(path)
    end

    def initialize(@path : String)
      raise ArgumentError.new("report template directory not found: #{path}") unless Dir.exists?(path)
    end

    def render(id : String, report : IncidentReport) : RenderedReport
      template = templates.select { |candidate| candidate.id == id }.max_by?(&.version)
      raise ArgumentError.new("report template not found: #{id}") unless template

      values = {
        "incident_id" => report.incident_id,
        "status"      => report.status.to_s,
        "severity"    => report.severity.to_s,
        "summary"     => report.summary,
        "report"      => report.to_markdown,
      }
      RenderedReport.new(
        template_id: template.id,
        template_version: template.version,
        subject: interpolate(template.subject, values),
        body: interpolate(template.body, values)
      )
    end

    private def templates : Array(ReportTemplate)
      files = (Dir.glob(File.join(path, "*.yml")) + Dir.glob(File.join(path, "*.yaml"))).sort
      raise ArgumentError.new("no report templates found in #{path}") if files.empty?

      identities = Set(String).new
      files.map do |file|
        template = ReportTemplate.from_yaml(File.read(file))
        validate(template, file)
        identity = "#{template.id}:#{template.version}"
        raise ArgumentError.new("duplicate report template #{identity}") unless identities.add?(identity)
        template
      rescue error : YAML::ParseException
        raise ArgumentError.new("invalid report template YAML in #{file}: #{error.message}")
      end
    end

    private def validate(template : ReportTemplate, file : String) : Nil
      unless template.schema_version == SCHEMA_VERSION
        raise ArgumentError.new("unsupported report template schema #{template.schema_version} in #{file}")
      end
      unless template.id.matches?(/\A[a-z0-9]+(?:-[a-z0-9]+)*\z/)
        raise ArgumentError.new("invalid report template id #{template.id} in #{file}")
      end
      raise ArgumentError.new("report template version must be positive in #{file}") unless template.version > 0
      raise ArgumentError.new("report template subject cannot be empty in #{file}") if template.subject.empty?
      raise ArgumentError.new("report template body cannot be empty in #{file}") if template.body.empty?

      placeholders(template.subject, file)
      placeholders(template.body, file)
    end

    private def placeholders(text : String, file : String) : Nil
      text.scan(PLACEHOLDER).each do |match|
        key = match[1]
        raise ArgumentError.new("unknown report template placeholder #{key} in #{file}") unless AVAILABLE_KEYS.includes?(key)
      end
    end

    private def interpolate(text : String, values : Hash(String, String)) : String
      text.gsub(PLACEHOLDER) do |placeholder|
        values[placeholder[2...-2]]
      end
    end
  end

  struct ReportDeliveryPayload
    include JSON::Serializable

    getter schema : String = "incident-report-delivery.v1"
    getter incident_id : String
    getter status : String
    getter severity : String
    getter summary : String
    getter report : IncidentReport
    getter template_id : String
    getter template_version : Int32
    getter subject : String
    getter markdown : String

    def initialize(report : IncidentReport, rendered : RenderedReport)
      @incident_id = report.incident_id
      @status = report.status.to_s
      @severity = report.severity.to_s
      @summary = report.summary
      @report = report
      @template_id = rendered.template_id
      @template_version = rendered.template_version
      @subject = rendered.subject
      @markdown = rendered.body
    end
  end

  struct ReportEmail
    getter recipients : Array(String)
    getter subject : String
    getter body : String

    def initialize(@recipients : Array(String), @subject : String, @body : String)
    end
  end

  abstract class ReportEmailSender
    abstract def send(email : ReportEmail) : Nil
  end

  class SmtpReportEmailSender < ReportEmailSender
    def initialize(@settings : SmtpSettings, @timeout : Time::Span = REPORT_DELIVERY_TIMEOUT_SECONDS.seconds)
    end

    def send(email : ReportEmail) : Nil
      message = EMail::Message.new
      message.from @settings.from_address, @settings.from_name
      email.recipients.each { |recipient| message.to recipient }
      message.subject email.subject
      message.message email.body

      EMail::Client.new(@settings.client_config(@timeout)).start do
        send(message)
      end
    end
  end

  class ReportDeliveryStore
    @records = [] of ReportDeliveryRecord
    @repository : PostgresIncidentRepository?
    @persistence_error : String?
    @lock = Mutex.new

    def persist_with(@repository : PostgresIncidentRepository) : Nil
    end

    def disable_persistence : Nil
      @repository = nil
      @persistence_error = nil
    end

    def persistence_enabled? : Bool
      !!@repository
    end

    def persistence_error : String?
      @persistence_error
    end

    def save(record : ReportDeliveryRecord) : ReportDeliveryRecord
      persist(&.save_delivery(record))
      @lock.synchronize { @records << record }
      record
    end

    def for_incident(incident_id : String) : Array(ReportDeliveryRecord)
      persisted = persist(&.deliveries_for_incident(incident_id))
      return persisted if persisted && !persisted.empty?

      @lock.synchronize { @records.select { |record| record.incident_id == incident_id } }
    end

    def all : Array(ReportDeliveryRecord)
      persisted = persist(&.all_deliveries)
      return persisted if persisted && !persisted.empty?

      @lock.synchronize { @records.dup }
    end

    def clear : Nil
      @lock.synchronize { @records.clear }
    end

    private def persist(& : PostgresIncidentRepository -> T) : T? forall T
      return unless repository = @repository

      yield repository
    rescue error
      @persistence_error = "#{error.class}: #{error.message}"
      AISupportAgent::Log.warn(exception: error) { "report-delivery persistence failed; continuing with in-memory store" }
      nil
    end
  end

  struct ReportDeliveryChannel
    getter destination : String
    getter url : URI?
    getter recipients : Array(String)

    def initialize(@destination : String, @url : URI? = nil, @recipients : Array(String) = [] of String)
    end
  end

  class ReportDelivery
    @email_sender : ReportEmailSender?
    @retrying = Set({String, String}).new
    @retry_lock = Mutex.new

    def initialize(
      @store : ReportDeliveryStore,
      @config : ReportDeliveryConfig = ReportDeliveryConfig.from_environment,
      @templates : ReportTemplateCatalog = ReportTemplateCatalog.from_environment,
      email_sender : ReportEmailSender? = nil,
    )
      @email_sender = email_sender || @config.smtp.try { |smtp| SmtpReportEmailSender.new(smtp, @config.timeout) }
    end

    def configure(@config : ReportDeliveryConfig, email_sender : ReportEmailSender? = nil) : Nil
      @email_sender = email_sender || @config.smtp.try { |smtp| SmtpReportEmailSender.new(smtp, @config.timeout) }
    end

    def deliver(report : IncidentReport) : Array(ReportDeliveryRecord)
      config = @config
      sender = @email_sender
      unless config.configured?
        return [@store.save(ReportDeliveryRecord.new(
          incident_id: report.incident_id,
          status: ReportDeliveryStatus::Skipped,
          destination: "disabled",
          attempted_at: Time.utc,
          error: "no report delivery channel configured"
        ))]
      end

      rendered, payload = begin
        rendered = @templates.render(config.template_id, report)
        {rendered, ReportDeliveryPayload.new(report, rendered).to_json}
      rescue error
        AISupportAgent::Log.warn(exception: error) { "report rendering failed" }
        return channels(config).map do |channel|
          failure(report.incident_id, channel, config, 1, "#{error.class}: #{error.message}", false)
        end
      end
      channels(config).map do |channel|
        record, retryable = attempt(report.incident_id, rendered, payload, channel, config, sender, 1)
        if record.status.failed?
          if retryable && config.max_attempts > 1
            schedule_retries(report.incident_id, rendered, payload, channel, config, sender)
          else
            give_up(report.incident_id, channel)
          end
        end
        record
      end
    end

    private def channels(config : ReportDeliveryConfig) : Array(ReportDeliveryChannel)
      destinations = [] of ReportDeliveryChannel
      if url = config.generic_webhook_url
        destinations << ReportDeliveryChannel.new("generic_webhook", url: url)
      end
      unless config.email_recipients.empty?
        destinations << ReportDeliveryChannel.new("email", recipients: config.email_recipients)
      end
      destinations
    end

    private def attempt(incident_id : String, rendered : RenderedReport, payload : String, channel : ReportDeliveryChannel,
                        config : ReportDeliveryConfig, sender : ReportEmailSender?, number : Int32) : Tuple(ReportDeliveryRecord, Bool)
      response_status = nil
      if url = channel.url
        unless url.scheme.in?("http", "https") && url.host.presence
          return {failure(incident_id, channel, config, number, "invalid webhook URL", false), false}
        end
        client = HTTP::Client.new(url)
        client.connect_timeout = config.timeout
        client.read_timeout = config.timeout
        begin
          response = client.post(url.request_target, headers: HTTP::Headers{"Content-Type" => "application/json"}, body: payload)
        ensure
          client.close
        end
        response_status = response.status_code
        unless response.success?
          retryable = response_status.in?(408, 425, 429) || (500..599).includes?(response_status)
          return {failure(incident_id, channel, config, number, "HTTP #{response_status}: #{response.body}", retryable, response_status), retryable}
        end
      else
        unless sender
          return {failure(incident_id, channel, config, number, "SMTP is not configured", false), false}
        end
        sender.send(ReportEmail.new(channel.recipients, rendered.subject, rendered.body))
      end
      {@store.save(ReportDeliveryRecord.new(
        incident_id: incident_id,
        status: ReportDeliveryStatus::Delivered,
        destination: channel.destination,
        attempted_at: Time.utc,
        response_status: response_status
      )), false}
    rescue error : EMail::Error::ClientConfigError
      {failure(incident_id, channel, config, number, "#{error.class}: #{error.message}", false), false}
    rescue error
      {failure(incident_id, channel, config, number, "#{error.class}: #{error.message}", true), true}
    end

    private def schedule_retries(incident_id : String, rendered : RenderedReport, payload : String, channel : ReportDeliveryChannel,
                                 config : ReportDeliveryConfig, sender : ReportEmailSender?) : Nil
      key = {incident_id, channel.destination}
      return unless @retry_lock.synchronize { @retrying.add?(key) }
      spawn do
        begin
          (2..config.max_attempts).each do |number|
            sleep config.retry_base * (2 ** (number - 2))
            record, retryable = attempt(incident_id, rendered, payload, channel, config, sender, number)
            break if record.status.delivered?
            unless retryable && number < config.max_attempts
              give_up(incident_id, channel)
              break
            end
          end
        rescue error
          AISupportAgent::Log.error(exception: error) { "#{channel.destination} report retries stopped for #{incident_id}" }
        ensure
          @retry_lock.synchronize { @retrying.delete(key) }
        end
      end
    end

    private def give_up(incident_id : String, channel : ReportDeliveryChannel) : Nil
      AISupportAgent::Log.error { "#{channel.destination} report delivery giving up for #{incident_id}" }
    end

    private def failure(incident_id : String, channel : ReportDeliveryChannel, config : ReportDeliveryConfig, number : Int32,
                        message : String, retryable : Bool, response_status : Int32? = nil) : ReportDeliveryRecord
      prefix = if !retryable
                 "attempt #{number} of #{config.max_attempts}, not retryable: "
               elsif number == config.max_attempts
                 "attempt #{number} of #{config.max_attempts}, giving up: "
               else
                 "attempt #{number} of #{config.max_attempts}: "
               end
      AISupportAgent::Log.warn { "#{channel.destination} report delivery failed: #{prefix}#{message}" }
      @store.save(ReportDeliveryRecord.new(
        incident_id: incident_id,
        status: ReportDeliveryStatus::Failed,
        destination: channel.destination,
        attempted_at: Time.utc,
        response_status: response_status,
        error: prefix + message
      ))
    end
  end
end
