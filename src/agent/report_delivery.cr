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

    def client_config : EMail::Client::Config
      config = EMail::Client::Config.new(host, port, helo_domain: helo_domain)
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
    )
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
    def initialize(@settings : SmtpSettings)
    end

    def send(email : ReportEmail) : Nil
      message = EMail::Message.new
      message.from @settings.from_address, @settings.from_name
      email.recipients.each { |recipient| message.to recipient }
      message.subject email.subject
      message.message email.body

      EMail::Client.new(@settings.client_config).start do
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

  class ReportDelivery
    @email_sender : ReportEmailSender?

    def initialize(
      @store : ReportDeliveryStore,
      @config : ReportDeliveryConfig = ReportDeliveryConfig.from_environment,
      @templates : ReportTemplateCatalog = ReportTemplateCatalog.from_environment,
      email_sender : ReportEmailSender? = nil,
    )
      @email_sender = email_sender || @config.smtp.try { |smtp| SmtpReportEmailSender.new(smtp) }
    end

    def configure(@config : ReportDeliveryConfig, email_sender : ReportEmailSender? = nil) : Nil
      @email_sender = email_sender || @config.smtp.try { |smtp| SmtpReportEmailSender.new(smtp) }
    end

    def deliver(report : IncidentReport) : Array(ReportDeliveryRecord)
      unless @config.configured?
        return [@store.save(ReportDeliveryRecord.new(
          incident_id: report.incident_id,
          status: ReportDeliveryStatus::Skipped,
          destination: "disabled",
          attempted_at: Time.utc,
          error: "no report delivery channel configured"
        ))]
      end

      rendered = @templates.render(@config.template_id, report)
      records = [] of ReportDeliveryRecord
      if url = @config.generic_webhook_url
        records << deliver_generic_webhook(report, rendered, url)
      end
      unless @config.email_recipients.empty?
        records << deliver_email(report, rendered)
      end
      records
    rescue error
      AISupportAgent::Log.warn(exception: error) { "report rendering failed" }
      configured_destinations.map do |destination|
        @store.save(ReportDeliveryRecord.new(
          incident_id: report.incident_id,
          status: ReportDeliveryStatus::Failed,
          destination: destination,
          attempted_at: Time.utc,
          error: "#{error.class}: #{error.message}"
        ))
      end
    end

    private def configured_destinations : Array(String)
      destinations = [] of String
      destinations << "generic_webhook" if @config.generic_webhook_url
      destinations << "email" unless @config.email_recipients.empty?
      destinations
    end

    private def deliver_generic_webhook(report : IncidentReport, rendered : RenderedReport, url : URI) : ReportDeliveryRecord
      response = HTTP::Client.post(
        url,
        headers: HTTP::Headers{"Content-Type" => "application/json"},
        body: ReportDeliveryPayload.new(report, rendered).to_json
      )

      if response.success?
        status = ReportDeliveryStatus::Delivered
        error = nil
      else
        status = ReportDeliveryStatus::Failed
        error = "HTTP #{response.status_code}: #{response.body}"
      end

      @store.save(ReportDeliveryRecord.new(
        incident_id: report.incident_id,
        status: status,
        destination: "generic_webhook",
        attempted_at: Time.utc,
        response_status: response.status_code,
        error: error
      ))
    rescue error
      save_failure(report.incident_id, "generic_webhook", error)
    end

    private def deliver_email(report : IncidentReport, rendered : RenderedReport) : ReportDeliveryRecord
      sender = @email_sender || raise "SMTP is not configured"
      sender.send(ReportEmail.new(@config.email_recipients, rendered.subject, rendered.body))
      @store.save(ReportDeliveryRecord.new(
        incident_id: report.incident_id,
        status: ReportDeliveryStatus::Delivered,
        destination: "email",
        attempted_at: Time.utc
      ))
    rescue error
      save_failure(report.incident_id, "email", error)
    end

    private def save_failure(incident_id : String, destination : String, error : Exception) : ReportDeliveryRecord
      AISupportAgent::Log.warn(exception: error) { "#{destination} report delivery failed" }
      @store.save(ReportDeliveryRecord.new(
        incident_id: incident_id,
        status: ReportDeliveryStatus::Failed,
        destination: destination,
        attempted_at: Time.utc,
        error: "#{error.class}: #{error.message}"
      ))
    end
  end
end
