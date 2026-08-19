require "digest/sha256"
require "set"
require "uuid"
require "yaml"

module AISupportAgent
  struct EscalationPlan
    include JSON::Serializable

    getter procedure : ProcedureAudit
    getter owner_queue : String
    getter response_sla_minutes : Int32
    getter required_artefacts : Array(String)
    getter reason : String

    def initialize(
      @procedure : ProcedureAudit,
      @owner_queue : String,
      @response_sla_minutes : Int32,
      @required_artefacts : Array(String),
      @reason : String,
    )
    end
  end

  class EscalationMatch
    include YAML::Serializable
    include YAML::Serializable::Strict

    getter severities : Array(String) = [] of String
    getter classifications : Array(String) = [] of String
    getter confidence_below : Float64? = nil
    getter minimum_age_seconds : Int32 = 0
    getter? fallback : Bool = false

    def matches?(report : IncidentReport, now : Time) : Bool
      return true if fallback?
      return false unless severities.empty? || severities.includes?(report.severity.to_s.downcase)
      return false unless classifications.empty? || classifications.any? { |value| DiagnosticClassification.parse(value) == report.classification }
      return false if (threshold = confidence_below) && report.confidence >= threshold

      now >= report.created_at + minimum_age_seconds.seconds
    end
  end

  class EscalationProcedure
    include YAML::Serializable
    include YAML::Serializable::Strict

    @[YAML::Field(key: "$schema")]
    getter schema_uri : String? = nil
    getter schema_version : String
    getter id : String
    getter version : Int32
    getter name : String
    getter mode : String
    getter priority : Int32 = 0
    getter matches : EscalationMatch
    getter owner_queue : String
    getter response_sla_minutes : Int32
    getter required_artefacts : Array(String)

    @[YAML::Field(ignore: true)]
    property content_hash : String = ""

    def reference : ProcedureReference
      ProcedureReference.new("escalation", id, version)
    end

    def plan(report : IncidentReport) : EscalationPlan
      EscalationPlan.new(
        procedure: ProcedureAudit.new("escalation", id, version, content_hash),
        owner_queue: owner_queue,
        response_sla_minutes: response_sla_minutes,
        required_artefacts: required_artefacts,
        reason: report.decision.try(&.recommended_action) || report.summary
      )
    end
  end

  class EscalationProcedureRegistry
    SCHEMA_VERSION = "escalation-procedure.v1"
    SEVERITIES     = ["info", "warning", "error", "critical"]
    ARTEFACTS      = ["diagnostic_report", "investigation_plan", "evidence", "agent_decision", "verification_history"]

    class Error < Exception
    end

    class ValidationError < Error
    end

    getter path : String

    def self.load(path : String) : EscalationProcedureRegistry
      raise ValidationError.new("escalation directory not found: #{path}") unless Dir.exists?(path)
      files = (Dir.glob(File.join(path, "**", "*.yml")) + Dir.glob(File.join(path, "**", "*.yaml"))).sort
      raise ValidationError.new("no escalation procedures found in #{path}") if files.empty?

      procedures = files.map do |file|
        contents = File.read(file)
        procedure = EscalationProcedure.from_yaml(contents)
        unless procedure.schema_version == SCHEMA_VERSION
          raise ValidationError.new("unsupported escalation schema_version #{procedure.schema_version} in #{file}")
        end
        procedure.content_hash = Digest::SHA256.hexdigest(contents)
        procedure
      rescue error : YAML::ParseException
        raise ValidationError.new("invalid escalation YAML in #{file}: #{error.message}")
      end
      new(path, procedures).tap(&.validate!)
    end

    private def initialize(@path : String, @procedures : Array(EscalationProcedure))
    end

    def size : Int32
      @procedures.size
    end

    def includes?(reference : ProcedureReference) : Bool
      @procedures.any? { |procedure| procedure.reference == reference }
    end

    def select(report : IncidentReport, allowed : Array(ProcedureReference), now : Time = Time.utc) : EscalationProcedure
      candidates = @procedures.select { |procedure| allowed.includes?(procedure.reference) }
      applicable = candidates.reject(&.matches.fallback?).select(&.matches.matches?(report, now))
      applicable = candidates.select(&.matches.fallback?) if applicable.empty?
      applicable.sort_by! { |procedure| {procedure.priority, procedure.version, procedure.id} }.last? ||
        raise Error.new("no escalation procedure matches incident #{report.incident_id}")
    end

    protected def procedures_snapshot : Array(EscalationProcedure)
      @procedures.dup
    end

    protected def validate! : EscalationProcedureRegistry
      identities = Set(String).new
      @procedures.each do |procedure|
        identity = "#{procedure.id}:#{procedure.version}"
        raise ValidationError.new("duplicate escalation procedure #{identity}") unless identities.add?(identity)
        validate(procedure)
      end
      fallbacks = @procedures.select(&.matches.fallback?)
      unless fallbacks.size == 1 && fallbacks.first.matches.severities.empty? && fallbacks.first.matches.classifications.empty? && fallbacks.first.matches.confidence_below.nil? && fallbacks.first.matches.minimum_age_seconds == 0
        raise ValidationError.new("escalation registry must define exactly one unconditional fallback")
      end
      self
    end

    private def validate(procedure : EscalationProcedure) : Nil
      raise ValidationError.new("invalid escalation procedure id #{procedure.id}") unless procedure.id.matches?(/\A[a-z0-9]+(?:-[a-z0-9]+)*\z/)
      raise ValidationError.new("#{procedure.id} version must be positive") unless procedure.version > 0
      raise ValidationError.new("#{procedure.id} name is required") if procedure.name.blank?
      raise ValidationError.new("#{procedure.id} mode must be escalation") unless procedure.mode == "escalation"
      procedure.matches.severities.each do |severity|
        raise ValidationError.new("#{procedure.id} has unknown severity #{severity}") unless SEVERITIES.includes?(severity)
      end
      procedure.matches.classifications.each do |classification|
        DiagnosticClassification.parse(classification)
      rescue error : ArgumentError
        raise ValidationError.new("#{procedure.id} #{error.message}")
      end
      if (threshold = procedure.matches.confidence_below) && !(0.0..1.0).includes?(threshold)
        raise ValidationError.new("#{procedure.id} confidence_below must be between 0 and 1")
      end
      raise ValidationError.new("#{procedure.id} minimum_age_seconds cannot be negative") if procedure.matches.minimum_age_seconds < 0
      raise ValidationError.new("#{procedure.id} owner_queue is required") if procedure.owner_queue.blank?
      unless (1..10_080).includes?(procedure.response_sla_minutes)
        raise ValidationError.new("#{procedure.id} response_sla_minutes must be between 1 and 10080")
      end
      if procedure.required_artefacts.empty? || procedure.required_artefacts.any? { |artefact| !ARTEFACTS.includes?(artefact) }
        raise ValidationError.new("#{procedure.id} has invalid required artefacts")
      end
    end
  end

  struct EscalationRecord
    include JSON::Serializable

    getter id : String
    getter incident_id : String
    getter plan : EscalationPlan
    getter delivery_status : ReportDeliveryStatus
    getter delivery_destination : String
    getter delivery_error : String?
    getter created_at : Time
    getter response_due_at : Time

    def self.from(report : IncidentReport, delivery : ReportDeliveryRecord, at : Time = Time.utc) : EscalationRecord?
      report.investigation_plan.try(&.escalation).try do |plan|
        new(
          id: "escalation-#{UUID.random}",
          incident_id: report.incident_id,
          plan: plan,
          delivery_status: delivery.status,
          delivery_destination: delivery.destination,
          delivery_error: delivery.error,
          created_at: at,
          response_due_at: at + plan.response_sla_minutes.minutes
        )
      end
    end

    def initialize(
      @id : String,
      @incident_id : String,
      @plan : EscalationPlan,
      @delivery_status : ReportDeliveryStatus,
      @delivery_destination : String,
      @delivery_error : String?,
      @created_at : Time,
      @response_due_at : Time,
    )
    end
  end

  class EscalationRecordStore
    @records = {} of String => Array(EscalationRecord)
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

    getter persistence_error : String?

    def save(record : EscalationRecord) : EscalationRecord
      persist(&.save_escalation_record(record))
      @lock.synchronize { (@records[record.incident_id] ||= [] of EscalationRecord) << record }
      record
    end

    def for_incident(incident_id : String) : Array(EscalationRecord)
      persisted = persist(&.escalation_records_for_incident(incident_id))
      return persisted if persisted && !persisted.empty?
      @lock.synchronize { (@records[incident_id]? || [] of EscalationRecord).dup }
    end

    def size : Int32
      persisted = persist(&.all_escalation_records)
      return persisted.size if persisted && !persisted.empty?
      @lock.synchronize { @records.values.sum(&.size) }
    end

    def clear : Nil
      @lock.synchronize { @records.clear }
    end

    private def persist(& : PostgresIncidentRepository -> T) : T? forall T
      return unless repository = @repository
      yield repository
    rescue error
      @persistence_error = "#{error.class}: #{error.message}"
      AISupportAgent::Log.warn(exception: error) { "escalation persistence failed; continuing with in-memory store" }
      nil
    end
  end
end
