require "digest/sha256"
require "set"
require "uuid"
require "yaml"

module AISupportAgent
  enum VerificationRunStatus
    Verified
    RetryScheduled
    Failed
  end

  struct VerificationCheckResult
    include JSON::Serializable

    getter id : String
    getter tool : String
    getter criterion : String
    getter? passed : Bool
    getter summary : String
    getter evidence : Array(Evidence)

    def initialize(
      @id : String,
      @tool : String,
      @criterion : String,
      @passed : Bool,
      @summary : String,
      @evidence : Array(Evidence),
    )
    end
  end

  struct VerificationRun
    include JSON::Serializable

    getter id : String
    getter incident_id : String
    getter procedure : ProcedureAudit
    getter attempt : Int32
    getter status : VerificationRunStatus
    getter checks : Array(VerificationCheckResult)
    getter evidence : Array(Evidence)
    getter started_at : Time
    getter completed_at : Time
    getter next_retry_at : Time?

    def initialize(
      @id : String,
      @incident_id : String,
      @procedure : ProcedureAudit,
      @attempt : Int32,
      @status : VerificationRunStatus,
      @checks : Array(VerificationCheckResult),
      @evidence : Array(Evidence),
      @started_at : Time,
      @completed_at : Time,
      @next_retry_at : Time? = nil,
    )
    end
  end

  class VerificationCheck
    include YAML::Serializable
    include YAML::Serializable::Strict

    getter id : String
    getter tool : String
    getter criterion : String
    getter io_timeout_seconds : Int32 = 10
    getter requires : Array(String) = [] of String
  end

  class VerificationPolicy
    include YAML::Serializable
    include YAML::Serializable::Strict

    getter retry_interval_seconds : Int32
    getter max_attempts : Int32
    getter timeout_seconds : Int32
    getter failure_outcome : String
  end

  class VerificationProcedure
    include YAML::Serializable
    include YAML::Serializable::Strict

    @[YAML::Field(key: "$schema")]
    getter schema_uri : String? = nil
    getter schema_version : String
    getter id : String
    getter version : Int32
    getter name : String
    getter mode : String
    getter checks : Array(VerificationCheck)
    getter policy : VerificationPolicy

    @[YAML::Field(ignore: true)]
    property content_hash : String = ""

    def reference : ProcedureReference
      ProcedureReference.new("verification", id, version)
    end
  end

  class VerificationProcedureRegistry
    SCHEMA_VERSION = "verification-procedure.v1"
    CRITERIA       = ["tool_succeeded", "evidence_present", "runtime_error_cleared"]
    CONTEXT_FIELDS = ["tenant_id", "system_id", "module_id", "module_name", "module_index"]

    class Error < Exception
    end

    class ValidationError < Error
    end

    getter path : String

    def self.load(path : String) : VerificationProcedureRegistry
      raise ValidationError.new("verification directory not found: #{path}") unless Dir.exists?(path)

      files = playbook_files(path)
      raise ValidationError.new("no verification procedures found in #{path}") if files.empty?

      procedures = files.map do |file|
        contents = File.read(file)
        procedure = VerificationProcedure.from_yaml(contents)
        unless procedure.schema_version == SCHEMA_VERSION
          raise ValidationError.new("unsupported verification schema_version #{procedure.schema_version} in #{file}")
        end
        procedure.content_hash = Digest::SHA256.hexdigest(contents)
        procedure
      rescue error : YAML::ParseException
        raise ValidationError.new("invalid verification YAML in #{file}: #{error.message}")
      end

      new(path, procedures).tap(&.validate!)
    end

    private def self.playbook_files(path : String) : Array(String)
      (Dir.glob(File.join(path, "**", "*.yml")) + Dir.glob(File.join(path, "**", "*.yaml"))).sort
    end

    private def initialize(@path : String, @procedures : Array(VerificationProcedure))
    end

    def size : Int32
      @procedures.size
    end

    def includes?(reference : ProcedureReference) : Bool
      @procedures.any? { |procedure| procedure.reference == reference }
    end

    def find(reference : ProcedureReference) : VerificationProcedure?
      @procedures.find { |procedure| procedure.reference == reference }
    end

    protected def procedures_snapshot : Array(VerificationProcedure)
      @procedures.dup
    end

    protected def validate! : VerificationProcedureRegistry
      identities = Set(String).new
      @procedures.each do |procedure|
        identity = "#{procedure.id}:#{procedure.version}"
        raise ValidationError.new("duplicate verification procedure #{identity}") unless identities.add?(identity)
        validate(procedure)
      end
      self
    end

    private def validate(procedure : VerificationProcedure) : Nil
      unless procedure.id.matches?(/\A[a-z0-9]+(?:-[a-z0-9]+)*\z/)
        raise ValidationError.new("invalid verification procedure id #{procedure.id}")
      end
      raise ValidationError.new("#{procedure.id} version must be positive") unless procedure.version > 0
      raise ValidationError.new("#{procedure.id} name is required") if procedure.name.blank?
      raise ValidationError.new("#{procedure.id} mode must be verification") unless procedure.mode == "verification"
      raise ValidationError.new("#{procedure.id} must define checks") if procedure.checks.empty?

      check_ids = Set(String).new
      procedure.checks.each do |check|
        raise ValidationError.new("#{procedure.id} has invalid check id #{check.id}") unless check.id.matches?(/\A[a-z0-9]+(?:-[a-z0-9]+)*\z/)
        raise ValidationError.new("#{procedure.id} has duplicate check #{check.id}") unless check_ids.add?(check.id)
        unless PlaybookStep::TOOL_CONTEXT.has_key?(check.tool)
          raise ValidationError.new("#{procedure.id} check #{check.id} uses unknown read-only tool #{check.tool}")
        end
        unless CRITERIA.includes?(check.criterion)
          raise ValidationError.new("#{procedure.id} check #{check.id} uses unknown criterion #{check.criterion}")
        end
        unless (1..60).includes?(check.io_timeout_seconds)
          raise ValidationError.new("#{procedure.id} check #{check.id} io_timeout_seconds must be between 1 and 60")
        end
        check.requires.each do |field|
          raise ValidationError.new("#{procedure.id} check #{check.id} has unknown context #{field}") unless CONTEXT_FIELDS.includes?(field)
        end
        required = PlaybookStep.required_context(check.tool)
        missing = required.reject { |field| check.requires.includes?(field) }
        unless missing.empty?
          raise ValidationError.new("#{procedure.id} check #{check.id} must require #{missing.join(", ")}")
        end
      end

      policy = procedure.policy
      unless (1..86_400).includes?(policy.retry_interval_seconds)
        raise ValidationError.new("#{procedure.id} retry_interval_seconds must be between 1 and 86400")
      end
      raise ValidationError.new("#{procedure.id} max_attempts must be between 1 and 10") unless (1..10).includes?(policy.max_attempts)
      unless policy.timeout_seconds >= policy.retry_interval_seconds && policy.timeout_seconds <= 604_800
        raise ValidationError.new("#{procedure.id} timeout_seconds must cover the retry interval and be at most 604800")
      end
      raise ValidationError.new("#{procedure.id} failure_outcome must be escalate") unless policy.failure_outcome == "escalate"
    end
  end

  class VerificationRunStore
    @runs = {} of String => Array(VerificationRun)
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

    def save(run : VerificationRun) : VerificationRun
      persist(&.save_verification_run(run))
      @lock.synchronize { (@runs[run.incident_id] ||= [] of VerificationRun) << run }
      run
    end

    def for_incident(incident_id : String) : Array(VerificationRun)
      persisted = persist(&.verification_runs_for_incident(incident_id))
      return persisted if persisted && !persisted.empty?

      @lock.synchronize { (@runs[incident_id]? || [] of VerificationRun).dup }
    end

    def size : Int32
      persisted = persist(&.all_verification_runs)
      return persisted.size if persisted && !persisted.empty?

      @lock.synchronize { @runs.values.sum(&.size) }
    end

    def clear : Nil
      @lock.synchronize { @runs.clear }
    end

    private def persist(& : PostgresIncidentRepository -> T) : T? forall T
      return unless repository = @repository

      yield repository
    rescue error
      @persistence_error = "#{error.class}: #{error.message}"
      AISupportAgent::Log.warn(exception: error) { "verification-run persistence failed; continuing with in-memory store" }
      nil
    end
  end

  class VerificationEngine
    class Error < Exception
    end

    def initialize(
      @catalog : WorkflowCatalog,
      @context : PlaceOSContext,
      @runs : VerificationRunStore,
    )
    end

    def verify(report : IncidentReport, event : IncidentEvent, force : Bool = false) : VerificationRun
      reference_value = report.remediation_proposal.try(&.verification_procedure) ||
                        raise Error.new("incident #{report.incident_id} has no verification procedure")
      reference = ProcedureReference.parse(reference_value)
      procedure = @catalog.verification(reference) || raise Error.new("verification procedure #{reference} is unavailable")
      previous = @runs.for_incident(report.incident_id).select(&.procedure.id.==(procedure.id))
      if !force && (retry_at = previous.last?.try(&.next_retry_at)) && retry_at > Time.utc
        raise Error.new("verification retry is not due until #{retry_at.to_rfc3339}")
      end

      started_at = Time.utc
      checks = procedure.checks.map { |check| execute(check, event) }
      completed_at = Time.utc
      passed = checks.all?(&.passed?)
      attempt = previous.size + 1
      first_started_at = previous.first?.try(&.started_at) || started_at
      retry_available = attempt < procedure.policy.max_attempts &&
                        completed_at < first_started_at + procedure.policy.timeout_seconds.seconds
      status = if passed
                 VerificationRunStatus::Verified
               elsif retry_available
                 VerificationRunStatus::RetryScheduled
               else
                 VerificationRunStatus::Failed
               end
      next_retry_at = completed_at + procedure.policy.retry_interval_seconds.seconds if status.retry_scheduled?

      @runs.save(VerificationRun.new(
        id: "verify-#{UUID.random}",
        incident_id: report.incident_id,
        procedure: ProcedureAudit.new("verification", procedure.id, procedure.version, procedure.content_hash),
        attempt: attempt,
        status: status,
        checks: checks,
        evidence: checks.flat_map(&.evidence),
        started_at: started_at,
        completed_at: completed_at,
        next_retry_at: next_retry_at
      ))
    rescue error : ArgumentError
      raise Error.new(error.message)
    end

    private def execute(check : VerificationCheck, event : IncidentEvent) : VerificationCheckResult
      result = @context.execute(check.tool, event, check.io_timeout_seconds)
      passed = case check.criterion
               when "tool_succeeded"
                 result.status.completed?
               when "evidence_present"
                 result.status.completed? && !result.evidence.empty?
               when "runtime_error_cleared"
                 result.status.completed? && result.evidence.any? { |evidence| runtime_error_cleared?(evidence.data) }
               else
                 false
               end
      VerificationCheckResult.new(
        id: check.id,
        tool: check.tool,
        criterion: check.criterion,
        passed: passed,
        summary: passed ? "Verification criterion passed" : "Verification criterion failed",
        evidence: result.evidence
      )
    end

    private def runtime_error_cleared?(data : JSON::Any?) : Bool
      return false unless data
      case raw = data.raw
      when Hash
        if value = raw["has_runtime_error"]?
          return value.raw == false
        end
        raw.values.any? { |nested| runtime_error_cleared?(nested) }
      when Array
        raw.any? { |nested| runtime_error_cleared?(nested) }
      else
        false
      end
    end
  end
end
