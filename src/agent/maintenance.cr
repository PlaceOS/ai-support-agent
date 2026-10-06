require "cron_parser"
require "digest/sha256"
require "set"
require "tasker"
require "uuid"
require "yaml"

class Tasker::Reactor
  private def start : Nil
    @started = true
    spawn(name: "reactor-loop") { run }
  end

  private def run : Nil
    loop do
      head = @mutex.synchronize { @heap[0]? }
      if head.nil?
        @wake.receive
        next
      end

      delay = head[0] - Time.utc
      if delay <= Time::Span.zero
        fire_due
      else
        select
        when @wake.receive
        when timeout(delay)
          fire_due
        end
      end
    end
  rescue error
    Tasker::Reactor::Log.error(exception: error) { "tasker reactor loop crashed; restarting" }
    spawn(name: "reactor-loop") { run }
  end

  private def fire_due : Nil
    now = Time.utc
    loop do
      task = @mutex.synchronize do
        head = @heap[0]?
        (head && head[0] <= now) ? pop[1] : nil
      end
      break unless task

      due = task
      spawn(name: "scheduled-task") { due.trigger }
    end
  end
end

module AISupportAgent
  struct MaintenanceTarget
    include JSON::Serializable

    getter module_id : String
    getter system_id : String?
    getter module_name : String?
    getter module_index : Int32?
    getter? has_runtime_error : Bool

    def initialize(
      @module_id : String,
      @system_id : String? = nil,
      @module_name : String? = nil,
      @module_index : Int32? = nil,
      @has_runtime_error : Bool = false,
    )
    end
  end

  class MaintenanceSchedule
    include YAML::Serializable
    include YAML::Serializable::Strict

    getter cron : String
    getter timezone : String = "UTC"
  end

  class MaintenanceScope
    include YAML::Serializable
    include YAML::Serializable::Strict

    getter kind : String
    getter filter : String = "all"
    getter module_ids : Array(String) = [] of String
    getter system_ids : Array(String) = [] of String
    getter limit : Int32 = 100
  end

  class MaintenanceReporting
    include YAML::Serializable
    include YAML::Serializable::Strict

    getter? deliver_reports : Bool = true
  end

  class MaintenanceProcedure
    include YAML::Serializable
    include YAML::Serializable::Strict

    @[YAML::Field(key: "$schema")]
    getter schema_uri : String? = nil
    getter schema_version : String
    getter id : String
    getter version : Int32
    getter name : String
    getter mode : String
    getter schedule : MaintenanceSchedule
    getter scope : MaintenanceScope
    getter diagnostics : Array(String)
    getter deduplication_window_seconds : Int32
    getter reporting : MaintenanceReporting

    @[YAML::Field(ignore: true)]
    property content_hash : String = ""

    def reference : ProcedureReference
      ProcedureReference.new("maintenance", id, version)
    end

    def diagnostic_references : Array(ProcedureReference)
      diagnostics.map { |value| ProcedureReference.parse(value) }
    end

    def schedule_bucket(at : Time) : Int64
      at.to_unix // deduplication_window_seconds
    end
  end

  class MaintenanceProcedureRegistry
    SCHEMA_VERSION = "maintenance-procedure.v1"
    SCOPE_KINDS    = ["modules"]
    SCOPE_FILTERS  = ["all", "runtime_errors"]

    class Error < Exception
    end

    class ValidationError < Error
    end

    getter path : String

    def self.load(path : String, diagnostics : DiagnosticProcedureRegistry) : MaintenanceProcedureRegistry
      raise ValidationError.new("maintenance directory not found: #{path}") unless Dir.exists?(path)
      files = (Dir.glob(File.join(path, "**", "*.yml")) + Dir.glob(File.join(path, "**", "*.yaml"))).sort
      raise ValidationError.new("no maintenance procedures found in #{path}") if files.empty?
      procedures = files.map do |file|
        contents = File.read(file)
        procedure = MaintenanceProcedure.from_yaml(contents)
        unless procedure.schema_version == SCHEMA_VERSION
          raise ValidationError.new("unsupported maintenance schema_version #{procedure.schema_version} in #{file}")
        end
        procedure.content_hash = Digest::SHA256.hexdigest(contents)
        procedure
      rescue error : YAML::ParseException
        raise ValidationError.new("invalid maintenance YAML in #{file}: #{error.message}")
      end
      new(path, procedures).tap(&.validate!(diagnostics))
    end

    private def initialize(@path : String, @procedures : Array(MaintenanceProcedure))
    end

    def size : Int32
      @procedures.size
    end

    def find(id : String) : MaintenanceProcedure?
      @procedures.select(&.id.==(id)).max_by?(&.version)
    end

    protected def procedures_snapshot : Array(MaintenanceProcedure)
      @procedures.dup
    end

    protected def validate!(diagnostics : DiagnosticProcedureRegistry) : Nil
      identities = Set(String).new
      @procedures.each do |procedure|
        identity = "#{procedure.id}:#{procedure.version}"
        raise ValidationError.new("duplicate maintenance procedure #{identity}") unless identities.add?(identity)
        validate(procedure, diagnostics)
      end
    end

    private def validate(procedure : MaintenanceProcedure, diagnostics : DiagnosticProcedureRegistry) : Nil
      raise ValidationError.new("invalid maintenance procedure id #{procedure.id}") unless procedure.id.matches?(/\A[a-z0-9]+(?:-[a-z0-9]+)*\z/)
      raise ValidationError.new("#{procedure.id} version must be positive") unless procedure.version > 0
      raise ValidationError.new("#{procedure.id} name is required") if procedure.name.blank?
      raise ValidationError.new("#{procedure.id} mode must be maintenance") unless procedure.mode == "maintenance"
      CronParser.new(procedure.schedule.cron)
      Time::Location.load(procedure.schedule.timezone)
      raise ValidationError.new("#{procedure.id} has unsupported scope #{procedure.scope.kind}") unless SCOPE_KINDS.includes?(procedure.scope.kind)
      raise ValidationError.new("#{procedure.id} has unsupported scope filter #{procedure.scope.filter}") unless SCOPE_FILTERS.includes?(procedure.scope.filter)
      raise ValidationError.new("#{procedure.id} scope limit must be between 1 and 1000") unless (1..1000).includes?(procedure.scope.limit)
      raise ValidationError.new("#{procedure.id} must reference diagnostics") if procedure.diagnostics.empty?
      procedure.diagnostic_references.each do |reference|
        unless reference.category == "diagnostic" && diagnostics.includes?(reference)
          raise ValidationError.new("#{procedure.id} references missing diagnostic procedure #{reference}")
        end
      end
      unless (60..604_800).includes?(procedure.deduplication_window_seconds)
        raise ValidationError.new("#{procedure.id} deduplication_window_seconds must be between 60 and 604800")
      end
    rescue error : ArgumentError
      raise ValidationError.new("#{procedure.id}: #{error.message}")
    end
  end

  enum MaintenanceRunStatus
    Completed
    Skipped
    Failed
  end

  struct MaintenanceRun
    include JSON::Serializable

    getter id : String
    getter procedure : ProcedureAudit
    getter schedule_bucket : Int64
    getter status : MaintenanceRunStatus
    getter target_count : Int32
    getter incident_ids : Array(String)
    getter classification_counts : Hash(String, Int32)
    getter started_at : Time
    getter completed_at : Time
    getter error : String?

    def initialize(
      @id : String,
      @procedure : ProcedureAudit,
      @schedule_bucket : Int64,
      @status : MaintenanceRunStatus,
      @target_count : Int32,
      @incident_ids : Array(String),
      @classification_counts : Hash(String, Int32),
      @started_at : Time,
      @completed_at : Time,
      @error : String? = nil,
    )
    end
  end

  class MaintenanceRunStore
    @runs = [] of MaintenanceRun
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

    def save(run : MaintenanceRun) : MaintenanceRun
      saved = persist(&.save_maintenance_run(run)) || run
      @lock.synchronize do
        @runs.reject! { |existing| existing.id == saved.id }
        @runs << saved
      end
      saved
    end

    def find_window(procedure : ProcedureReference, bucket : Int64) : MaintenanceRun?
      @lock.synchronize do
        @runs.find { |run| run.procedure.id == procedure.id && run.procedure.version == procedure.version && run.schedule_bucket == bucket }
      end || persist(&.find_maintenance_run(procedure.id, procedure.version, bucket))
    end

    def all : Array(MaintenanceRun)
      persisted = persist(&.all_maintenance_runs)
      return persisted if persisted && !persisted.empty?
      @lock.synchronize { @runs.dup }
    end

    def clear : Nil
      @lock.synchronize { @runs.clear }
    end

    private def persist(& : PostgresIncidentRepository -> T) : T? forall T
      return unless repository = @repository
      yield repository
    rescue error
      @persistence_error = "#{error.class}: #{error.message}"
      AISupportAgent::Log.warn(exception: error) { "maintenance-run persistence failed; continuing with in-memory store" }
      nil
    end
  end

  class MaintenanceRunner
    def initialize(
      @context : PlaceOSContext,
      @store : MaintenanceRunStore,
      @ingest : Proc(IncidentEvent, ProcedureReference, Bool, IncidentReport),
      @incidents : IncidentStore? = nil,
    )
    end

    def self.correlation_key(procedure_id : String, module_id : String, diagnostic_id : String) : String
      "maintenance:#{procedure_id}:#{module_id}:#{diagnostic_id}"
    end

    def run(procedure : MaintenanceProcedure, scheduled_for : Time = Time.utc) : MaintenanceRun
      bucket = procedure.schedule_bucket(scheduled_for)
      if existing = @store.find_window(procedure.reference, bucket)
        return existing
      end

      started_at = Time.utc
      targets = @context.maintenance_targets(procedure.scope)
      reports = targets.flat_map do |target|
        procedure.diagnostic_references.map do |reference|
          @ingest.call(
            IncidentEvent.new(
              source: IncidentSource::Scheduled,
              severity: IncidentSeverity::Warning,
              correlation_key: MaintenanceRunner.correlation_key(procedure.id, target.module_id, reference.id),
              payload: JSON.parse({maintenance_procedure: procedure.id, diagnostic: reference.to_s}.to_json),
              system_id: target.system_id,
              module_id: target.module_id,
              module_name: target.module_name,
              module_index: target.module_index
            ),
            reference,
            procedure.reporting.deliver_reports?
          )
        end
      end
      resolved = resolve_recovered(procedure, targets)
      counts = Hash(String, Int32).new(0)
      reports.each { |report| counts[report.classification.to_s] += 1 }
      @store.save(MaintenanceRun.new(
        id: "maintenance-#{UUID.random}",
        procedure: ProcedureAudit.new("maintenance", procedure.id, procedure.version, procedure.content_hash),
        schedule_bucket: bucket,
        status: MaintenanceRunStatus::Completed,
        target_count: targets.size,
        incident_ids: reports.map(&.incident_id) + resolved.map(&.incident_id),
        classification_counts: counts,
        started_at: started_at,
        completed_at: Time.utc
      ))
    rescue error
      @store.save(MaintenanceRun.new(
        id: "maintenance-#{UUID.random}",
        procedure: ProcedureAudit.new("maintenance", procedure.id, procedure.version, procedure.content_hash),
        schedule_bucket: procedure.schedule_bucket(scheduled_for),
        status: MaintenanceRunStatus::Failed,
        target_count: 0,
        incident_ids: [] of String,
        classification_counts: {} of String => Int32,
        started_at: Time.utc,
        completed_at: Time.utc,
        error: "#{error.class}: #{error.message}"
      ))
    end

    # Resolves this procedure's open incidents whose module is no longer in the target list and, on a
    # direct check, is no longer failing or no longer exists. A module that is still failing stays open.
    private def resolve_recovered(procedure : MaintenanceProcedure, targets : Array(MaintenanceTarget)) : Array(IncidentReport)
      incidents = @incidents
      return [] of IncidentReport unless incidents

      target_ids = targets.map(&.module_id).to_set
      references = procedure.diagnostic_references
      incidents.open_by_correlation_prefix("maintenance:#{procedure.id}:").compact_map do |incident|
        module_id = incident.module_id
        next unless module_id
        next if target_ids.includes?(module_id)
        reference = references.find { |candidate| incident.correlation_key.ends_with?(":#{candidate.id}") } || references.first
        begin
          health = @context.module_health(module_id)
          next if health.failing?
          @ingest.call(
            IncidentEvent.new(
              source: IncidentSource::Scheduled,
              severity: IncidentSeverity::Info,
              correlation_key: incident.correlation_key,
              payload: JSON.parse({
                maintenance_procedure: procedure.id,
                diagnostic:            reference.to_s,
                status:                "resolved",
                module_health:         health.to_s.downcase,
              }.to_json),
              system_id: incident.system_id,
              module_id: module_id,
              module_name: incident.module_name,
              module_index: incident.module_index
            ),
            reference,
            false
          )
        rescue error
          AISupportAgent::Log.warn(exception: error) { "maintenance sweep could not resolve incident #{incident.incident_id} for #{module_id}" }
          nil
        end
      end
    end
  end

  class MaintenanceScheduler
    @tasks = [] of Tasker::Task

    def initialize(@catalog : WorkflowCatalog, @runner : MaintenanceRunner)
    end

    def start : Nil
      return unless @tasks.empty?
      @catalog.maintenance_procedures.each do |procedure|
        location = Time::Location.load(procedure.schedule.timezone)
        @tasks << Tasker.cron(procedure.schedule.cron, location) { @runner.run(procedure) }
      end
    end

    def stop : Nil
      @tasks.each(&.cancel)
      @tasks.clear
    end

    def size : Int32
      @tasks.size
    end
  end
end
