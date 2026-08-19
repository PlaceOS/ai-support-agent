require "digest/sha256"
require "set"
require "uuid"
require "yaml"

module AISupportAgent
  class CorrelationRule
    include YAML::Serializable
    include YAML::Serializable::Strict

    getter? enabled : Bool
    getter window_seconds : Int32
    getter threshold : Int32
  end

  class CorrelationRules
    include YAML::Serializable
    include YAML::Serializable::Strict

    getter repeated_incidents : CorrelationRule
    getter flapping : CorrelationRule
    getter noisy_signals : CorrelationRule
  end

  class CorrelationGrouping
    include YAML::Serializable
    include YAML::Serializable::Strict

    getter dimensions : Array(String)
  end

  class TrendPolicy
    include YAML::Serializable
    include YAML::Serializable::Strict

    getter default_window_seconds : Int32
    getter maximum_window_seconds : Int32
    getter top_modules_limit : Int32
  end

  class CorrelationPolicy
    include YAML::Serializable
    include YAML::Serializable::Strict

    @[YAML::Field(key: "$schema")]
    getter schema_uri : String? = nil
    getter schema_version : String
    getter id : String
    getter version : Int32
    getter name : String
    getter? default : Bool
    getter grouping : CorrelationGrouping
    getter rules : CorrelationRules
    getter trends : TrendPolicy

    @[YAML::Field(ignore: true)]
    property content_hash : String = ""

    def reference : ProcedureReference
      ProcedureReference.new("correlation", id, version)
    end
  end

  class CorrelationPolicyRegistry
    SCHEMA_VERSION = "correlation-policy.v1"

    class Error < Exception
    end

    class ValidationError < Error
    end

    getter path : String

    def self.load(path : String) : CorrelationPolicyRegistry
      raise ValidationError.new("correlation directory not found: #{path}") unless Dir.exists?(path)
      files = (Dir.glob(File.join(path, "**", "*.yml")) + Dir.glob(File.join(path, "**", "*.yaml"))).sort
      raise ValidationError.new("no correlation policies found in #{path}") if files.empty?
      policies = files.map do |file|
        contents = File.read(file)
        policy = CorrelationPolicy.from_yaml(contents)
        unless policy.schema_version == SCHEMA_VERSION
          raise ValidationError.new("unsupported correlation schema_version #{policy.schema_version} in #{file}")
        end
        policy.content_hash = Digest::SHA256.hexdigest(contents)
        policy
      rescue error : YAML::ParseException
        raise ValidationError.new("invalid correlation YAML in #{file}: #{error.message}")
      end
      new(path, policies).tap(&.validate!)
    end

    private def initialize(@path : String, @policies : Array(CorrelationPolicy))
    end

    def size : Int32
      @policies.size
    end

    def default : CorrelationPolicy
      @policies.find(&.default?) || raise Error.new("no default correlation policy")
    end

    protected def policies_snapshot : Array(CorrelationPolicy)
      @policies.dup
    end

    protected def validate! : Nil
      identities = Set(String).new
      defaults = 0
      @policies.each do |policy|
        identity = "#{policy.id}:#{policy.version}"
        raise ValidationError.new("duplicate correlation policy #{identity}") unless identities.add?(identity)
        validate(policy)
        defaults += 1 if policy.default?
      end
      raise ValidationError.new("exactly one default correlation policy is required") unless defaults == 1
    end

    private def validate(policy : CorrelationPolicy) : Nil
      raise ValidationError.new("invalid correlation policy id #{policy.id}") unless policy.id.matches?(/\A[a-z0-9]+(?:-[a-z0-9]+)*\z/)
      raise ValidationError.new("#{policy.id} version must be positive") unless policy.version > 0
      raise ValidationError.new("#{policy.id} name is required") if policy.name.blank?
      allowed_dimensions = ["tenant_id", "system_id", "module_id", "classification"]
      dimensions = policy.grouping.dimensions
      if dimensions.empty? || dimensions.uniq.size != dimensions.size || dimensions.any? { |dimension| !allowed_dimensions.includes?(dimension) }
        raise ValidationError.new("#{policy.id} has invalid correlation grouping dimensions")
      end
      unless dimensions.includes?("classification")
        raise ValidationError.new("#{policy.id} correlation grouping must include classification")
      end
      rules = [policy.rules.repeated_incidents, policy.rules.flapping, policy.rules.noisy_signals]
      rules.each do |rule|
        unless (60..2_678_400).includes?(rule.window_seconds)
          raise ValidationError.new("#{policy.id} rule window_seconds must be between 60 and 2678400")
        end
        unless (2..10_000).includes?(rule.threshold)
          raise ValidationError.new("#{policy.id} rule threshold must be between 2 and 10000")
        end
      end
      trends = policy.trends
      unless (300..2_678_400).includes?(trends.default_window_seconds)
        raise ValidationError.new("#{policy.id} default trend window must be between 300 and 2678400")
      end
      unless (trends.default_window_seconds..2_678_400).includes?(trends.maximum_window_seconds)
        raise ValidationError.new("#{policy.id} maximum trend window must include the default window")
      end
      unless (1..100).includes?(trends.top_modules_limit)
        raise ValidationError.new("#{policy.id} top_modules_limit must be between 1 and 100")
      end
    end
  end

  struct IncidentObservation
    include JSON::Serializable

    getter incident_id : String
    getter correlation_key : String
    getter status : IncidentStatus
    getter classification : DiagnosticClassification
    getter source : IncidentSource
    getter tenant_id : String?
    getter system_id : String?
    getter module_id : String?
    getter module_name : String?
    getter observed_at : Time

    def self.from(report : IncidentReport, observed_at : Time = Time.utc) : IncidentObservation
      new(
        report.incident_id,
        report.correlation_key,
        report.status,
        report.classification,
        report.source,
        report.tenant_id,
        report.system_id,
        report.module_id,
        report.module_name,
        observed_at
      )
    end

    def initialize(
      @incident_id : String,
      @correlation_key : String,
      @status : IncidentStatus,
      @classification : DiagnosticClassification,
      @source : IncidentSource,
      @tenant_id : String?,
      @system_id : String?,
      @module_id : String?,
      @module_name : String?,
      @observed_at : Time,
    )
    end

    def group_key(grouping : CorrelationGrouping) : String
      values = {} of String => String
      grouping.dimensions.each do |dimension|
        value = case dimension
                when "tenant_id"      then tenant_id
                when "system_id"      then system_id
                when "module_id"      then module_id
                when "classification" then classification.to_s
                end
        values[dimension] = value if value
      end
      values["correlation_key"] = correlation_key if values.keys.all?(&.==("classification"))
      "group:#{Digest::SHA256.hexdigest(values.to_json)}"
    end

    def active? : Bool
      !status.resolved?
    end
  end

  enum CorrelationKind
    RepeatedIncident
    Flapping
    NoisySignals

    def key : String
      case self
      in .repeated_incident? then "repeated_incident"
      in .flapping?          then "flapping"
      in .noisy_signals?     then "noisy_signals"
      end
    end
  end

  struct CorrelationFinding
    include JSON::Serializable

    getter id : String
    getter deduplication_key : String
    getter kind : CorrelationKind
    getter policy : ProcedureAudit
    getter scope_key : String
    getter tenant_id : String?
    getter system_id : String?
    getter module_id : String?
    getter classification : DiagnosticClassification
    getter incident_ids : Array(String)
    getter observation_count : Int32
    getter transition_count : Int32
    getter window_start : Time
    getter window_end : Time
    getter summary : String
    getter created_at : Time

    def initialize(
      @id : String,
      @deduplication_key : String,
      @kind : CorrelationKind,
      @policy : ProcedureAudit,
      @scope_key : String,
      @tenant_id : String?,
      @system_id : String?,
      @module_id : String?,
      @classification : DiagnosticClassification,
      @incident_ids : Array(String),
      @observation_count : Int32,
      @transition_count : Int32,
      @window_start : Time,
      @window_end : Time,
      @summary : String,
      @created_at : Time,
    )
    end
  end

  class CorrelationFindingStore
    @findings = [] of CorrelationFinding
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

    def save(finding : CorrelationFinding) : CorrelationFinding
      saved = persist(&.save_correlation_finding(finding)) || finding
      @lock.synchronize do
        @findings.reject! { |existing| existing.deduplication_key == saved.deduplication_key }
        @findings << saved
      end
      saved
    end

    def find_by_key(key : String) : CorrelationFinding?
      @lock.synchronize { @findings.find(&.deduplication_key.==(key)) } ||
        persist(&.find_correlation_finding(key))
    end

    def all : Array(CorrelationFinding)
      persisted = persist(&.all_correlation_findings)
      return persisted if persisted && !persisted.empty?
      @lock.synchronize { @findings.dup }
    end

    def since(time : Time) : Array(CorrelationFinding)
      all.select { |finding| finding.created_at >= time }
    end

    def clear : Nil
      @lock.synchronize { @findings.clear }
    end

    private def persist(& : PostgresIncidentRepository -> T) : T? forall T
      return unless repository = @repository
      yield repository
    rescue error
      @persistence_error = "#{error.class}: #{error.message}"
      AISupportAgent::Log.warn(exception: error) { "correlation persistence failed; continuing with in-memory store" }
      nil
    end
  end

  enum FeedbackRating
    Helpful
    Incorrect
    Incomplete

    def key : String
      to_s.downcase
    end

    def self.from_api(value : String) : FeedbackRating
      case value.downcase
      when "helpful"    then Helpful
      when "incorrect"  then Incorrect
      when "incomplete" then Incomplete
      else                   raise ArgumentError.new("unsupported feedback rating #{value.inspect}")
      end
    end
  end

  struct IncidentFeedback
    include JSON::Serializable

    getter id : String
    getter incident_id : String
    getter rating : FeedbackRating
    getter submitted_by : String
    getter comment : String?
    getter created_at : Time

    def initialize(
      @id : String,
      @incident_id : String,
      @rating : FeedbackRating,
      @submitted_by : String,
      @comment : String?,
      @created_at : Time,
    )
    end
  end

  class IncidentFeedbackStore
    class Error < Exception
    end

    @feedback = [] of IncidentFeedback
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

    def create(incident_id : String, rating : FeedbackRating, submitted_by : String, comment : String? = nil) : IncidentFeedback
      raise Error.new("submitted_by is required") if submitted_by.blank?
      record = IncidentFeedback.new(
        id: "feedback-#{UUID.random}",
        incident_id: incident_id,
        rating: rating,
        submitted_by: submitted_by,
        comment: comment.try(&.presence),
        created_at: Time.utc
      )
      save(record)
    end

    def save(record : IncidentFeedback) : IncidentFeedback
      saved = persist(&.save_incident_feedback(record)) || record
      @lock.synchronize do
        @feedback.reject! { |existing| existing.id == saved.id }
        @feedback << saved
      end
      saved
    end

    def for_incident(incident_id : String) : Array(IncidentFeedback)
      persisted = persist(&.incident_feedback_for(incident_id))
      return persisted if persisted && !persisted.empty?
      @lock.synchronize { @feedback.select(&.incident_id.==(incident_id)) }
    end

    def all : Array(IncidentFeedback)
      persisted = persist(&.all_incident_feedback)
      return persisted if persisted && !persisted.empty?
      @lock.synchronize { @feedback.dup }
    end

    def clear : Nil
      @lock.synchronize { @feedback.clear }
    end

    private def persist(& : PostgresIncidentRepository -> T) : T? forall T
      return unless repository = @repository
      yield repository
    rescue error
      @persistence_error = "#{error.class}: #{error.message}"
      AISupportAgent::Log.warn(exception: error) { "incident-feedback persistence failed; continuing with in-memory store" }
      nil
    end
  end

  struct TrendCount
    include JSON::Serializable

    getter key : String
    getter count : Int32

    def initialize(@key : String, @count : Int32)
    end
  end

  struct TrendSummary
    include JSON::Serializable

    getter window_start : Time
    getter window_end : Time
    getter observation_count : Int32
    getter incident_count : Int32
    getter classification_counts : Hash(String, Int32)
    getter status_counts : Hash(String, Int32)
    getter source_counts : Hash(String, Int32)
    getter finding_counts : Hash(String, Int32)
    getter feedback_counts : Hash(String, Int32)
    getter top_modules : Array(TrendCount)

    def initialize(
      @window_start : Time,
      @window_end : Time,
      @observation_count : Int32,
      @incident_count : Int32,
      @classification_counts : Hash(String, Int32),
      @status_counts : Hash(String, Int32),
      @source_counts : Hash(String, Int32),
      @finding_counts : Hash(String, Int32),
      @feedback_counts : Hash(String, Int32),
      @top_modules : Array(TrendCount),
    )
    end
  end

  struct TrendReport
    include JSON::Serializable

    getter id : String
    getter policy : ProcedureAudit
    getter summary : TrendSummary
    getter markdown : String
    getter generated_at : Time

    def initialize(
      @id : String,
      @policy : ProcedureAudit,
      @summary : TrendSummary,
      @markdown : String,
      @generated_at : Time,
    )
    end
  end

  class TrendReportStore
    @reports = [] of TrendReport
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

    def save(report : TrendReport) : TrendReport
      saved = persist(&.save_trend_report(report)) || report
      @lock.synchronize do
        @reports.reject! { |existing| existing.id == saved.id }
        @reports << saved
      end
      saved
    end

    def find(id : String) : TrendReport?
      @lock.synchronize { @reports.find(&.id.==(id)) } || persist(&.find_trend_report(id))
    end

    def all : Array(TrendReport)
      persisted = persist(&.all_trend_reports)
      return persisted if persisted && !persisted.empty?
      @lock.synchronize { @reports.dup }
    end

    def clear : Nil
      @lock.synchronize { @reports.clear }
    end

    private def persist(& : PostgresIncidentRepository -> T) : T? forall T
      return unless repository = @repository
      yield repository
    rescue error
      @persistence_error = "#{error.class}: #{error.message}"
      AISupportAgent::Log.warn(exception: error) { "trend-report persistence failed; continuing with in-memory store" }
      nil
    end
  end

  class CorrelationEngine
    def initialize(
      @catalog : WorkflowCatalog,
      @incidents : IncidentStore,
      @findings : CorrelationFindingStore,
    )
    end

    def evaluate(report : IncidentReport, at : Time = Time.utc) : Array(CorrelationFinding)
      policy = @catalog.correlation_policy
      observation = IncidentObservation.from(report, at)
      findings = [] of CorrelationFinding
      evaluate_repeated(policy, observation, at).try { |finding| findings << finding }
      evaluate_flapping(policy, observation, at).try { |finding| findings << finding }
      evaluate_noisy(policy, observation, at).try { |finding| findings << finding }
      findings
    end

    private def evaluate_repeated(policy : CorrelationPolicy, observation : IncidentObservation, at : Time) : CorrelationFinding?
      rule = policy.rules.repeated_incidents
      return unless rule.enabled?
      observations, window_start, window_end = scoped_observations(policy, observation, rule, at)
      incident_ids = observations.map(&.incident_id).uniq!
      return if incident_ids.size < rule.threshold
      finding(policy, CorrelationKind::RepeatedIncident, observation, incident_ids, observations.size, 0, window_start, window_end)
    end

    private def evaluate_flapping(policy : CorrelationPolicy, observation : IncidentObservation, at : Time) : CorrelationFinding?
      rule = policy.rules.flapping
      return unless rule.enabled?
      observations, window_start, window_end = scoped_observations(policy, observation, rule, at)
      transitions = status_transitions(observations)
      return if transitions < rule.threshold
      finding(policy, CorrelationKind::Flapping, observation, observations.map(&.incident_id).uniq!, observations.size, transitions, window_start, window_end)
    end

    private def evaluate_noisy(policy : CorrelationPolicy, observation : IncidentObservation, at : Time) : CorrelationFinding?
      rule = policy.rules.noisy_signals
      return unless rule.enabled?
      observations, window_start, window_end = scoped_observations(policy, observation, rule, at)
      return if observations.size < rule.threshold
      finding(policy, CorrelationKind::NoisySignals, observation, observations.map(&.incident_id).uniq!, observations.size, 0, window_start, window_end)
    end

    private def scoped_observations(policy : CorrelationPolicy, observation : IncidentObservation, rule : CorrelationRule, at : Time) : Tuple(Array(IncidentObservation), Time, Time)
      bucket = at.to_unix // rule.window_seconds
      window_start = Time.unix(bucket * rule.window_seconds)
      window_end = window_start + rule.window_seconds.seconds
      observations = @incidents.observations_since(window_start).select do |candidate|
        candidate.observed_at < window_end && candidate.group_key(policy.grouping) == observation.group_key(policy.grouping)
      end
      {observations.sort_by!(&.observed_at), window_start, window_end}
    end

    private def status_transitions(observations : Array(IncidentObservation)) : Int32
      previous : Bool? = nil
      transitions = 0
      observations.each do |observation|
        active = observation.active?
        transitions += 1 if !previous.nil? && previous != active
        previous = active
      end
      transitions
    end

    private def finding(
      policy : CorrelationPolicy,
      kind : CorrelationKind,
      observation : IncidentObservation,
      incident_ids : Array(String),
      observation_count : Int32,
      transition_count : Int32,
      window_start : Time,
      window_end : Time,
    ) : CorrelationFinding
      group_key = observation.group_key(policy.grouping)
      key_source = "#{policy.reference}:#{kind}:#{group_key}:#{window_start.to_unix}"
      key = Digest::SHA256.hexdigest(key_source)
      if existing = @findings.find_by_key(key)
        return existing
      end
      @findings.save(CorrelationFinding.new(
        id: "correlation-#{UUID.random}",
        deduplication_key: key,
        kind: kind,
        policy: ProcedureAudit.new("correlation", policy.id, policy.version, policy.content_hash),
        scope_key: group_key,
        tenant_id: observation.tenant_id,
        system_id: observation.system_id,
        module_id: observation.module_id,
        classification: observation.classification,
        incident_ids: incident_ids,
        observation_count: observation_count,
        transition_count: transition_count,
        window_start: window_start,
        window_end: window_end,
        summary: finding_summary(kind, observation_count, transition_count, incident_ids.size),
        created_at: Time.utc
      ))
    end

    private def finding_summary(kind : CorrelationKind, observations : Int32, transitions : Int32, incidents : Int32) : String
      case kind
      in .repeated_incident? then "#{incidents} related incidents occurred in the correlation window"
      in .flapping?          then "#{transitions} active/resolved transitions occurred in the correlation window"
      in .noisy_signals?     then "#{observations} related signals occurred in the correlation window"
      end
    end
  end

  class TrendReporter
    def initialize(
      @catalog : WorkflowCatalog,
      @incidents : IncidentStore,
      @findings : CorrelationFindingStore,
      @feedback : IncidentFeedbackStore,
      @reports : TrendReportStore,
    )
    end

    def summary(window_seconds : Int32? = nil, at : Time = Time.utc) : TrendSummary
      trends = @catalog.correlation_policy.trends
      window = window_seconds || trends.default_window_seconds
      unless (300..trends.maximum_window_seconds).includes?(window)
        raise ArgumentError.new("window_seconds must be between 300 and #{trends.maximum_window_seconds}")
      end
      window_start = at - window.seconds
      observations = @incidents.observations_since(window_start).select { |observation| observation.observed_at <= at }
      findings = @findings.since(window_start).select { |finding| finding.created_at <= at }
      feedback = @feedback.all.select { |record| record.created_at >= window_start && record.created_at <= at }
      module_counts = count(observations.compact_map(&.module_id))
      top_modules = module_counts.to_a.sort_by { |key, value| {-value, key} }.first(trends.top_modules_limit).map do |key, value|
        TrendCount.new(key, value)
      end
      TrendSummary.new(
        window_start: window_start,
        window_end: at,
        observation_count: observations.size,
        incident_count: observations.map(&.incident_id).uniq!.size,
        classification_counts: count(observations.map(&.classification.to_s)),
        status_counts: count(observations.map(&.status.to_s.downcase)),
        source_counts: count(observations.map(&.source.to_s.downcase)),
        finding_counts: count(findings.map(&.kind.key)),
        feedback_counts: count(feedback.map(&.rating.key)),
        top_modules: top_modules
      )
    end

    def generate(window_seconds : Int32? = nil, at : Time = Time.utc) : TrendReport
      policy = @catalog.correlation_policy
      summary = summary(window_seconds, at)
      @reports.save(TrendReport.new(
        id: "trend-#{UUID.random}",
        policy: ProcedureAudit.new("correlation", policy.id, policy.version, policy.content_hash),
        summary: summary,
        markdown: markdown(summary),
        generated_at: at
      ))
    end

    private def count(values : Array(String)) : Hash(String, Int32)
      counts = Hash(String, Int32).new(0)
      values.each { |value| counts[value] += 1 }
      counts
    end

    private def markdown(summary : TrendSummary) : String
      String.build do |io|
        io << "# Incident Trend Report\n\n"
        io << "- Window Start: " << summary.window_start.to_rfc3339 << '\n'
        io << "- Window End: " << summary.window_end.to_rfc3339 << '\n'
        io << "- Observations: " << summary.observation_count << '\n'
        io << "- Incidents: " << summary.incident_count << "\n\n"
        markdown_counts(io, "Classifications", summary.classification_counts)
        markdown_counts(io, "Correlation Findings", summary.finding_counts)
        markdown_counts(io, "Operator Feedback", summary.feedback_counts)
        io << "## Top Modules\n\n"
        if summary.top_modules.empty?
          io << "- None recorded.\n"
        else
          summary.top_modules.each { |item| io << "- " << item.key << ": " << item.count << '\n' }
        end
      end
    end

    private def markdown_counts(io : IO, title : String, counts : Hash(String, Int32)) : Nil
      io << "## " << title << "\n\n"
      if counts.empty?
        io << "- None recorded.\n\n"
      else
        counts.to_a.sort_by(&.[0]).each { |key, value| io << "- " << key << ": " << value << '\n' }
        io << '\n'
      end
    end
  end
end
