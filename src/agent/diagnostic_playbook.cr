require "digest/sha256"
require "yaml"

module AISupportAgent
  struct AgentAnalysis
    include JSON::Serializable

    getter summary : String
    getter next_steps : Array(String)
    getter confidence : Float64?

    def initialize(
      @summary : String,
      @next_steps : Array(String) = [] of String,
      @confidence : Float64? = nil,
    )
    end
  end

  struct AgentDecision
    include JSON::Serializable

    getter observed_facts : Array(String)
    getter hypotheses : Array(String)
    getter ruled_out : Array(String)
    getter? escalation_required : Bool
    getter recommended_action : String
    getter remediation_boundary : String

    def initialize(
      @observed_facts : Array(String),
      @hypotheses : Array(String),
      @ruled_out : Array(String),
      @escalation_required : Bool,
      @recommended_action : String,
      @remediation_boundary : String = "Report-only mode: no remediation attempted.",
    )
    end
  end

  struct RemediationProposal
    include JSON::Serializable

    getter action : String
    getter risk_level : String
    getter? approval_required : Bool
    getter execution_mode : String
    getter policy_basis : String
    getter verification_plan : Array(String)
    getter verification_procedure : String?

    def initialize(
      @action : String,
      @risk_level : String,
      @approval_required : Bool,
      @execution_mode : String,
      @policy_basis : String,
      @verification_plan : Array(String),
      @verification_procedure : String? = nil,
    )
    end
  end

  class PlaybookStep
    include JSON::Serializable
    include YAML::Serializable
    include YAML::Serializable::Strict

    TOOL_CONTEXT = {
      "module_details"        => ["module_id"],
      "module_state"          => ["module_id"],
      "module_error_logs"     => ["module_id"],
      "debug_or_error_logs"   => ["module_id"],
      "system_details"        => ["system_id"],
      "core_loaded_processes" => ["module_id"],
    }

    getter id : String
    getter tool : String
    getter io_timeout_seconds : Int32 = 10
    getter depends_on : Array(String) = [] of String
    getter requires : Array(String) = [] of String

    def initialize(
      @id : String,
      @tool : String,
      @io_timeout_seconds : Int32 = 10,
      @depends_on : Array(String) = [] of String,
      @requires : Array(String) = [] of String,
    )
    end

    def self.required_context(tool : String) : Array(String)
      TOOL_CONTEXT[tool]? || [] of String
    end

    def context_satisfied?(event : IncidentEvent) : Bool
      requires.all? { |field| DiagnosticProcedure.context_present?(field, event) }
    end
  end

  struct ProcedureAudit
    include JSON::Serializable

    getter category : String
    getter id : String
    getter version : Int32
    getter content_hash : String

    def initialize(@category : String, @id : String, @version : Int32, @content_hash : String)
    end
  end

  struct InvestigationPlan
    include JSON::Serializable

    SCHEMA_VERSION = "investigation-plan.v1"

    getter schema_version : String = SCHEMA_VERSION
    getter goal : String
    getter evidence_targets : Array(String)
    getter confidence_threshold : Float64
    getter max_iterations : Int32
    getter playbook_id : String?
    getter playbook_version : Int32?
    getter playbook_hash : String?
    getter workflow_id : String?
    getter workflow_version : Int32?
    getter workflow_hash : String?
    getter workflow_stage : String?
    getter steps : Array(PlaybookStep)
    getter procedures : Array(ProcedureAudit)
    getter escalation : EscalationPlan?

    def initialize(
      @goal : String,
      @evidence_targets : Array(String),
      @confidence_threshold : Float64 = 0.65,
      @max_iterations : Int32 = 2,
      @playbook_id : String? = nil,
      @playbook_version : Int32? = nil,
      @playbook_hash : String? = nil,
      @steps : Array(PlaybookStep) = [] of PlaybookStep,
      @schema_version : String = SCHEMA_VERSION,
      @workflow_id : String? = nil,
      @workflow_version : Int32? = nil,
      @workflow_hash : String? = nil,
      @workflow_stage : String? = nil,
      @procedures : Array(ProcedureAudit) = [] of ProcedureAudit,
      @escalation : EscalationPlan? = nil,
    )
    end

    def with_additional_targets(targets : Array(String)) : InvestigationPlan
      InvestigationPlan.new(
        goal: goal,
        evidence_targets: (evidence_targets + targets).uniq,
        confidence_threshold: confidence_threshold,
        max_iterations: max_iterations,
        playbook_id: playbook_id,
        playbook_version: playbook_version,
        playbook_hash: playbook_hash,
        steps: steps,
        schema_version: schema_version,
        workflow_id: workflow_id,
        workflow_version: workflow_version,
        workflow_hash: workflow_hash,
        workflow_stage: workflow_stage,
        procedures: procedures,
        escalation: escalation
      )
    end

    def with_workflow(workflow : WorkflowPlaybook, stage : String) : InvestigationPlan
      InvestigationPlan.new(
        goal: goal,
        evidence_targets: evidence_targets,
        confidence_threshold: confidence_threshold,
        max_iterations: max_iterations,
        playbook_id: playbook_id,
        playbook_version: playbook_version,
        playbook_hash: playbook_hash,
        steps: steps,
        schema_version: schema_version,
        workflow_id: workflow.id,
        workflow_version: workflow.version,
        workflow_hash: workflow.content_hash,
        workflow_stage: stage,
        procedures: procedures,
        escalation: escalation
      )
    end

    def with_procedure(reference : ProcedureReference, content_hash : String) : InvestigationPlan
      audit = ProcedureAudit.new(reference.category, reference.id, reference.version, content_hash)
      InvestigationPlan.new(
        goal: goal,
        evidence_targets: evidence_targets,
        confidence_threshold: confidence_threshold,
        max_iterations: max_iterations,
        playbook_id: playbook_id,
        playbook_version: playbook_version,
        playbook_hash: playbook_hash,
        steps: steps,
        schema_version: schema_version,
        workflow_id: workflow_id,
        workflow_version: workflow_version,
        workflow_hash: workflow_hash,
        workflow_stage: workflow_stage,
        procedures: (procedures + [audit]).uniq { |procedure| {procedure.category, procedure.id, procedure.version} },
        escalation: escalation
      )
    end

    def with_escalation(plan : EscalationPlan) : InvestigationPlan
      procedures_with_escalation = (procedures + [plan.procedure]).uniq do |procedure|
        {procedure.category, procedure.id, procedure.version}
      end
      InvestigationPlan.new(
        goal: goal,
        evidence_targets: evidence_targets,
        confidence_threshold: confidence_threshold,
        max_iterations: max_iterations,
        playbook_id: playbook_id,
        playbook_version: playbook_version,
        playbook_hash: playbook_hash,
        steps: steps,
        schema_version: schema_version,
        workflow_id: workflow_id,
        workflow_version: workflow_version,
        workflow_hash: workflow_hash,
        workflow_stage: workflow_stage,
        procedures: procedures_with_escalation,
        escalation: plan
      )
    end

    protected def after_initialize : Nil
      return if schema_version == SCHEMA_VERSION

      raise ArgumentError.new("unsupported investigation plan schema #{schema_version}")
    end
  end

  struct DiagnosticToolResult
    getter target : String
    getter evidence : Array(Evidence)
    getter summary : String

    def initialize(
      @target : String,
      @evidence : Array(Evidence),
      @summary : String,
      @execution_status : InvestigationStepStatus? = nil,
    )
    end

    def status : InvestigationStepStatus
      @execution_status || (evidence.empty? ? InvestigationStepStatus::Skipped : InvestigationStepStatus::Completed)
    end
  end

  struct AgentRun
    include JSON::Serializable

    getter incident_id : String
    getter correlation_key : String
    getter classification : DiagnosticClassification
    getter confidence : Float64
    getter investigation_plan : InvestigationPlan?
    getter investigation : Array(InvestigationStep)
    getter decision : AgentDecision?
    getter remediation_proposal : RemediationProposal?
    getter created_at : Time

    def initialize(
      @incident_id : String,
      @correlation_key : String,
      @classification : DiagnosticClassification,
      @confidence : Float64,
      @investigation_plan : InvestigationPlan?,
      @investigation : Array(InvestigationStep),
      @decision : AgentDecision?,
      @remediation_proposal : RemediationProposal?,
      @created_at : Time,
    )
    end

    def self.from_report(report : IncidentReport) : AgentRun
      new(
        incident_id: report.incident_id,
        correlation_key: report.correlation_key,
        classification: report.classification,
        confidence: report.confidence,
        investigation_plan: report.investigation_plan,
        investigation: report.investigation,
        decision: report.decision,
        remediation_proposal: report.remediation_proposal,
        created_at: report.created_at
      )
    end
  end

  class AgentRunStore
    @runs = {} of String => AgentRun
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

    def save(report : IncidentReport) : AgentRun
      run = AgentRun.from_report(report)
      persist(&.save_run(run))
      @lock.synchronize { @runs[run.incident_id] = run }
      run
    end

    def find(id : String) : AgentRun?
      @lock.synchronize { @runs[id]? } || persist(&.find_run(id))
    end

    def all : Array(AgentRun)
      persist(&.all_runs) || @lock.synchronize { @runs.values.sort_by!(&.created_at) }
    end

    def clear : Nil
      @lock.synchronize { @runs.clear }
    end

    private def persist(& : PostgresIncidentRepository -> T) : T? forall T
      return unless repository = @repository

      yield repository
    rescue error
      @persistence_error = "#{error.class}: #{error.message}"
      AISupportAgent::Log.warn(exception: error) { "agent-run persistence failed; continuing with in-memory store" }
      nil
    end
  end

  class PlaybookMatch
    include YAML::Serializable
    include YAML::Serializable::Strict

    getter patterns : Array(String) = [] of String
    getter sources : Array(String) = [] of String
    getter required_context : Array(String) = [] of String
    getter? fallback : Bool = false

    @[YAML::Field(ignore: true)]
    @compiled_patterns = [] of Regex

    def compile_patterns! : Nil
      @compiled_patterns = patterns.map { |pattern| Regex.new(pattern) }
    end

    def matches?(event : IncidentEvent, payload : JSON::Any) : Bool
      return false unless sources.empty? || sources.includes?(source_key(event.source))
      return false unless required_context.all? { |field| DiagnosticProcedure.context_present?(field, event) }
      return fallback? if patterns.empty?

      @compiled_patterns.any?(&.matches?(payload.to_json))
    end

    private def source_key(source : IncidentSource) : String
      case source
      in .grafana?      then "grafana"
      in .webhook?      then "webhook"
      in .module_state? then "module_state"
      in .scheduled?    then "scheduled"
      end
    end
  end

  class PlaybookAnalysis
    include YAML::Serializable
    include YAML::Serializable::Strict

    getter hypotheses : Array(String)
    getter ruled_out : Array(String)
    getter initial_confidence : Float64
    getter minimum_confidence : Float64 = 0.65
    getter escalate_below : Float64 = 0.5
    getter max_iterations : Int32 = 2
    getter fallback_tools : Array(String) = [] of String
  end

  class DiagnosticGuidance
    include YAML::Serializable
    include YAML::Serializable::Strict

    getter summary : String
    getter operator_steps : Array(String)
  end

  class DiagnosticProcedure
    include YAML::Serializable
    include YAML::Serializable::Strict

    @[YAML::Field(key: "$schema")]
    getter schema_uri : String? = nil
    getter schema_version : String
    getter id : String
    @[YAML::Field(key: "classification")]
    getter classification_name : String
    getter version : Int32
    getter name : String
    getter mode : String
    getter priority : Int32 = 0
    getter matches : PlaybookMatch
    getter steps : Array(PlaybookStep)
    getter analysis : PlaybookAnalysis
    getter guidance : DiagnosticGuidance

    @[YAML::Field(ignore: true)]
    property content_hash : String = ""

    def classification : DiagnosticClassification
      DiagnosticClassification.parse(classification_name)
    end

    def reference : ProcedureReference
      ProcedureReference.new("diagnostic", id, version)
    end

    def applicable?(event : IncidentEvent, payload : JSON::Any) : Bool
      matches.matches?(event, payload)
    end

    def plan(event : IncidentEvent) : InvestigationPlan
      target = event.module_name || event.module_id || event.system_id || event.correlation_key
      InvestigationPlan.new(
        goal: "Diagnose #{name} incident for #{target}",
        evidence_targets: steps.map(&.tool),
        confidence_threshold: analysis.minimum_confidence,
        max_iterations: analysis.max_iterations,
        playbook_id: id,
        playbook_version: version,
        playbook_hash: content_hash,
        steps: steps,
        procedures: [ProcedureAudit.new("diagnostic", id, version, content_hash)]
      )
    end

    def fallback_steps(executed_tools : Array(String)) : Array(PlaybookStep)
      analysis.fallback_tools.reject { |tool| executed_tools.includes?(tool) }.map do |tool|
        PlaybookStep.new(
          id: "fallback-#{tool}",
          tool: tool,
          requires: PlaybookStep.required_context(tool)
        )
      end
    end

    def decision(classification : DiagnosticClassification, evidence : Array(Evidence), confidence : Float64) : AgentDecision
      AgentDecision.new(
        observed_facts: observed_facts(classification, evidence, confidence),
        hypotheses: analysis.hypotheses,
        ruled_out: analysis.ruled_out,
        escalation_required: confidence < analysis.escalate_below || matches.fallback?,
        recommended_action: guidance.summary
      )
    end

    def self.context_present?(field : String, event : IncidentEvent) : Bool
      case field
      when "tenant_id"    then !event.tenant_id.presence.nil?
      when "system_id"    then !event.system_id.presence.nil?
      when "module_id"    then !event.module_id.presence.nil?
      when "module_name"  then !event.module_name.presence.nil?
      when "module_index" then !event.module_index.nil?
      else                     false
      end
    end

    private def observed_facts(classification : DiagnosticClassification, evidence : Array(Evidence), confidence : Float64) : Array(String)
      facts = [
        "Playbook: #{id} v#{version}",
        "Classification: #{classification}",
        "Confidence: #{confidence}",
        "Evidence items collected: #{evidence.size}",
      ]

      sources = evidence.map(&.source).uniq!
      facts << "Evidence sources: #{sources.join(", ")}" unless sources.empty?
      facts
    end
  end

  class DiagnosticProcedureRegistry
    SCHEMA_VERSION   = "diagnostic-procedure.v1"
    DEFAULT_PATH     = "playbooks/diagnostics"
    SOURCE_PATH      = File.expand_path("../../playbooks/diagnostics", __DIR__)
    DIAGNOSTIC_TOOLS = PlaybookStep::TOOL_CONTEXT.keys
    CONTEXT_FIELDS   = ["tenant_id", "system_id", "module_id", "module_name", "module_index"]
    SOURCES          = ["grafana", "webhook", "module_state", "scheduled"]

    class Error < Exception
    end

    class ValidationError < Error
    end

    getter path : String
    getter loaded_at : Time
    @fingerprint : String
    @reload_error : String?
    @lock = Mutex.new
    @reload_lock = Mutex.new

    def self.from_environment : DiagnosticProcedureRegistry
      if path = ENV["PLAYBOOKS_PATH"]?.presence
        return load(path)
      end

      paths = [DEFAULT_PATH]
      if executable = Process.executable_path
        paths << File.join(File.dirname(executable), DEFAULT_PATH)
      end
      paths << SOURCE_PATH

      load(paths.find { |candidate| !playbook_files(candidate).empty? } || DEFAULT_PATH)
    end

    def self.load(path : String, live_reload : Bool = true) : DiagnosticProcedureRegistry
      raise ValidationError.new("playbook directory not found: #{path}") unless Dir.exists?(path)

      files = playbook_files(path)
      raise ValidationError.new("no YAML playbooks found in #{path}") if files.empty?

      playbooks = files.map do |file|
        contents = File.read(file)
        playbook = DiagnosticProcedure.from_yaml(contents)
        unless playbook.schema_version == SCHEMA_VERSION
          raise ValidationError.new("unsupported schema_version #{playbook.schema_version} in #{file}")
        end
        playbook.content_hash = Digest::SHA256.hexdigest(contents)
        playbook
      rescue error : YAML::ParseException
        raise ValidationError.new("invalid playbook YAML in #{file}: #{error.message}")
      end

      new(path, playbooks, live_reload: live_reload).tap(&.validate!)
    end

    private def self.playbook_files(path : String) : Array(String)
      return [] of String unless Dir.exists?(path)

      (Dir.glob(File.join(path, "**", "*.yml")) + Dir.glob(File.join(path, "**", "*.yaml"))).sort
    end

    private def initialize(
      @path : String,
      @playbooks : Array(DiagnosticProcedure),
      @loaded_at : Time = Time.utc,
      @live_reload : Bool = true,
    )
      @fingerprint = self.class.fingerprint(path)
    end

    def size : Int32
      refresh_if_changed if @live_reload
      @lock.synchronize { @playbooks.size }
    end

    def reload_error : String?
      @lock.synchronize { @reload_error }
    end

    def select(
      event : IncidentEvent,
      payload : JSON::Any,
      allowed : Array(ProcedureReference)? = nil,
    ) : DiagnosticProcedure
      refresh_if_changed if @live_reload
      @lock.synchronize do
        candidates = if references = allowed
                       @playbooks.select { |procedure| references.includes?(procedure.reference) }
                     else
                       @playbooks
                     end
        applicable = candidates.reject(&.matches.fallback?).select(&.applicable?(event, payload))
        applicable = candidates.select(&.applicable?(event, payload)) if applicable.empty?
        applicable.sort_by! { |playbook| {playbook.priority, playbook.version, playbook.id} }.last? ||
          raise Error.new("no diagnostic procedure matches incident #{event.correlation_key}")
      end
    end

    def includes?(reference : ProcedureReference) : Bool
      @playbooks.any? { |procedure| procedure.reference == reference }
    end

    def find(reference : ProcedureReference) : DiagnosticProcedure?
      @playbooks.find { |procedure| procedure.reference == reference }
    end

    protected def self.fingerprint(path : String) : String
      entries = playbook_files(path).map do |file|
        "#{file}:#{Digest::SHA256.hexdigest(File.read(file))}"
      end
      Digest::SHA256.hexdigest(entries.join("\n"))
    end

    private def refresh_if_changed : Nil
      @reload_lock.synchronize do
        current_fingerprint : String? = nil
        begin
          current_fingerprint = self.class.fingerprint(path)
          return if @lock.synchronize { current_fingerprint == @fingerprint }

          replacement = self.class.load(path, live_reload: @live_reload)
          @lock.synchronize do
            @playbooks = replacement.playbooks_snapshot
            @fingerprint = current_fingerprint.as(String)
            @loaded_at = Time.utc
            @reload_error = nil
          end
          AISupportAgent::Log.info { "reloaded diagnostic procedures from #{path}" }
        rescue error
          @lock.synchronize do
            @fingerprint = current_fingerprint if current_fingerprint
            @reload_error = "#{error.class}: #{error.message}"
          end
          AISupportAgent::Log.warn(exception: error) { "playbook reload failed; retaining the last valid registry" }
        end
      end
    end

    protected def playbooks_snapshot : Array(DiagnosticProcedure)
      @playbooks.dup
    end

    protected def validate! : DiagnosticProcedureRegistry
      raise ValidationError.new("playbook registry is empty") if @playbooks.empty?

      identities = {} of String => Bool
      @playbooks.each do |playbook|
        identity = "#{playbook.id}:#{playbook.version}"
        raise ValidationError.new("duplicate playbook #{identity}") if identities[identity]?
        identities[identity] = true
        validate(playbook)
      end

      fallbacks = @playbooks.select(&.matches.fallback?)
      unless fallbacks.size == 1 && fallbacks.first.matches.sources.empty? && fallbacks.first.matches.required_context.empty?
        raise ValidationError.new("registry must define exactly one unconditional fallback playbook")
      end
      self
    end

    private def validate(playbook : DiagnosticProcedure) : Nil
      unless playbook.id.matches?(/\A[a-z0-9]+(?:-[a-z0-9]+)*\z/)
        raise ValidationError.new("invalid playbook id #{playbook.id}")
      end
      raise ValidationError.new("#{playbook.id} version must be positive") unless playbook.version > 0
      raise ValidationError.new("#{playbook.id} name is required") if playbook.name.blank?
      raise ValidationError.new("#{playbook.id} mode must be diagnostic") unless playbook.mode == "diagnostic"
      begin
        DiagnosticClassification.parse(playbook.classification_name)
      rescue error : ArgumentError
        raise ValidationError.new("#{playbook.id} #{error.message}")
      end
      if playbook.matches.fallback? && !playbook.matches.patterns.empty?
        raise ValidationError.new("#{playbook.id} fallback playbook cannot define patterns")
      end
      if !playbook.matches.fallback? && playbook.matches.patterns.empty?
        raise ValidationError.new("#{playbook.id} must define at least one match pattern")
      end
      playbook.matches.patterns.each do |pattern|
        raise ValidationError.new("#{playbook.id} match patterns cannot be empty") if pattern.empty?
        Regex.new(pattern)
      rescue error : ArgumentError
        raise ValidationError.new("#{playbook.id} has invalid match pattern #{pattern.inspect}: #{error.message}")
      end
      playbook.matches.compile_patterns!
      playbook.matches.sources.each do |source|
        raise ValidationError.new("#{playbook.id} has unknown source #{source}") unless SOURCES.includes?(source)
      end
      validate_context(playbook.id, playbook.matches.required_context)
      validate_steps(playbook)
      validate_analysis(playbook)
      validate_guidance(playbook)
    end

    private def validate_steps(playbook : DiagnosticProcedure) : Nil
      raise ValidationError.new("#{playbook.id} must define at least one step") if playbook.steps.empty?

      preceding = [] of String
      playbook.steps.each do |step|
        unless step.id.matches?(/\A[a-z0-9]+(?:-[a-z0-9]+)*\z/)
          raise ValidationError.new("#{playbook.id} has invalid step id #{step.id}")
        end
        raise ValidationError.new("#{playbook.id} has duplicate step #{step.id}") if preceding.includes?(step.id)
        raise ValidationError.new("#{playbook.id} step #{step.id} uses unknown tool #{step.tool}") unless DIAGNOSTIC_TOOLS.includes?(step.tool)
        unless step.io_timeout_seconds > 0 && step.io_timeout_seconds <= 60
          raise ValidationError.new("#{playbook.id} step #{step.id} io_timeout_seconds must be between 0 and 60")
        end
        step.depends_on.each do |dependency|
          unless preceding.includes?(dependency)
            raise ValidationError.new("#{playbook.id} step #{step.id} has unknown or later dependency #{dependency}")
          end
        end
        validate_context("#{playbook.id} step #{step.id}", step.requires)
        required_context = PlaybookStep.required_context(step.tool)
        missing_context = required_context.reject { |field| step.requires.includes?(field) }
        unless missing_context.empty?
          raise ValidationError.new("#{playbook.id} step #{step.id} must require #{missing_context.join(", ")}")
        end
        preceding << step.id
      end
    end

    private def validate_analysis(playbook : DiagnosticProcedure) : Nil
      analysis = playbook.analysis
      if analysis.hypotheses.empty? || analysis.hypotheses.any?(&.blank?)
        raise ValidationError.new("#{playbook.id} hypotheses must contain non-empty values")
      end
      if analysis.ruled_out.any?(&.blank?)
        raise ValidationError.new("#{playbook.id} ruled_out must contain non-empty values")
      end
      unless (0.0..1.0).includes?(analysis.initial_confidence) &&
             (0.0..1.0).includes?(analysis.minimum_confidence) &&
             (0.0..1.0).includes?(analysis.escalate_below)
        raise ValidationError.new("#{playbook.id} confidence thresholds must be between 0 and 1")
      end
      if analysis.escalate_below > analysis.minimum_confidence
        raise ValidationError.new("#{playbook.id} escalate_below cannot exceed minimum_confidence")
      end
      raise ValidationError.new("#{playbook.id} max_iterations must be between 0 and 5") unless (0..5).includes?(analysis.max_iterations)
      analysis.fallback_tools.each do |tool|
        raise ValidationError.new("#{playbook.id} uses unknown fallback tool #{tool}") unless DIAGNOSTIC_TOOLS.includes?(tool)
      end
      unless analysis.fallback_tools.uniq.size == analysis.fallback_tools.size
        raise ValidationError.new("#{playbook.id} fallback tools must be unique")
      end
    end

    private def validate_guidance(playbook : DiagnosticProcedure) : Nil
      guidance = playbook.guidance
      raise ValidationError.new("#{playbook.id} guidance summary is required") if guidance.summary.blank?
      if guidance.operator_steps.empty? || guidance.operator_steps.any?(&.blank?)
        raise ValidationError.new("#{playbook.id} operator steps must contain non-empty values")
      end
    end

    private def validate_context(owner : String, fields : Array(String)) : Nil
      fields.each do |field|
        raise ValidationError.new("#{owner} has unknown context requirement #{field}") unless CONTEXT_FIELDS.includes?(field)
      end
    end
  end
end
