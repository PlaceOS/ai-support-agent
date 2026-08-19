require "digest/sha256"
require "set"
require "yaml"

module AISupportAgent
  struct ProcedureReference
    PATTERN = /\A(diagnostic|remediation|verification|escalation|maintenance|correlation):([a-z0-9]+(?:-[a-z0-9]+)*)@([1-9][0-9]*)\z/

    getter category : String
    getter id : String
    getter version : Int32

    def initialize(@category : String, @id : String, @version : Int32)
    end

    def self.parse(value : String) : ProcedureReference
      match = PATTERN.match(value) || raise ArgumentError.new("invalid procedure reference #{value.inspect}")
      new(match[1], match[2], match[3].to_i)
    end

    def to_s(io : IO) : Nil
      io << category << ':' << id << '@' << version
    end
  end

  class WorkflowStage
    include YAML::Serializable
    include YAML::Serializable::Strict

    getter id : String
    getter type : String
    getter procedures : Array(String) = [] of String
    getter transitions : Hash(String, String) = {} of String => String
    getter? terminal : Bool = false

    def procedure_references : Array(ProcedureReference)
      procedures.map { |reference| ProcedureReference.parse(reference) }
    end
  end

  class WorkflowPlaybook
    include YAML::Serializable
    include YAML::Serializable::Strict

    @[YAML::Field(key: "$schema")]
    getter schema_uri : String? = nil
    getter schema_version : String
    getter id : String
    getter version : Int32
    getter name : String
    getter entrypoint : String
    getter? default : Bool
    getter stages : Array(WorkflowStage)

    @[YAML::Field(ignore: true)]
    property content_hash : String = ""

    def stage(id : String) : WorkflowStage
      stages.find(&.id.==(id)) || raise WorkflowRegistry::Error.new("workflow #{self.id} has no stage #{id}")
    end
  end

  struct WorkflowSelection
    getter workflow : WorkflowPlaybook
    getter procedure : DiagnosticProcedure
    getter stage : WorkflowStage

    def initialize(@workflow : WorkflowPlaybook, @procedure : DiagnosticProcedure, @stage : WorkflowStage)
    end
  end

  class WorkflowRegistry
    SCHEMA_VERSION = "workflow.v1"

    class Error < Exception
    end

    class ValidationError < Error
    end

    getter path : String

    def self.load(
      path : String,
      diagnostics : DiagnosticProcedureRegistry,
      remediations : RemediationProcedureRegistry,
      escalations : EscalationProcedureRegistry,
    ) : WorkflowRegistry
      raise ValidationError.new("workflow directory not found: #{path}") unless Dir.exists?(path)

      files = playbook_files(path)
      raise ValidationError.new("no YAML workflows found in #{path}") if files.empty?

      workflows = files.map do |file|
        contents = File.read(file)
        workflow = WorkflowPlaybook.from_yaml(contents)
        unless workflow.schema_version == SCHEMA_VERSION
          raise ValidationError.new("unsupported workflow schema_version #{workflow.schema_version} in #{file}")
        end
        workflow.content_hash = Digest::SHA256.hexdigest(contents)
        workflow
      rescue error : YAML::ParseException
        raise ValidationError.new("invalid workflow YAML in #{file}: #{error.message}")
      end

      new(path, workflows).tap(&.validate!(diagnostics, remediations, escalations))
    end

    private def self.playbook_files(path : String) : Array(String)
      return [] of String unless Dir.exists?(path)

      (Dir.glob(File.join(path, "**", "*.yml")) + Dir.glob(File.join(path, "**", "*.yaml"))).sort
    end

    private def initialize(@path : String, @workflows : Array(WorkflowPlaybook))
    end

    def size : Int32
      @workflows.size
    end

    def default : WorkflowPlaybook
      @workflows.find(&.default?) || raise Error.new("no default workflow configured")
    end

    protected def workflows_snapshot : Array(WorkflowPlaybook)
      @workflows.dup
    end

    protected def validate!(
      diagnostics : DiagnosticProcedureRegistry,
      remediations : RemediationProcedureRegistry,
      escalations : EscalationProcedureRegistry,
    ) : Nil
      defaults = @workflows.count(&.default?)
      raise ValidationError.new("workflow registry must define exactly one default workflow") unless defaults == 1

      identities = Set(String).new
      @workflows.each do |workflow|
        identity = "#{workflow.id}:#{workflow.version}"
        raise ValidationError.new("duplicate workflow #{identity}") unless identities.add?(identity)
        validate(workflow, diagnostics, remediations, escalations)
      end
    end

    private def validate(
      workflow : WorkflowPlaybook,
      diagnostics : DiagnosticProcedureRegistry,
      remediations : RemediationProcedureRegistry,
      escalations : EscalationProcedureRegistry,
    ) : Nil
      unless workflow.id.matches?(/\A[a-z0-9]+(?:-[a-z0-9]+)*\z/)
        raise ValidationError.new("invalid workflow id #{workflow.id}")
      end
      raise ValidationError.new("#{workflow.id} version must be positive") unless workflow.version > 0
      raise ValidationError.new("#{workflow.id} name is required") if workflow.name.blank?
      raise ValidationError.new("#{workflow.id} must define stages") if workflow.stages.empty?

      stage_ids = workflow.stages.map(&.id)
      raise ValidationError.new("#{workflow.id} has duplicate stage ids") unless stage_ids.uniq.size == stage_ids.size
      raise ValidationError.new("#{workflow.id} entrypoint #{workflow.entrypoint} does not exist") unless stage_ids.includes?(workflow.entrypoint)
      workflow.stages.each do |stage|
        stage.transitions.each_value do |target|
          unless stage_ids.includes?(target)
            raise ValidationError.new("#{workflow.id} stage #{stage.id} targets missing stage #{target}")
          end
        end
      end

      validate_acyclic(workflow)
      workflow.stages.each do |stage|
        validate_stage(workflow, stage, diagnostics, remediations, escalations)
      end
      validate_reachability(workflow)
    end

    private def validate_stage(
      workflow : WorkflowPlaybook,
      stage : WorkflowStage,
      diagnostics : DiagnosticProcedureRegistry,
      remediations : RemediationProcedureRegistry,
      escalations : EscalationProcedureRegistry,
    ) : Nil
      unless stage.id.matches?(/\A[a-z0-9]+(?:-[a-z0-9]+)*\z/)
        raise ValidationError.new("#{workflow.id} has invalid stage id #{stage.id}")
      end
      case stage.type
      when "diagnostic"
        raise ValidationError.new("#{workflow.id} diagnostic stage #{stage.id} cannot be terminal") if stage.terminal?
        raise ValidationError.new("#{workflow.id} diagnostic stage #{stage.id} requires procedures") if stage.procedures.empty?
        expected = ["diagnosed", "insufficient_evidence"]
        unless stage.transitions.keys.sort! == expected
          raise ValidationError.new("#{workflow.id} diagnostic stage #{stage.id} must define diagnosed and insufficient_evidence transitions")
        end
        stage.procedure_references.each do |reference|
          unless reference.category == "diagnostic" && diagnostics.includes?(reference)
            raise ValidationError.new("#{workflow.id} references missing procedure #{reference}")
          end
        end
        diagnosed_target = workflow.stage(stage.transitions["diagnosed"])
        unless ["remediation", "report"].includes?(diagnosed_target.type)
          raise ValidationError.new("#{workflow.id} diagnosed outcome must target remediation or report")
        end
        unless workflow.stage(stage.transitions["insufficient_evidence"]).type == "escalation"
          raise ValidationError.new("#{workflow.id} insufficient_evidence outcome must target escalation")
        end
      when "remediation"
        raise ValidationError.new("#{workflow.id} remediation stage #{stage.id} cannot be terminal") if stage.terminal?
        raise ValidationError.new("#{workflow.id} remediation stage #{stage.id} requires procedures") if stage.procedures.empty?
        expected = ["no_proposal", "proposal_created"]
        unless stage.transitions.keys.sort! == expected
          raise ValidationError.new("#{workflow.id} remediation stage #{stage.id} must define proposal_created and no_proposal transitions")
        end
        stage.procedure_references.each do |reference|
          unless reference.category == "remediation" && remediations.includes?(reference)
            raise ValidationError.new("#{workflow.id} references missing procedure #{reference}")
          end
        end
        stage.transitions.each_value do |target|
          unless workflow.stage(target).type == "report"
            raise ValidationError.new("#{workflow.id} remediation outcomes must target report")
          end
        end
      when "escalation"
        raise ValidationError.new("#{workflow.id} escalation stage #{stage.id} cannot be terminal") if stage.terminal?
        raise ValidationError.new("#{workflow.id} escalation stage #{stage.id} requires procedures") if stage.procedures.empty?
        unless stage.transitions.keys == ["escalated"]
          raise ValidationError.new("#{workflow.id} escalation stage #{stage.id} must define escalated transition")
        end
        stage.procedure_references.each do |reference|
          unless reference.category == "escalation" && escalations.includes?(reference)
            raise ValidationError.new("#{workflow.id} references missing procedure #{reference}")
          end
        end
        unless workflow.stage(stage.transitions["escalated"]).type == "escalated"
          raise ValidationError.new("#{workflow.id} escalated outcome must target escalated terminal")
        end
      when "report", "escalated"
        unless stage.terminal? && stage.procedures.empty? && stage.transitions.empty?
          raise ValidationError.new("#{workflow.id} terminal stage #{stage.id} cannot define procedures or transitions")
        end
      else
        raise ValidationError.new("#{workflow.id} stage #{stage.id} has unsupported type #{stage.type}")
      end
    rescue error : ArgumentError
      raise ValidationError.new("#{workflow.id} stage #{stage.id}: #{error.message}")
    end

    private def validate_reachability(workflow : WorkflowPlaybook) : Nil
      reachable = Set(String).new
      pending = [workflow.entrypoint]
      until pending.empty?
        id = pending.shift
        next unless reachable.add?(id)
        pending.concat(workflow.stage(id).transitions.values)
      end

      unreachable = workflow.stages.map(&.id).reject { |stage_id| reachable.includes?(stage_id) }
      unless unreachable.empty?
        raise ValidationError.new("#{workflow.id} has unreachable stages: #{unreachable.join(", ")}")
      end
    end

    private def validate_acyclic(workflow : WorkflowPlaybook) : Nil
      visiting = Set(String).new
      visited = Set(String).new
      visit = uninitialized String -> Nil
      visit = ->(id : String) do
        raise ValidationError.new("#{workflow.id} contains a cycle at stage #{id}") if visiting.includes?(id)
        unless visited.includes?(id)
          visiting << id
          workflow.stage(id).transitions.each_value { |target| visit.call(target) }
          visiting.delete(id)
          visited << id
        end
      end
      visit.call(workflow.entrypoint)
    end
  end

  class WorkflowCatalog
    DEFAULT_ROOT = "playbooks"
    SOURCE_ROOT  = File.expand_path("../../playbooks", __DIR__)

    getter root : String
    getter reload_error : String?
    @fingerprint : String
    @lock = Mutex.new
    @reload_lock = Mutex.new

    def self.from_environment : WorkflowCatalog
      root = ENV["PLAYBOOKS_PATH"]?.presence || discover_root
      load(root)
    end

    def self.load(root : String) : WorkflowCatalog
      diagnostics_path = File.join(root, "diagnostics")
      remediation_path = File.join(root, "remediation")
      verification_path = File.join(root, "verification")
      escalation_path = File.join(root, "escalation")
      maintenance_path = File.join(root, "maintenance")
      correlation_path = File.join(root, "correlation")
      workflows_path = File.join(root, "workflows")
      diagnostics = DiagnosticProcedureRegistry.load(diagnostics_path, live_reload: false)
      verifications = VerificationProcedureRegistry.load(verification_path)
      remediations = RemediationProcedureRegistry.load(remediation_path)
      escalations = EscalationProcedureRegistry.load(escalation_path)
      maintenance = MaintenanceProcedureRegistry.load(maintenance_path, diagnostics)
      correlations = CorrelationPolicyRegistry.load(correlation_path)
      remediations.validate_verification_references!(verifications)
      workflows = WorkflowRegistry.load(workflows_path, diagnostics, remediations, escalations)
      new(root, diagnostics, remediations, verifications, escalations, maintenance, correlations, workflows)
    end

    private def self.discover_root : String
      roots = [DEFAULT_ROOT]
      if executable = Process.executable_path
        roots << File.join(File.dirname(executable), DEFAULT_ROOT)
      end
      roots << SOURCE_ROOT
      roots.find do |root|
        ["diagnostics", "remediation", "verification", "escalation", "maintenance", "correlation", "workflows"].all? { |directory| Dir.exists?(File.join(root, directory)) }
      end || DEFAULT_ROOT
    end

    protected def self.fingerprint(root : String) : String
      files = ["diagnostics", "remediation", "verification", "escalation", "maintenance", "correlation", "workflows"].flat_map do |directory|
        path = File.join(root, directory, "**")
        Dir.glob(File.join(path, "*.yml")) + Dir.glob(File.join(path, "*.yaml"))
      end.sort!
      entries = files.map { |file| "#{file}:#{Digest::SHA256.hexdigest(File.read(file))}" }
      Digest::SHA256.hexdigest(entries.join("\n"))
    end

    private def initialize(
      @root : String,
      @diagnostics : DiagnosticProcedureRegistry,
      @remediations : RemediationProcedureRegistry,
      @verifications : VerificationProcedureRegistry,
      @escalations : EscalationProcedureRegistry,
      @maintenance : MaintenanceProcedureRegistry,
      @correlations : CorrelationPolicyRegistry,
      @workflows : WorkflowRegistry,
    )
      @fingerprint = self.class.fingerprint(root)
    end

    def select(
      event : IncidentEvent,
      payload : JSON::Any,
      reference : ProcedureReference? = nil,
    ) : WorkflowSelection
      refresh_if_changed
      @lock.synchronize do
        workflow = @workflows.default
        stage = workflow.stage(workflow.entrypoint)
        procedure = if selected = reference
                      unless selected.category == "diagnostic" && stage.procedure_references.includes?(selected)
                        raise WorkflowRegistry::Error.new("workflow #{workflow.id} does not declare diagnostic procedure #{selected}")
                      end
                      @diagnostics.find(selected) || raise WorkflowRegistry::Error.new("diagnostic procedure #{selected} is unavailable")
                    else
                      @diagnostics.select(event, payload, stage.procedure_references)
                    end
        WorkflowSelection.new(workflow, procedure, stage)
      end
    end

    def select_remediation(
      report : IncidentReport,
      event : IncidentEvent,
      stage : WorkflowStage,
    ) : RemediationProcedure?
      refresh_if_changed
      @lock.synchronize do
        @remediations.select(report, event, stage.procedure_references)
      end
    end

    def diagnostic_count : Int32
      refresh_if_changed
      @lock.synchronize { @diagnostics.size }
    end

    def remediation_count : Int32
      refresh_if_changed
      @lock.synchronize { @remediations.size }
    end

    def verification_count : Int32
      refresh_if_changed
      @lock.synchronize { @verifications.size }
    end

    def verification(reference : ProcedureReference) : VerificationProcedure?
      refresh_if_changed
      @lock.synchronize { @verifications.find(reference) }
    end

    def escalation_count : Int32
      refresh_if_changed
      @lock.synchronize { @escalations.size }
    end

    def select_escalation(report : IncidentReport, stage : WorkflowStage) : EscalationProcedure
      refresh_if_changed
      @lock.synchronize { @escalations.select(report, stage.procedure_references) }
    end

    def maintenance_count : Int32
      refresh_if_changed
      @lock.synchronize { @maintenance.size }
    end

    def maintenance_procedures : Array(MaintenanceProcedure)
      refresh_if_changed
      @lock.synchronize { @maintenance.procedures_snapshot }
    end

    def maintenance(id : String) : MaintenanceProcedure?
      refresh_if_changed
      @lock.synchronize { @maintenance.find(id) }
    end

    def correlation_count : Int32
      refresh_if_changed
      @lock.synchronize { @correlations.size }
    end

    def correlation_policy : CorrelationPolicy
      refresh_if_changed
      @lock.synchronize { @correlations.default }
    end

    def workflow_count : Int32
      refresh_if_changed
      @lock.synchronize { @workflows.size }
    end

    private def refresh_if_changed : Nil
      @reload_lock.synchronize do
        observed : String? = nil
        begin
          observed = self.class.fingerprint(root)
          return if @lock.synchronize { observed == @fingerprint }

          replacement = self.class.load(root)
          @lock.synchronize do
            @diagnostics = replacement.diagnostics_snapshot
            @remediations = replacement.remediations_snapshot
            @verifications = replacement.verifications_snapshot
            @escalations = replacement.escalations_snapshot
            @maintenance = replacement.maintenance_snapshot
            @correlations = replacement.correlations_snapshot
            @workflows = replacement.workflows_snapshot
            @fingerprint = observed.as(String)
            @reload_error = nil
          end
          AISupportAgent::Log.info { "reloaded workflow catalog from #{root}" }
        rescue error
          @lock.synchronize do
            @fingerprint = observed if observed
            @reload_error = "#{error.class}: #{error.message}"
          end
          AISupportAgent::Log.warn(exception: error) { "workflow catalog reload failed; retaining last-known-good catalog" }
        end
      end
    end

    protected def diagnostics_snapshot : DiagnosticProcedureRegistry
      @diagnostics
    end

    protected def remediations_snapshot : RemediationProcedureRegistry
      @remediations
    end

    protected def verifications_snapshot : VerificationProcedureRegistry
      @verifications
    end

    protected def escalations_snapshot : EscalationProcedureRegistry
      @escalations
    end

    protected def maintenance_snapshot : MaintenanceProcedureRegistry
      @maintenance
    end

    protected def correlations_snapshot : CorrelationPolicyRegistry
      @correlations
    end

    protected def workflows_snapshot : WorkflowRegistry
      @workflows
    end
  end

  class WorkflowRunner
    def initialize(@catalog : WorkflowCatalog, @diagnostics : DiagnosticEngine)
    end

    def report_for(incident : Incident, diagnostic_reference : ProcedureReference? = nil) : IncidentReport
      payload = Redactor.redact(incident.event.payload)
      selection = @catalog.select(incident.event, payload, diagnostic_reference)
      report = @diagnostics.report_for(incident, selection.procedure)
      outcome = report.decision.try(&.escalation_required?) ? "insufficient_evidence" : "diagnosed"
      plan = report.investigation_plan.try do |current|
        current.with_workflow(selection.workflow, selection.stage.id)
      end
      steps = [transition_step(selection.workflow, selection.stage, outcome, report)]
      stage = selection.workflow.stage(selection.stage.transitions[outcome])

      loop do
        case stage.type
        when "remediation"
          if procedure = @catalog.select_remediation(report, incident.event, stage)
            plan = plan.try(&.with_procedure(procedure.reference, procedure.content_hash))
            report = report.with_remediation_proposal(
              procedure.build_proposal,
              plan,
              InvestigationStep.new(
                name: "remediation:#{procedure.id}",
                status: InvestigationStepStatus::Completed,
                summary: "Generated an approval-required proposal from remediation procedure #{procedure.id} v#{procedure.version}; no action executed",
                evidence_count: report.evidence.size
              )
            )
            outcome = "proposal_created"
          else
            outcome = "no_proposal"
          end
          steps << transition_step(selection.workflow, stage, outcome, report)
          stage = selection.workflow.stage(stage.transitions[outcome])
        when "escalation"
          procedure = @catalog.select_escalation(report, stage)
          escalation = procedure.plan(report)
          plan = plan.try(&.with_escalation(escalation))
          outcome = "escalated"
          steps << transition_step(selection.workflow, stage, outcome, report)
          stage = selection.workflow.stage(stage.transitions[outcome])
        when "report", "escalated"
          break
        else
          raise WorkflowRegistry::Error.new("unsupported runtime workflow stage #{stage.type}")
        end
      end

      status = stage.type == "escalated" ? IncidentStatus::Escalated : report.status
      steps << InvestigationStep.new(
        name: "workflow:#{stage.id}",
        status: InvestigationStepStatus::Completed,
        summary: "Workflow reached terminal #{stage.type} stage #{stage.id}",
        evidence_count: report.evidence.size
      )
      report.with_workflow_result(plan, status, steps)
    end

    private def transition_step(
      workflow : WorkflowPlaybook,
      stage : WorkflowStage,
      outcome : String,
      report : IncidentReport,
    ) : InvestigationStep
      InvestigationStep.new(
        name: "workflow:#{stage.id}",
        status: InvestigationStepStatus::Completed,
        summary: "Workflow #{workflow.id} transitioned on #{outcome} to #{stage.transitions[outcome]}",
        evidence_count: report.evidence.size
      )
    end
  end
end
