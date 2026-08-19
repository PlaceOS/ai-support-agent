require "digest/sha256"
require "set"
require "yaml"

module AISupportAgent
  struct RemediationAction
    getter id : String
    getter summary : String
    getter required_context : Array(String)

    def initialize(@id : String, @summary : String, @required_context : Array(String))
    end
  end

  module RemediationActionCatalog
    ACTIONS = {
      "restart-module" => RemediationAction.new(
        "restart-module",
        "Restart the affected module after an operator reviews the captured runtime-error evidence.",
        ["module_id"]
      ),
      "update-module-credentials" => RemediationAction.new(
        "update-module-credentials",
        "Update the affected module credentials after an operator validates the intended account and secret source.",
        ["module_id"]
      ),
      "renew-tls-certificate" => RemediationAction.new(
        "renew-tls-certificate",
        "Renew or replace the affected TLS certificate after an operator validates its identity and trust chain.",
        ["module_id"]
      ),
    }

    def self.find(id : String) : RemediationAction?
      ACTIONS[id]?
    end
  end

  class RemediationMatch
    include YAML::Serializable
    include YAML::Serializable::Strict

    getter classifications : Array(String)
    getter minimum_confidence : Float64 = 0.0
    getter required_context : Array(String) = [] of String

    def matches?(report : IncidentReport, event : IncidentEvent) : Bool
      classifications.any? { |classification| DiagnosticClassification.parse(classification) == report.classification } &&
        report.confidence >= minimum_confidence &&
        required_context.all? { |field| DiagnosticProcedure.context_present?(field, event) }
    end
  end

  class RemediationPolicy
    include YAML::Serializable
    include YAML::Serializable::Strict

    getter action : String
    getter risk_level : String
    getter? approval_required : Bool
    getter policy_basis : String
    getter verification : String
  end

  class RemediationProcedure
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
    getter matches : RemediationMatch
    getter proposal : RemediationPolicy

    @[YAML::Field(ignore: true)]
    property content_hash : String = ""

    def reference : ProcedureReference
      ProcedureReference.new("remediation", id, version)
    end

    def applicable?(report : IncidentReport, event : IncidentEvent) : Bool
      matches.matches?(report, event)
    end

    def build_proposal : RemediationProposal
      action = RemediationActionCatalog.find(proposal.action) || raise RemediationProcedureRegistry::Error.new("unknown remediation action #{proposal.action}")
      RemediationProposal.new(
        action: action.summary,
        risk_level: proposal.risk_level,
        approval_required: proposal.approval_required?,
        execution_mode: "proposal_only",
        policy_basis: proposal.policy_basis,
        verification_plan: [] of String,
        verification_procedure: proposal.verification
      )
    end
  end

  class RemediationProcedureRegistry
    SCHEMA_VERSION = "remediation-procedure.v1"
    CONTEXT_FIELDS = ["tenant_id", "system_id", "module_id", "module_name", "module_index"]
    RISK_LEVELS    = ["low", "medium", "high"]

    class Error < Exception
    end

    class ValidationError < Error
    end

    getter path : String

    def self.load(path : String) : RemediationProcedureRegistry
      raise ValidationError.new("remediation directory not found: #{path}") unless Dir.exists?(path)

      files = playbook_files(path)
      raise ValidationError.new("no remediation procedures found in #{path}") if files.empty?

      procedures = files.map do |file|
        contents = File.read(file)
        procedure = RemediationProcedure.from_yaml(contents)
        unless procedure.schema_version == SCHEMA_VERSION
          raise ValidationError.new("unsupported remediation schema_version #{procedure.schema_version} in #{file}")
        end
        procedure.content_hash = Digest::SHA256.hexdigest(contents)
        procedure
      rescue error : YAML::ParseException
        raise ValidationError.new("invalid remediation YAML in #{file}: #{error.message}")
      end

      new(path, procedures).tap(&.validate!)
    end

    private def self.playbook_files(path : String) : Array(String)
      (Dir.glob(File.join(path, "**", "*.yml")) + Dir.glob(File.join(path, "**", "*.yaml"))).sort
    end

    private def initialize(@path : String, @procedures : Array(RemediationProcedure))
    end

    def size : Int32
      @procedures.size
    end

    def includes?(reference : ProcedureReference) : Bool
      @procedures.any? { |procedure| procedure.reference == reference }
    end

    def select(
      report : IncidentReport,
      event : IncidentEvent,
      allowed : Array(ProcedureReference),
    ) : RemediationProcedure?
      @procedures
        .select { |procedure| allowed.includes?(procedure.reference) && procedure.applicable?(report, event) }
        .sort_by! { |procedure| {procedure.priority, procedure.version, procedure.id} }
        .last?
    end

    def validate_verification_references!(verifications : VerificationProcedureRegistry) : Nil
      @procedures.each do |procedure|
        reference = ProcedureReference.parse(procedure.proposal.verification)
        unless reference.category == "verification" && verifications.includes?(reference)
          raise ValidationError.new("#{procedure.id} references missing verification procedure #{reference}")
        end
      rescue error : ArgumentError
        raise ValidationError.new("#{procedure.id} has invalid verification reference: #{error.message}")
      end
    end

    protected def procedures_snapshot : Array(RemediationProcedure)
      @procedures.dup
    end

    protected def validate! : RemediationProcedureRegistry
      identities = Set(String).new
      @procedures.each do |procedure|
        identity = "#{procedure.id}:#{procedure.version}"
        raise ValidationError.new("duplicate remediation procedure #{identity}") unless identities.add?(identity)
        validate(procedure)
      end
      self
    end

    private def validate(procedure : RemediationProcedure) : Nil
      unless procedure.id.matches?(/\A[a-z0-9]+(?:-[a-z0-9]+)*\z/)
        raise ValidationError.new("invalid remediation procedure id #{procedure.id}")
      end
      raise ValidationError.new("#{procedure.id} version must be positive") unless procedure.version > 0
      raise ValidationError.new("#{procedure.id} name is required") if procedure.name.blank?
      raise ValidationError.new("#{procedure.id} mode must be remediation") unless procedure.mode == "remediation"
      raise ValidationError.new("#{procedure.id} must match at least one classification") if procedure.matches.classifications.empty?
      procedure.matches.classifications.each do |classification|
        DiagnosticClassification.parse(classification)
      rescue error : ArgumentError
        raise ValidationError.new("#{procedure.id} #{error.message}")
      end
      unless (0.0..1.0).includes?(procedure.matches.minimum_confidence)
        raise ValidationError.new("#{procedure.id} minimum_confidence must be between 0 and 1")
      end
      procedure.matches.required_context.each do |field|
        raise ValidationError.new("#{procedure.id} has unknown context requirement #{field}") unless CONTEXT_FIELDS.includes?(field)
      end
      action = RemediationActionCatalog.find(procedure.proposal.action) ||
               raise ValidationError.new("#{procedure.id} references unknown action #{procedure.proposal.action}")
      missing_context = action.required_context.reject { |field| procedure.matches.required_context.includes?(field) }
      unless missing_context.empty?
        raise ValidationError.new("#{procedure.id} must require #{missing_context.join(", ")} for action #{action.id}")
      end
      unless RISK_LEVELS.includes?(procedure.proposal.risk_level)
        raise ValidationError.new("#{procedure.id} has invalid risk level #{procedure.proposal.risk_level}")
      end
      raise ValidationError.new("#{procedure.id} proposals must require approval") unless procedure.proposal.approval_required?
      raise ValidationError.new("#{procedure.id} policy_basis is required") if procedure.proposal.policy_basis.blank?
    end
  end
end
