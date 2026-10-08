require "file_utils"
require "./helper"

module AISupportAgent
  class FailingPlaybookContext < PlaceOSContext
    getter calls = [] of String

    def execute(target : String, event : IncidentEvent, io_timeout_seconds : Int32 = 10) : DiagnosticToolResult
      @calls << target
      DiagnosticToolResult.new(target, [] of Evidence, "simulated tool failure", InvestigationStepStatus::Failed)
    end
  end

  class SkippedPlaybookContext < PlaceOSContext
    getter calls = [] of String
    getter timeouts = [] of Int32

    def execute(target : String, event : IncidentEvent, io_timeout_seconds : Int32 = 10) : DiagnosticToolResult
      @calls << target
      @timeouts << io_timeout_seconds
      DiagnosticToolResult.new(target, [] of Evidence, "no evidence", InvestigationStepStatus::Skipped)
    end
  end

  class RetryPlaybookContext < PlaceOSContext
    getter calls = [] of String

    def execute(target : String, event : IncidentEvent, io_timeout_seconds : Int32 = 10) : DiagnosticToolResult
      @calls << target
      if @calls.size == 1
        DiagnosticToolResult.new(
          target,
          [Evidence.new(source: "diagnostic_tool_error", message: "first attempt failed")],
          "first attempt failed",
          InvestigationStepStatus::Failed
        )
      else
        DiagnosticToolResult.new(
          target,
          [Evidence.new(source: "retry_fixture", message: "retry completed")],
          "retry completed",
          InvestigationStepStatus::Completed
        )
      end
    end
  end

  def self.with_playbooks(contents : String, fallback : String? = fallback_playbook_yaml, & : String ->) : Nil
    directory = File.join(Dir.tempdir, "support-playbooks-#{UUID.random}")
    Dir.mkdir_p(directory)
    File.write(File.join(directory, "custom.yml"), contents)
    File.write(File.join(directory, "unknown.yml"), fallback) if fallback
    yield directory
  ensure
    FileUtils.rm_rf(directory) if directory
  end

  def self.playbook_yaml(tool : String = "module_details") : String
    <<-YAML
    schema_version: diagnostic-procedure.v1
    id: custom-diagnostic
    classification: custom_failure
    version: 3
    name: Custom Diagnosis
    mode: diagnostic
    priority: 100
    matches:
      patterns: ['(?i)custom signal|unclassified signal|HTTP 401']
    steps:
      - id: inspect-module
        tool: #{tool}
        io_timeout_seconds: 2
        requires: [module_id]
    analysis:
      hypotheses: [Custom hypothesis from YAML.]
      ruled_out: [Nothing ruled out yet.]
      initial_confidence: 0.72
      minimum_confidence: 0.65
      escalate_below: 0.5
      fallback_tools: [module_state]
    guidance:
      summary: Follow the repository procedure.
      operator_steps: [Review the YAML-defined evidence.]
    YAML
  end

  def self.fallback_playbook_yaml : String
    <<-YAML
    schema_version: diagnostic-procedure.v1
    id: unknown-incident
    classification: unknown
    version: 1
    name: Unknown Diagnosis
    mode: diagnostic
    matches:
      fallback: true
    steps:
      - id: inspect-module
        tool: module_details
        requires: [module_id]
    analysis:
      hypotheses: [No diagnostic pattern matched.]
      ruled_out: []
      initial_confidence: 0.2
      minimum_confidence: 0.65
      escalate_below: 0.5
      fallback_tools: []
    guidance:
      summary: Escalate with collected evidence.
      operator_steps: [Review the incident payload.]
    YAML
  end

  describe DiagnosticProcedureRegistry do
    it "publishes a machine-readable schema" do
      schema = JSON.parse(File.read("playbooks/schemas/diagnostic.v1.json"))

      schema["$schema"].as_s.should contain "2020-12"
      schema["properties"]["classification"]["pattern"].as_s.should eq "^[a-z][a-z0-9_]*$"
      schema["properties"]["matches"]["$ref"].as_s.should eq "#/$defs/matches"
    end

    it "loads and selects independently stored repository playbooks" do
      registry = DiagnosticProcedureRegistry.load("playbooks/diagnostics")
      event = IncidentEvent.new(
        source: IncidentSource::ModuleState,
        severity: IncidentSeverity::Error,
        correlation_key: "playbook-registry",
        payload: JSON.parse({message: "runtime error"}.to_json),
        module_id: "mod-playbook"
      )

      registry.size.should eq 15
      Dir.glob("playbooks/diagnostics/*.yml").size.should eq registry.size
      playbook = registry.select(event, event.payload)
      playbook.id.should eq "module-runtime-error"
      playbook.classification.runtime_error?.should be_true
      playbook.content_hash.size.should eq 64
      playbook.steps.map(&.tool).should contain "module_error_logs"
    end

    it "uses a newly added classification without engine changes" do
      contents = AISupportAgent.playbook_yaml
        .sub("id: custom-diagnostic", "id: battery-overheat")
        .sub("classification: custom_failure", "classification: battery_overheat")
        .sub("custom signal|unclassified signal|HTTP 401", "battery temperature critical")
        .sub("initial_confidence: 0.72", "initial_confidence: 0.83")

      AISupportAgent.with_playbooks(AISupportAgent.playbook_yaml) do |directory|
        registry = DiagnosticProcedureRegistry.load(directory)
        File.write(File.join(directory, "battery-overheat.yml"), contents)
        event = IncidentEvent.new(
          source: IncidentSource::Webhook,
          severity: IncidentSeverity::Critical,
          correlation_key: "new-runtime-playbook",
          payload: JSON.parse({message: "Battery temperature critical"}.to_json),
          module_id: "mod-battery"
        )

        report = DiagnosticEngine.new(PlaceOSContext.new, AIReporter.disabled, registry)
          .report_for(Incident.new("aisup-new-playbook", event, Time.utc))

        report.classification.to_s.should eq "battery_overheat"
        report.confidence.should eq 0.83
        report.decision.try(&.recommended_action).should eq "Follow the repository procedure."
        report.investigation_plan.try(&.playbook_id).should eq "battery-overheat"
      end
    end

    it "retains the last valid registry when a live reload is invalid" do
      AISupportAgent.with_playbooks(AISupportAgent.playbook_yaml) do |directory|
        registry = DiagnosticProcedureRegistry.load(directory)
        File.write(File.join(directory, "broken.yml"), "not: a valid playbook")

        registry.size.should eq 2
        registry.reload_error.should_not be_nil
      end
    end

    it "requires schema-declared safety fields at runtime" do
      contents = AISupportAgent.playbook_yaml.sub("  summary: Follow the repository procedure.\n", "")

      AISupportAgent.with_playbooks(contents) do |directory|
        expect_raises(DiagnosticProcedureRegistry::ValidationError, /summary/) do
          DiagnosticProcedureRegistry.load(directory)
        end
      end
    end

    it "uses the fallback when no diagnostic pattern matches" do
      AISupportAgent.with_playbooks(AISupportAgent.playbook_yaml) do |directory|
        registry = DiagnosticProcedureRegistry.load(directory)
        event = IncidentEvent.new(
          source: IncidentSource::Webhook,
          severity: IncidentSeverity::Warning,
          correlation_key: "fallback",
          payload: JSON.parse({message: "something entirely different"}.to_json),
          module_id: "mod-playbook"
        )

        report = DiagnosticEngine.new(PlaceOSContext.new, AIReporter.disabled, registry)
          .report_for(Incident.new("aisup-fallback", event, Time.utc))

        report.classification.unknown?.should be_true
        report.decision.try(&.escalation_required?).should be_true
      end
    end

    it "rejects unknown diagnostic tools" do
      AISupportAgent.with_playbooks(AISupportAgent.playbook_yaml(tool: "arbitrary_shell")) do |directory|
        expect_raises(DiagnosticProcedureRegistry::ValidationError, /unknown tool arbitrary_shell/) do
          DiagnosticProcedureRegistry.load(directory)
        end
      end
    end

    it "rejects steps that omit tool-required context" do
      contents = AISupportAgent.playbook_yaml.sub("requires: [module_id]", "requires: []")

      AISupportAgent.with_playbooks(contents) do |directory|
        expect_raises(DiagnosticProcedureRegistry::ValidationError, /must require module_id/) do
          DiagnosticProcedureRegistry.load(directory)
        end
      end
    end

    it "rejects remediation fields in diagnostic procedures" do
      contents = AISupportAgent.playbook_yaml.sub(
        "  summary: Follow the repository procedure.",
        "  summary: Follow the repository procedure.\n  execution_mode: execute"
      )
      AISupportAgent.with_playbooks(contents) do |directory|
        expect_raises(DiagnosticProcedureRegistry::ValidationError, /execution_mode/) do
          DiagnosticProcedureRegistry.load(directory)
        end
      end
    end

    it "rejects unresolved dependencies" do
      contents = AISupportAgent.playbook_yaml.sub(
        "requires: [module_id]",
        "requires: [module_id]\n    depends_on: [missing-step]"
      )

      AISupportAgent.with_playbooks(contents) do |directory|
        expect_raises(DiagnosticProcedureRegistry::ValidationError, /unknown or later dependency missing-step/) do
          DiagnosticProcedureRegistry.load(directory)
        end
      end
    end

    it "rejects registries without exactly one unconditional fallback" do
      AISupportAgent.with_playbooks(AISupportAgent.playbook_yaml, fallback: nil) do |directory|
        expect_raises(DiagnosticProcedureRegistry::ValidationError, /exactly one unconditional fallback/) do
          DiagnosticProcedureRegistry.load(directory)
        end
      end
    end

    it "rejects invalid signal patterns" do
      contents = AISupportAgent.playbook_yaml.sub("custom signal|unclassified signal|HTTP 401", "[")

      AISupportAgent.with_playbooks(contents) do |directory|
        expect_raises(DiagnosticProcedureRegistry::ValidationError, /invalid match pattern/) do
          DiagnosticProcedureRegistry.load(directory)
        end
      end
    end

    it "rejects empty signal patterns" do
      contents = AISupportAgent.playbook_yaml.sub("'(?i)custom signal|unclassified signal|HTTP 401'", "''")

      AISupportAgent.with_playbooks(contents) do |directory|
        expect_raises(DiagnosticProcedureRegistry::ValidationError, /patterns cannot be empty/) do
          DiagnosticProcedureRegistry.load(directory)
        end
      end
    end

    it "rejects unsupported persisted investigation plan schemas" do
      plan = InvestigationPlan.new("diagnose", ["module_details"])
      serialized = plan.to_json.sub(InvestigationPlan::SCHEMA_VERSION, "investigation-plan.v999")

      expect_raises(ArgumentError, /unsupported investigation plan schema/) do
        InvestigationPlan.from_json(serialized)
      end
    end

    it "skips dependent steps when an earlier tool fails" do
      contents = AISupportAgent.playbook_yaml
        .sub(
          "    requires: [module_id]\nanalysis:",
          "    requires: [module_id]\n  - id: inspect-state\n    tool: module_state\n    io_timeout_seconds: 2\n    depends_on: [inspect-module]\n    requires: [module_id]\nanalysis:"
        )
        .sub("fallback_tools: [module_state]", "fallback_tools: []")

      AISupportAgent.with_playbooks(contents) do |directory|
        context = FailingPlaybookContext.new
        registry = DiagnosticProcedureRegistry.load(directory)
        event = IncidentEvent.new(
          source: IncidentSource::Webhook,
          severity: IncidentSeverity::Warning,
          correlation_key: "dependency-failure",
          payload: JSON.parse({message: "custom signal"}.to_json),
          module_id: "mod-playbook"
        )

        report = DiagnosticEngine.new(context, AIReporter.disabled, registry)
          .report_for(Incident.new("aisup-dependency-failure", event, Time.utc))

        context.calls.should eq ["module_details"]
        dependent = report.investigation.find { |step| step.name == "tool:module_state" }
        dependent.try(&.status.skipped?).should be_true
      end
    end

    it "forwards I/O timeouts and skips dependencies after a skipped prerequisite" do
      contents = AISupportAgent.playbook_yaml
        .sub(
          "    requires: [module_id]\nanalysis:",
          "    requires: [module_id]\n  - id: inspect-state\n    tool: module_state\n    io_timeout_seconds: 7\n    depends_on: [inspect-module]\n    requires: [module_id]\nanalysis:"
        )
        .sub("fallback_tools: [module_state]", "fallback_tools: []")

      AISupportAgent.with_playbooks(contents) do |directory|
        context = SkippedPlaybookContext.new
        registry = DiagnosticProcedureRegistry.load(directory)
        event = IncidentEvent.new(
          source: IncidentSource::Webhook,
          severity: IncidentSeverity::Warning,
          correlation_key: "dependency-skipped",
          payload: JSON.parse({message: "custom signal"}.to_json),
          module_id: "mod-playbook"
        )

        report = DiagnosticEngine.new(context, AIReporter.disabled, registry)
          .report_for(Incident.new("aisup-dependency-skipped", event, Time.utc))

        context.calls.should eq ["module_details"]
        context.timeouts.should eq [2]
        dependent = report.investigation.find { |step| step.name == "tool:module_state" }
        dependent.try(&.status.skipped?).should be_true
      end
    end

    it "can retry a failed primary tool as fallback evidence" do
      contents = AISupportAgent.playbook_yaml.sub("fallback_tools: [module_state]", "fallback_tools: [module_details]")
      AISupportAgent.with_playbooks(contents) do |directory|
        context = RetryPlaybookContext.new
        registry = DiagnosticProcedureRegistry.load(directory)
        event = IncidentEvent.new(
          source: IncidentSource::Webhook,
          severity: IncidentSeverity::Warning,
          correlation_key: "fallback-retry",
          payload: JSON.parse({message: "custom signal"}.to_json),
          module_id: "mod-playbook"
        )

        report = DiagnosticEngine.new(context, AIReporter.disabled, registry)
          .report_for(Incident.new("aisup-fallback-retry", event, Time.utc))

        context.calls.should eq ["module_details", "module_details"]
        report.investigation.map(&.name).should contain "iterate_for_confidence"
      end
    end

    it "discovers repository playbooks outside the repository working directory" do
      configured_path = ENV.delete("PLAYBOOKS_PATH")
      AISupportAgent.with_playbooks(AISupportAgent.playbook_yaml) do |directory|
        Dir.mkdir(File.join(directory, "playbooks"))
        Dir.cd(directory) do
          registry = DiagnosticProcedureRegistry.from_environment
          registry.size.should eq 15
          Dir.glob(File.join(registry.path, "*.yml")).size.should eq 15
        end
      end
    ensure
      ENV["PLAYBOOKS_PATH"] = configured_path if configured_path
    end
  end
end
