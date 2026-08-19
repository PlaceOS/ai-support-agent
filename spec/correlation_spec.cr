require "file_utils"
require "./helper"

module AISupportAgent
  class CorrelationRepository < PostgresIncidentRepository
    getter findings = [] of CorrelationFinding
    getter feedback_records = [] of IncidentFeedback
    getter reports = [] of TrendReport

    def save_correlation_finding(finding : CorrelationFinding) : CorrelationFinding
      @findings << finding unless @findings.any?(&.deduplication_key.==(finding.deduplication_key))
      @findings.find(&.deduplication_key.==(finding.deduplication_key)) || finding
    end

    def find_correlation_finding(key : String) : CorrelationFinding?
      @findings.find(&.deduplication_key.==(key))
    end

    def all_correlation_findings : Array(CorrelationFinding)
      @findings
    end

    def save_incident_feedback(record : IncidentFeedback) : IncidentFeedback
      @feedback_records << record unless @feedback_records.any?(&.id.==(record.id))
      record
    end

    def incident_feedback_for(incident_id : String) : Array(IncidentFeedback)
      @feedback_records.select(&.incident_id.==(incident_id))
    end

    def all_incident_feedback : Array(IncidentFeedback)
      @feedback_records
    end

    def save_trend_report(report : TrendReport) : TrendReport
      @reports << report unless @reports.any?(&.id.==(report.id))
      report
    end

    def find_trend_report(id : String) : TrendReport?
      @reports.find(&.id.==(id))
    end

    def all_trend_reports : Array(TrendReport)
      @reports
    end
  end

  class FailingCorrelationRepository < PostgresIncidentRepository
    def save_correlation_finding(finding : CorrelationFinding) : CorrelationFinding
      raise "database offline"
    end

    def find_correlation_finding(key : String) : CorrelationFinding?
      raise "database offline"
    end

    def all_correlation_findings : Array(CorrelationFinding)
      raise "database offline"
    end

    def save_incident_feedback(record : IncidentFeedback) : IncidentFeedback
      raise "database offline"
    end

    def incident_feedback_for(incident_id : String) : Array(IncidentFeedback)
      raise "database offline"
    end

    def all_incident_feedback : Array(IncidentFeedback)
      raise "database offline"
    end

    def save_trend_report(report : TrendReport) : TrendReport
      raise "database offline"
    end

    def find_trend_report(id : String) : TrendReport?
      raise "database offline"
    end

    def all_trend_reports : Array(TrendReport)
      raise "database offline"
    end
  end

  def self.with_correlation_file(contents : String, & : String ->) : Nil
    directory = File.join(Dir.tempdir, "support-correlation-#{UUID.random}")
    Dir.mkdir_p(directory)
    File.write(File.join(directory, "policy.yml"), contents)
    yield directory
  ensure
    FileUtils.rm_rf(directory) if directory
  end

  def self.correlation_report(
    id : String,
    correlation_key : String,
    status : IncidentStatus = IncidentStatus::Open,
    classification : DiagnosticClassification = DiagnosticClassification::RuntimeError,
    source : IncidentSource = IncidentSource::Webhook,
    tenant_id : String? = "tenant-1",
    system_id : String? = "sys-1",
    module_id : String? = "mod-1",
  ) : IncidentReport
    IncidentReport.new(
      incident_id: id,
      status: status,
      summary: "Correlation fixture",
      classification: classification,
      confidence: 0.8,
      severity: IncidentSeverity::Error,
      source: source,
      correlation_key: correlation_key,
      tenant_id: tenant_id,
      system_id: system_id,
      module_id: module_id,
      created_at: Time.utc,
      evidence: [] of Evidence,
      actions_taken: ["report_only_no_remediation"],
      next_steps: [] of String
    )
  end

  def self.correlation_runtime : Tuple(WorkflowCatalog, IncidentStore, CorrelationFindingStore, CorrelationEngine)
    catalog = WorkflowCatalog.load("playbooks")
    incidents = IncidentStore.new
    findings = CorrelationFindingStore.new
    {catalog, incidents, findings, CorrelationEngine.new(catalog, incidents, findings)}
  end

  describe CorrelationPolicyRegistry do
    it "loads typed grouping, detector, and trend policy" do
      registry = CorrelationPolicyRegistry.load("playbooks/correlation")
      policy = registry.default

      registry.size.should eq 1
      policy.reference.to_s.should eq "correlation:incident-patterns@1"
      policy.grouping.dimensions.should eq ["tenant_id", "system_id", "module_id", "classification"]
      policy.rules.flapping.threshold.should eq 4
      policy.content_hash.size.should eq 64
    end

    it "rejects unknown executable fields and unsafe grouping" do
      contents = File.read("playbooks/correlation/incident-patterns.yml") + "\ncommand: restart modules\n"
      AISupportAgent.with_correlation_file(contents) do |directory|
        expect_raises(CorrelationPolicyRegistry::ValidationError, /command/) do
          CorrelationPolicyRegistry.load(directory)
        end
      end

      contents = File.read("playbooks/correlation/incident-patterns.yml")
        .sub("tenant_id, system_id, module_id, classification", "module_id, arbitrary")
      AISupportAgent.with_correlation_file(contents) do |directory|
        expect_raises(CorrelationPolicyRegistry::ValidationError, /grouping/) do
          CorrelationPolicyRegistry.load(directory)
        end
      end
    end

    it "retains the complete last-known-good catalogue after an invalid edit" do
      base = File.join(Dir.tempdir, "support-correlation-reload-#{UUID.random}")
      root = File.join(base, "playbooks")
      Dir.mkdir_p(base)
      FileUtils.cp_r("playbooks", root)
      catalog = WorkflowCatalog.load(root)
      policy = File.join(root, "correlation", "incident-patterns.yml")
      File.write(policy, File.read(policy) + "\ncommand: mutate\n")

      catalog.correlation_count.should eq 1
      catalog.workflow_count.should eq 1
      catalog.reload_error.should_not be_nil
    ensure
      FileUtils.rm_rf(base) if base
    end
  end

  describe "incident episodes" do
    it "deduplicates active firing but creates a new episode after resolution" do
      firing = IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "episode:mod-1",
        payload: JSON.parse({message: "connection closed"}.to_json),
        module_id: "mod-1"
      )
      first = AISupportAgent.ingest(firing)
      duplicate = AISupportAgent.ingest(firing)
      resolved = AISupportAgent.ingest(IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Info,
        correlation_key: firing.correlation_key,
        payload: JSON.parse({event: "resolved"}.to_json),
        module_id: "mod-1"
      ))
      next_episode = AISupportAgent.ingest(firing)

      duplicate.incident_id.should eq first.incident_id
      duplicate.duplicate_count.should eq 1
      resolved.status.resolved?.should be_true
      next_episode.incident_id.should_not eq first.incident_id
      AISupportAgent.incidents.all.size.should eq 2
    end
  end

  describe CorrelationEngine do
    it "groups source-specific keys and detects repeated incident episodes" do
      catalog, incidents, findings, engine = AISupportAgent.correlation_runtime
      base = Time.utc
      sources = [IncidentSource::Grafana, IncidentSource::ModuleState, IncidentSource::Scheduled]
      sources.each_with_index do |source, index|
        report = AISupportAgent.correlation_report("incident-#{index}", "source:#{index}", source: source)
        at = base + index.seconds
        incidents.save(report, observed_at: at)
        engine.evaluate(report, at)
      end

      repeated = findings.all.select(&.kind.repeated_incident?)
      repeated.size.should eq 1
      repeated.first.incident_ids.size.should eq 3
      repeated.first.policy.id.should eq catalog.correlation_policy.id
    end

    it "keeps tenant and module scopes isolated" do
      policy = WorkflowCatalog.load("playbooks").correlation_policy
      first = IncidentObservation.from(AISupportAgent.correlation_report("one", "one", tenant_id: "tenant-1"))
      second = IncidentObservation.from(AISupportAgent.correlation_report("two", "two", tenant_id: "tenant-2"))
      third = IncidentObservation.from(AISupportAgent.correlation_report("three", "three", module_id: "mod-2"))

      first.group_key(policy.grouping).should_not eq second.group_key(policy.grouping)
      first.group_key(policy.grouping).should_not eq third.group_key(policy.grouping)
      first.group_key(policy.grouping).should start_with "group:"
    end

    it "detects noisy repeated signals once per policy window" do
      _, incidents, findings, engine = AISupportAgent.correlation_runtime
      base = Time.utc
      report = AISupportAgent.correlation_report("incident-noisy", "noisy")
      6.times do |index|
        at = base + index.seconds
        incidents.save(report, observed_at: at)
        engine.evaluate(report, at)
      end

      noisy = findings.all.select(&.kind.noisy_signals?)
      noisy.size.should eq 1
      noisy.first.observation_count.should eq 5
    end

    it "detects alternating active and resolved transitions without treating duplicates as flapping" do
      _, incidents, findings, engine = AISupportAgent.correlation_runtime
      base = Time.utc
      statuses = [
        IncidentStatus::Open,
        IncidentStatus::Open,
        IncidentStatus::Resolved,
        IncidentStatus::Open,
        IncidentStatus::Resolved,
        IncidentStatus::Open,
      ]
      statuses.each_with_index do |status, index|
        report = AISupportAgent.correlation_report("flap-#{index}", "flap", status: status)
        at = base + index.seconds
        incidents.save(report, observed_at: at)
        engine.evaluate(report, at)
      end

      flapping = findings.all.select(&.kind.flapping?)
      flapping.size.should eq 1
      flapping.first.transition_count.should eq 4
    end
  end

  describe TrendReporter do
    it "generates a persisted, auditable trend report" do
      catalog, incidents, findings, engine = AISupportAgent.correlation_runtime
      feedback = IncidentFeedbackStore.new
      reports = TrendReportStore.new
      reporter = TrendReporter.new(catalog, incidents, findings, feedback, reports)
      base = Time.utc
      5.times do |index|
        report = AISupportAgent.correlation_report("trend-#{index}", "trend:#{index}")
        at = base + index.seconds
        incidents.save(report, observed_at: at)
        engine.evaluate(report, at)
      end
      feedback.create("trend-0", FeedbackRating::Helpful, "operator@example.test")

      report = reporter.generate(3600, base + 10.seconds)

      report.policy.id.should eq "incident-patterns"
      report.summary.observation_count.should eq 5
      report.summary.incident_count.should eq 5
      report.summary.classification_counts.should eq({"runtime_error" => 5})
      report.summary.finding_counts["repeated_incident"].should eq 1
      report.summary.feedback_counts["helpful"].should eq 1
      report.markdown.should contain "# Incident Trend Report"
      reports.find(report.id).should eq report
    end
  end

  describe "analytics and feedback APIs" do
    it "records immutable feedback without changing the incident report" do
      report = AISupportAgent.ingest(IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "feedback:incident",
        payload: JSON.parse({message: "connection closed"}.to_json),
        module_id: "mod-feedback"
      ))
      original = report.to_json
      response = client.post(
        "/api/ai-support/v1/incidents/#{report.incident_id}/feedback",
        headers: HTTP::Headers{"Content-Type" => "application/json"},
        body: {rating: "helpful", submitted_by: "operator@example.test", comment: "Accurate diagnosis"}.to_json
      )

      response.status_code.should eq 201
      record = IncidentFeedback.from_json(response.body)
      record.rating.helpful?.should be_true
      AISupportAgent.incidents.find(report.incident_id).try(&.to_json).should eq original
      history = client.get("/api/ai-support/v1/incidents/#{report.incident_id}/feedback")
      Array(IncidentFeedback).from_json(history.body).size.should eq 1
    end

    it "validates feedback ratings and bounded analytics parameters" do
      report = AISupportAgent.ingest(IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Warning,
        correlation_key: "feedback:invalid",
        payload: JSON.parse({message: "connection closed"}.to_json)
      ))
      invalid = client.post(
        "/api/ai-support/v1/incidents/#{report.incident_id}/feedback",
        headers: HTTP::Headers{"Content-Type" => "application/json"},
        body: {rating: "perfect", submitted_by: "operator"}.to_json
      )

      invalid.status_code.should eq 422
      client.get("/api/ai-support/v1/analytics/correlations?limit=501").status_code.should eq 422
      client.post(
        "/api/ai-support/v1/analytics/trends",
        headers: HTTP::Headers{"Content-Type" => "application/json"},
        body: {window_seconds: 60}.to_json
      ).status_code.should eq 422
    end

    it "generates, lists, and renders trend-report artifacts" do
      AISupportAgent.ingest(IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "trend:api",
        payload: JSON.parse({message: "runtime error"}.to_json),
        module_id: "mod-trend"
      ))
      response = client.post(
        "/api/ai-support/v1/analytics/trends",
        headers: HTTP::Headers{"Content-Type" => "application/json"},
        body: {window_seconds: 3600}.to_json
      )

      response.status_code.should eq 201
      report = TrendReport.from_json(response.body)
      client.get("/api/ai-support/v1/analytics/trends").status_code.should eq 200
      markdown = client.get("/api/ai-support/v1/analytics/trends/#{report.id}/report")
      markdown.status_code.should eq 200
      markdown.body.should contain "# Incident Trend Report"
    end
  end

  describe "correlation persistence" do
    it "loads findings, feedback, and trend reports after memory is cleared" do
      repository = CorrelationRepository.new
      findings = CorrelationFindingStore.new
      feedback = IncidentFeedbackStore.new
      reports = TrendReportStore.new
      findings.persist_with(repository)
      feedback.persist_with(repository)
      reports.persist_with(repository)
      finding = CorrelationFinding.new(
        id: "finding-persisted",
        deduplication_key: "key-persisted",
        kind: CorrelationKind::RepeatedIncident,
        policy: ProcedureAudit.new("correlation", "incident-patterns", 1, "a" * 64),
        scope_key: "group:one",
        tenant_id: "tenant-1",
        system_id: "sys-1",
        module_id: "mod-1",
        classification: DiagnosticClassification::RuntimeError,
        incident_ids: ["incident-1"],
        observation_count: 3,
        transition_count: 0,
        window_start: Time.utc - 1.hour,
        window_end: Time.utc,
        summary: "Repeated incidents",
        created_at: Time.utc
      )
      findings.save(finding)
      feedback_record = feedback.create("incident-1", FeedbackRating::Helpful, "operator")
      trend = TrendReport.new(
        id: "trend-persisted",
        policy: finding.policy,
        summary: TrendSummary.new(
          Time.utc - 1.hour,
          Time.utc,
          0,
          0,
          {} of String => Int32,
          {} of String => Int32,
          {} of String => Int32,
          {} of String => Int32,
          {} of String => Int32,
          [] of TrendCount
        ),
        markdown: "# Trend",
        generated_at: Time.utc
      )
      reports.save(trend)
      findings.clear
      feedback.clear
      reports.clear

      findings.find_by_key(finding.deduplication_key).should eq finding
      feedback.for_incident("incident-1").should eq [feedback_record]
      reports.find(trend.id).should eq trend
    end

    it "continues in memory and exposes persistence failures" do
      repository = FailingCorrelationRepository.new
      AISupportAgent.correlation_findings.persist_with(repository)
      AISupportAgent.feedback.persist_with(repository)
      AISupportAgent.trend_reports.persist_with(repository)
      feedback = AISupportAgent.feedback.create("incident-fallback", FeedbackRating::Incomplete, "operator")

      AISupportAgent.feedback.for_incident(feedback.incident_id).should eq [feedback]
      AISupportAgent.feedback.persistence_error.try(&.should contain "database offline")
      status = Root::Status.from_json(client.get("/api/ai-support/v1/status").body)
      status.persistence_enabled?.should be_true
      status.correlation_persistence_error.try(&.should contain "database offline")
      status.feedback_persistence_error.try(&.should contain "database offline")
      status.trend_persistence_error.try(&.should contain "database offline")
    end
  end
end
