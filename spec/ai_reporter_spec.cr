require "./helper"

module AISupportAgent
  OPENAI_TEST_BASE = "http://openai.test/v1"

  def self.openai_reply(content : String?) : String
    {
      id:      "chatcmpl-spec",
      object:  "chat.completion",
      created: 1_790_000_000,
      model:   "gpt-4o-mini",
      choices: [{
        index:         0,
        message:       {role: "assistant", content: content},
        finish_reason: "stop",
      }],
      usage: {prompt_tokens: 120, completion_tokens: 80, total_tokens: 200},
    }.to_json
  end

  def self.openai_reporter : AIReporter
    AIReporter.new(::OpenAI::Client.new("spec-key", OPENAI_TEST_BASE), "gpt-4o-mini")
  end

  def self.auth_failure_event(key : String) : IncidentEvent
    IncidentEvent.new(
      source: IncidentSource::Webhook,
      severity: IncidentSeverity::Error,
      correlation_key: key,
      payload: JSON.parse({error: "HTTP 401 Unauthorized from upstream"}.to_json),
      module_name: "Display"
    )
  end

  # what gpt-4o-mini sent back for the original prompt on 29 Sep 2026
  OBJECT_SUMMARY_REPLY = {
    summary: {
      incident_id:    "aisup-x",
      severity:       "error",
      classification: "http_auth",
      target:         "Display",
      evidence:       [{source: "webhook", message: "HTTP 401 Unauthorized"}],
      likely_cause:   "The HTTP request to the Display service was unauthorized, indicating that the provided credentials may be incorrect or missing.",
    },
    next_steps: [
      "Verify the credentials being used for the HTTP authentication.",
      "Check the configuration settings for the Display service to ensure the correct credentials are specified.",
    ],
    confidence: 0.75,
  }.to_json

  describe AIReporter do
    describe ".parse" do
      it "reads a reply in the requested shape" do
        analysis = AIReporter.parse({
          summary:    "The display rejected the stored credentials.",
          next_steps: ["Check the module settings."],
          confidence: 0.8,
        }.to_json)

        analysis.summary.should eq "The display rejected the stored credentials."
        analysis.next_steps.should eq ["Check the module settings."]
        analysis.confidence.should eq 0.8
      end

      it "reads a summary sent as an object" do
        analysis = AIReporter.parse(OBJECT_SUMMARY_REPLY)

        analysis.summary.should start_with "The HTTP request to the Display service was unauthorized"
        analysis.next_steps.size.should eq 2
        analysis.confidence.should eq 0.75
      end

      it "joins the fields of an object that has no known text key" do
        analysis = AIReporter.parse({summary: {root_cause: "expired token", scope: "one module"}}.to_json)

        analysis.summary.should eq "root cause: expired token; scope: one module"
        analysis.next_steps.should be_empty
        analysis.confidence.should be_nil
      end

      it "reads steps sent as objects or as one string" do
        AIReporter.parse({
          summary:    "Credentials rejected.",
          next_steps: [{step: 1, action: "Check the module settings."}, "Retry the connection."],
        }.to_json).next_steps.should eq ["Check the module settings.", "Retry the connection."]

        AIReporter.parse({
          summary:    "Credentials rejected.",
          next_steps: "Check the module settings.",
        }.to_json).next_steps.should eq ["Check the module settings."]

        AIReporter.parse({
          summary:    "Credentials rejected.",
          next_steps: [{step: "Check the module settings.", priority: 1}],
        }.to_json).next_steps.should eq ["Check the module settings."]
      end

      it "reads a confidence sent as a string" do
        AIReporter.parse({summary: "Credentials rejected.", confidence: "0.6"}.to_json).confidence.should eq 0.6
        AIReporter.parse({summary: "Credentials rejected.", confidence: "high"}.to_json).confidence.should be_nil
      end

      it "reads a reply wrapped in a code fence" do
        fenced = "```json\n#{{summary: "Credentials rejected."}.to_json}\n```"

        AIReporter.parse(fenced).summary.should eq "Credentials rejected."
      end

      it "rejects a reply with no usable summary" do
        expect_raises(AIReporter::ParseError, "no usable summary") do
          AIReporter.parse({summary: {} of String => String, next_steps: ["Check the module settings."]}.to_json)
        end
        expect_raises(AIReporter::ParseError, "not a JSON object") do
          AIReporter.parse(["Credentials rejected."].to_json)
        end
      end
    end

    describe "#analyze" do
      it "returns nil when AI is switched off" do
        report = DiagnosticEngine.new(PlaceOSContext.static([] of Evidence), AIReporter.disabled)
          .report_for(Incident.new("aisup-ai-off", AISupportAgent.auth_failure_event("ai-off"), Time.utc))

        AIReporter.disabled.analyze(report).should be_nil
      end

      it "parses the reply the API returns for a summary sent as an object" do
        completions = WebMock.stub(:post, "#{OPENAI_TEST_BASE}/chat/completions")
          .to_return(body: AISupportAgent.openai_reply(OBJECT_SUMMARY_REPLY))
        report = DiagnosticEngine.new(PlaceOSContext.static([] of Evidence), AIReporter.disabled)
          .report_for(Incident.new("aisup-ai-object", AISupportAgent.auth_failure_event("ai-object"), Time.utc))

        analysis = AISupportAgent.openai_reporter.analyze(report)

        completions.calls.should eq 1
        analysis.should be_a AgentAnalysis
        analysis.as(AgentAnalysis).summary.should start_with "The HTTP request to the Display service was unauthorized"
      end

      it "reports a reply that is not JSON as a failure" do
        WebMock.stub(:post, "#{OPENAI_TEST_BASE}/chat/completions")
          .to_return(body: AISupportAgent.openai_reply("I could not analyse this incident."))
        report = DiagnosticEngine.new(PlaceOSContext.static([] of Evidence), AIReporter.disabled)
          .report_for(Incident.new("aisup-ai-text", AISupportAgent.auth_failure_event("ai-text"), Time.utc))

        failure = AISupportAgent.openai_reporter.analyze(report)

        failure.should be_a AIReporter::Failure
        failure.as(AIReporter::Failure).reason.should start_with "the reply could not be parsed"
      end

      it "reports a rejected request as a failure without the vendor's message" do
        WebMock.stub(:post, "#{OPENAI_TEST_BASE}/chat/completions")
          .to_return(status: 401, body: {error: {message: "Incorrect API key provided: spec-key", type: "invalid_request_error", code: "invalid_api_key"}}.to_json)
        report = DiagnosticEngine.new(PlaceOSContext.static([] of Evidence), AIReporter.disabled)
          .report_for(Incident.new("aisup-ai-401", AISupportAgent.auth_failure_event("ai-401"), Time.utc))

        failure = AISupportAgent.openai_reporter.analyze(report)

        failure.should be_a AIReporter::Failure
        reason = failure.as(AIReporter::Failure).reason
        reason.should start_with "the request failed with"
        reason.should_not contain "spec-key"
      end
    end

    describe "in a diagnostic report" do
      it "carries the AI analysis when the summary arrives as an object" do
        WebMock.stub(:post, "#{OPENAI_TEST_BASE}/chat/completions")
          .to_return(body: AISupportAgent.openai_reply(OBJECT_SUMMARY_REPLY))

        report = DiagnosticEngine.new(PlaceOSContext.static([] of Evidence), AISupportAgent.openai_reporter)
          .report_for(Incident.new("aisup-ai-report", AISupportAgent.auth_failure_event("ai-report"), Time.utc))

        report.summary.should start_with "The HTTP request to the Display service was unauthorized"
        report.next_steps.size.should eq 2
        report.evidence.map(&.source).should contain "openai"
        step = report.investigation.last
        step.name.should eq "ai_structured_analysis"
        step.status.completed?.should be_true
      end

      it "records a failed AI step before the fallback" do
        WebMock.stub(:post, "#{OPENAI_TEST_BASE}/chat/completions")
          .to_return(body: AISupportAgent.openai_reply("I could not analyse this incident."))

        report = DiagnosticEngine.new(PlaceOSContext.static([] of Evidence), AISupportAgent.openai_reporter)
          .report_for(Incident.new("aisup-ai-failed", AISupportAgent.auth_failure_event("ai-failed"), Time.utc))

        report.evidence.map(&.source).should_not contain "openai"
        report.next_steps.should_not be_empty
        failed, fallback = report.investigation.last(2)
        failed.name.should eq "ai_structured_analysis"
        failed.status.failed?.should be_true
        failed.summary.should start_with "AI analysis failed: the reply could not be parsed"
        fallback.name.should eq "deterministic_fallback"
        fallback.status.completed?.should be_true
      end

      it "records only the fallback when AI is switched off" do
        report = DiagnosticEngine.new(PlaceOSContext.static([] of Evidence), AIReporter.disabled)
          .report_for(Incident.new("aisup-ai-disabled", AISupportAgent.auth_failure_event("ai-disabled"), Time.utc))

        report.investigation.map(&.name).should_not contain "ai_structured_analysis"
        report.investigation.last.name.should eq "deterministic_fallback"
      end
    end
  end
end
