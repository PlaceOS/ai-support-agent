module AISupportAgent
  class AIReporter
    SYSTEM_PROMPT = <<-PROMPT
      You are an AI support agent for PlaceOS. Generate structured JSON incident analysis for operators.
      The service is report-only. Do not claim that remediation was performed, and do not recommend unsafe direct process manipulation.
      Prefer concrete observations, likely cause, and next safe diagnostic step.
      Respond only with a JSON object that has exactly these keys:
      "summary": one string of one to three plain sentences, never an object or a list.
      "next_steps": an array of strings, one safe diagnostic step in each.
      "confidence": a number between 0 and 1.
      PROMPT

    # keys read, in this order, when the model sends an object where text was asked for
    TEXT_KEYS = %w(summary text description likely_cause cause analysis observation message step action)

    class ParseError < Exception
    end

    # an analysis that was attempted and produced nothing usable
    record Failure, reason : String

    def self.from_environment : AIReporter
      return disabled unless api_key = OPENAI_API_KEY

      config = if api_base = OPENAI_API_BASE
                 ::OpenAI::Client::Config.azure(api_key: api_key, api_base: api_base)
               else
                 ::OpenAI::Client::Config.default(api_key: api_key)
               end

      new(::OpenAI::Client.new(config), OPENAI_MODEL)
    end

    def self.disabled : AIReporter
      new
    end

    def self.fake(response : String) : AIReporter
      new(fake_response: AgentAnalysis.new(response))
    end

    def self.fake(response : AgentAnalysis) : AIReporter
      new(fake_response: response)
    end

    def initialize(
      @client : ::OpenAI::Client? = nil,
      @model : String = OPENAI_MODEL,
      @fake_response : AgentAnalysis? = nil,
    )
    end

    def enabled? : Bool
      !!@client || !!@fake_response
    end

    def analyze?(report : IncidentReport) : AgentAnalysis?
      analyze(report).as?(AgentAnalysis)
    end

    # @returns the analysis, a `Failure` when the attempt did not produce one, nil when AI is switched off. Never raises.
    def analyze(report : IncidentReport) : AgentAnalysis | Failure | Nil
      if fake = @fake_response
        return fake
      end

      return unless client = @client

      request = ::OpenAI::ChatCompletionRequest.new(
        model: @model,
        temperature: 0.2,
        max_tokens: 350,
        messages: [
          ::OpenAI::ChatMessage.new(role: :system, content: SYSTEM_PROMPT),
          ::OpenAI::ChatMessage.new(role: :user, content: report_prompt(report)),
        ]
      )
      request.response_format = ::OpenAI::ResponseFormat.new(::OpenAI::ResponseFormat::FormatType::JsonObject)
      response = client.chat_completion(request)

      content = response.choices.first?.try(&.message.content).presence
      return Failure.new("the model returned no content") unless content

      AIReporter.parse(content)
    rescue error : ParseError | JSON::ParseException
      AISupportAgent::Log.warn(exception: error) { "AI report reply could not be parsed" }
      Failure.new("the reply could not be parsed: #{error.message}")
    rescue error
      AISupportAgent::Log.warn(exception: error) { "AI report generation failed" }
      Failure.new("the request failed with #{error.class}")
    end

    # Reads a model reply into an analysis. Accepts a summary sent as an object,
    # steps sent as objects or one string, a confidence sent as a string, and a
    # reply wrapped in a markdown code fence.
    def self.parse(content : String) : AgentAnalysis
      reply = JSON.parse(unfenced(content)).as_h?
      raise ParseError.new("the reply is not a JSON object") unless reply

      summary = text_from(reply["summary"]?)
      raise ParseError.new("the reply has no usable summary") unless summary

      AgentAnalysis.new(summary, steps_from(reply["next_steps"]?), confidence_from(reply["confidence"]?))
    end

    private def self.unfenced(content : String) : String
      text = content.strip
      return text unless text.starts_with?("```")

      text.lchop("```json").lchop("```").rchop("```").strip
    end

    # @param numbers whether a bare number counts as text
    private def self.text_from(value : JSON::Any?, numbers : Bool = true) : String?
      case raw = value.try(&.raw)
      when String
        raw.strip.presence
      when Int64, Float64
        raw.to_s if numbers
      when Array(JSON::Any)
        raw.compact_map { |item| text_from(item, numbers) }.join(" ").presence
      when Hash(String, JSON::Any)
        TEXT_KEYS.each do |key|
          if text = text_from(raw[key]?, numbers: false)
            return text
          end
        end
        raw.compact_map { |key, item| text_from(item).try { |text| "#{key.tr("_", " ")}: #{text}" } }.join("; ").presence
      end
    end

    private def self.steps_from(value : JSON::Any?) : Array(String)
      case raw = value.try(&.raw)
      when Array(JSON::Any)
        raw.compact_map { |item| text_from(item) }
      when nil
        [] of String
      else
        [text_from(value)].compact
      end
    end

    private def self.confidence_from(value : JSON::Any?) : Float64?
      case raw = value.try(&.raw)
      when Float64, Int64
        raw.to_f
      when String
        raw.strip.to_f?
      end
    end

    private def report_prompt(report : IncidentReport) : String
      {
        incident_id:    report.incident_id,
        severity:       report.severity.to_s,
        classification: report.classification.to_s,
        confidence:     report.confidence,
        target:         report.module_name || report.module_id || report.system_id,
        evidence:       report.evidence.map { |item| {source: item.source, message: item.message} },
        plan:           report.investigation_plan.try { |plan| {goal: plan.goal, evidence_targets: plan.evidence_targets} },
        next_steps:     report.next_steps,
      }.to_json
    end
  end
end
