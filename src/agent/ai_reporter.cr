module AISupportAgent
  class AIReporter
    SYSTEM_PROMPT = <<-PROMPT
      You are an AI support agent for PlaceOS. Generate structured JSON incident analysis for operators.
      The service is report-only. Do not claim that remediation was performed, and do not recommend unsafe direct process manipulation.
      Prefer concrete observations, likely cause, and next safe diagnostic step.
      Respond only as JSON with keys: summary, next_steps, confidence.
      PROMPT

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

      content = response.choices.first?.try(&.message.content)
      return unless content

      AgentAnalysis.from_json(content)
    rescue error
      AISupportAgent::Log.warn(exception: error) { "AI report generation failed" }
      nil
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
