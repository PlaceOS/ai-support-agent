module AISupportAgent
  # What a ticket says, in the terms the agent can look up.
  struct TicketExtraction
    include JSON::Serializable

    CATEGORIES = %w(module device platform calendar auth user booking request commercial unknown)

    getter summary : String? = nil
    getter category : String = "unknown"
    getter environment : String? = nil
    getter module_ids : Array(String) = [] of String
    getter system_ids : Array(String) = [] of String
    getter zone_ids : Array(String) = [] of String
    getter driver_ids : Array(String) = [] of String
    getter hosts : Array(String) = [] of String
    getter systems : Array(String) = [] of String
    getter modules : Array(String) = [] of String
    getter locations : Array(String) = [] of String
    getter errors : Array(String) = [] of String
    getter urgency : String? = nil
    getter evidence_requests : Array(String) = [] of String
    getter method : String = "deterministic"

    def initialize(
      @summary : String? = nil,
      @category : String = "unknown",
      @environment : String? = nil,
      @module_ids : Array(String) = [] of String,
      @system_ids : Array(String) = [] of String,
      @zone_ids : Array(String) = [] of String,
      @driver_ids : Array(String) = [] of String,
      @hosts : Array(String) = [] of String,
      @systems : Array(String) = [] of String,
      @modules : Array(String) = [] of String,
      @locations : Array(String) = [] of String,
      @errors : Array(String) = [] of String,
      @urgency : String? = nil,
      @evidence_requests : Array(String) = [] of String,
      @method : String = "deterministic",
    )
    end

    # This extraction with `other` layered on top: lists are unioned, a scalar
    # in `other` wins when present.
    def merge(other : TicketExtraction, method : String) : TicketExtraction
      TicketExtraction.new(
        summary: other.summary || summary,
        category: other.category == "unknown" ? category : other.category,
        environment: other.environment || environment,
        module_ids: union(module_ids, other.module_ids),
        system_ids: union(system_ids, other.system_ids),
        zone_ids: union(zone_ids, other.zone_ids),
        driver_ids: union(driver_ids, other.driver_ids),
        hosts: union(hosts, other.hosts),
        systems: union(systems, other.systems),
        modules: union(modules, other.modules),
        locations: union(locations, other.locations),
        errors: union(errors, other.errors),
        urgency: other.urgency || urgency,
        evidence_requests: union(evidence_requests, other.evidence_requests),
        method: method
      )
    end

    def targets? : Bool
      !(module_ids.empty? && system_ids.empty? && systems.empty? && modules.empty?)
    end

    private def union(left : Array(String), right : Array(String)) : Array(String)
      (left + right).map(&.strip).reject(&.empty?).uniq { |value| value.downcase }
    end
  end

  # Reads a ticket into a `TicketExtraction`: regular expressions first, then an
  # optional language model pass layered on top. Never raises.
  class TicketExtractor
    PLACEOS_ID   = /\b(mod|sys|zone|driver)-(?=[A-Za-z0-9~_-]*[0-9A-Z])[A-Za-z0-9~_-]{3,}/
    URL_HOST     = /https?:\/\/([a-z0-9.-]+\.[a-z]{2,})/i
    PLACEOS_HOST = /\b([a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:placeos\.run|placeos\.com|aca\.im))\b/i
    NAMED_UNIT   = /\b((?:[A-Za-z0-9&\/.-]+[ \t]){1,4})(?:modules?|drivers?)\b/i
    ROOM         = /\b(?:room|boardroom|meeting room|training room|system)\s+([A-Z0-9][\w.\-]{0,24})/i
    LEVEL_ROOM   = /\b(L\d{1,2}\.\d{1,3})\b/
    PARENTHESES  = /\(([^()]{3,40})\)/
    QUOTED       = /["“]([^"”]{3,60})["”]/
    LOCATION     = /\b(?:building|level|floor|site|office|tower)\s+([A-Z0-9][\w.\-]{0,15})/i
    BUILDING     = /\b([A-Z]{1,3}\d{2,4}[A-Z]?|\d{3,4}[A-Z])\b/
    ERROR_LINE   = /(?:error|exception|timeout|timed out|refused|unauthori[sz]ed|forbidden|\b40[134]\b|\b50[0-4]\b|crashloop|oomkilled|not (?:responding|connecting|loading|syncing)|offline|stack ?trace|certificate)/i
    STOPWORDS    = %w(the a an our this that these those one of some my your their its in on for with to is are was were be been has have had and or)

    INTEGRATIONS = {
      "azure ad"     => /\b(?:azure ad|aad|entra|active directory|ad sync|user sync)\b/i,
      "floorsense"   => /\bfloorsense\b/i,
      "gallagher"    => /\bgallagher\b/i,
      "integriti"    => /\bintegriti\b/i,
      "lenel"        => /\blenel\b/i,
      "exchange"     => /\b(?:exchange|ews)\b/i,
      "graph"        => /\b(?:ms graph|microsoft graph|graph api)\b/i,
      "office 365"   => /\b(?:office ?365|o365)\b/i,
      "google"       => /\bgoogle (?:calendar|workspace)\b/i,
      "calendar"     => /\b(?:calendar|bookings? (?:driver|module|sync))\b/i,
      "mailer"       => /\b(?:mailer|smtp)\b/i,
      "locker"       => /\blockers?\b/i,
      "desk booking" => /\bdesk booking\b/i,
      "lutron"       => /\blutron\b/i,
      "cisco"        => /\b(?:cisco|webex)\b/i,
      "samsung"      => /\bsamsung\b/i,
      "crestron"     => /\bcrestron\b/i,
      "extron"       => /\bextron\b/i,
      "biamp"        => /\bbiamp\b/i,
      "shure"        => /\bshure\b/i,
      "qsc"          => /\bqsc\b/i,
      "polycom"      => /\bpolycom\b/i,
      "logitech"     => /\blogitech\b/i,
      "projector"    => /\bprojectors?\b/i,
      "display"      => /\b(?:displays?|screens?|tv)\b/i,
      "camera"       => /\bcameras?\b/i,
      "lighting"     => /\b(?:lights?|lighting)\b/i,
      "blinds"       => /\bblinds?\b/i,
      "dsp"          => /\b(?:dsp|audio|microphones?|mics?)\b/i,
      "sensor"       => /\b(?:sensors?|vergesense|xovis|occupancy)\b/i,
      "meraki"       => /\bmeraki\b/i,
      "visitor"      => /\bvisitors?\b/i,
      "signage"      => /\b(?:signage|player)\b/i,
    }

    CATEGORY_WORDS = {
      "module"     => /\b(?:modules?|drivers?|sync|runtime error|core pods?|not loading|logic|binding|status (?:key|value))\b/i,
      "device"     => /\b(?:display|projector|screen|touch ?panel|panel|camera|audio|mic|volume|lights?|lighting|blinds?|dsp|vc|webex|cisco|samsung|hdmi|comms error|offline|not responding|wake)\b/i,
      "platform"   => /\b(?:pods?|kubernetes|k8s|openshift|cluster|elastic(?:search)?|redis|postgres|disk|memory|cpu|cert(?:ificate)?|ssl|tls|502|503|504|upgrade|version|docker|container|outage|ingress|helm|search-ingest|re-?index)\b/i,
      "calendar"   => /\b(?:o365|office ?365|exchange|ews|graph|calendar|mailbox|outlook|room resource|impersonation)\b/i,
      "auth"       => /\b(?:sso|saml|adfs|azure ad login|log ?in|sign ?in|password|401|403|unauthori[sz]ed|forbidden|credentials?)\b/i,
      "user"       => /\b(?:user accounts?|add(?:ing)? (?:a |new )?users?|remove users?|delete users?|duplicate users?|permissions?|admin access)\b/i,
      "booking"    => /\b(?:book(?:ing|ings|ed)?|desk|locker|visitor|parking|catering|maps?|svg|floor ?plan|concierge|workplace|workmate|kiosk)\b/i,
      "request"    => /\b(?:please (?:add|change|update|remove|rename|set|configure)|rename|change request|new room|new site|new building|configure)\b/i,
      "commercial" => /\b(?:licen[cs]e|quote|pricing|invoice|contract|purchase order|reseller)\b/i,
    }

    ENVIRONMENTS = {
      "ppe"        => /\b(?:ppe|pre-?prod(?:uction)?)\b/i,
      "uat"        => /\buat\b/i,
      "staging"    => /\b(?:staging|stage)\b/i,
      "dev"        => /\b(?:dev|development|non-?prod)\b/i,
      "production" => /\b(?:prod|production)\b/i,
    }

    SYSTEM_PROMPT = <<-PROMPT
      You read support tickets for PlaceOS, a smart building platform. In PlaceOS a "system" is a room or space
      (Backoffice shows them as systems), a "module" is a running instance of a "driver" (an integration or device
      control such as Azure AD user sync, Floorsense desk sync, a Samsung display, an Exchange calendar), a "zone"
      is an organisation, building, level or area, and the platform runs as services and pods (core, rest-api,
      staff-api, search-ingest, triggers). Extract what the ticket names so an operator can look it up.
      Respond only with a JSON object with exactly these keys:
      "summary": one plain sentence saying what is wrong.
      "category": one of module, device, platform, calendar, auth, user, booking, request, commercial, unknown.
      "environment": one of production, ppe, uat, staging, dev, unknown.
      "systems": array of room or system names mentioned, as written.
      "modules": array of module, driver, integration or device names mentioned, as written.
      "locations": array of building, level or floor names mentioned.
      "errors": array of error messages or symptoms quoted from the ticket, each under 200 characters.
      "hosts": array of PlaceOS hostnames mentioned.
      "urgency": one of low, medium, high, critical.
      "evidence_requests": array of short questions a support engineer would ask the reporter before investigating.
      PROMPT

    def self.from_environment : TicketExtractor
      return disabled unless api_key = OPENAI_API_KEY

      config = if api_base = OPENAI_API_BASE
                 ::OpenAI::Client::Config.azure(api_key: api_key, api_base: api_base)
               else
                 ::OpenAI::Client::Config.default(api_key: api_key)
               end
      new(::OpenAI::Client.new(config), TICKET_EXTRACTION_MODEL)
    end

    def self.disabled : TicketExtractor
      new
    end

    def self.fake(extraction : TicketExtraction) : TicketExtractor
      new(fake_response: extraction)
    end

    def initialize(
      @client : ::OpenAI::Client? = nil,
      @model : String = TICKET_EXTRACTION_MODEL,
      @fake_response : TicketExtraction? = nil,
    )
    end

    def ai_enabled? : Bool
      !!@client || !!@fake_response
    end

    def extract(ticket : SupportTicket) : TicketExtraction
      base = TicketExtractor.deterministic(ticket)
      if fake = @fake_response
        return base.merge(fake, "deterministic+ai")
      end
      return base unless client = @client

      if ai = ask_model(client, ticket)
        base.merge(ai, "deterministic+ai")
      else
        base
      end
    end

    # @returns the model's extraction, nil when the request or the reply is unusable. Never raises.
    private def ask_model(client : ::OpenAI::Client, ticket : SupportTicket) : TicketExtraction?
      request = ::OpenAI::ChatCompletionRequest.new(
        model: @model,
        temperature: 0.0,
        max_tokens: 700,
        messages: [
          ::OpenAI::ChatMessage.new(role: :system, content: SYSTEM_PROMPT),
          ::OpenAI::ChatMessage.new(role: :user, content: prompt_for(ticket)),
        ]
      )
      request.response_format = ::OpenAI::ResponseFormat.new(::OpenAI::ResponseFormat::FormatType::JsonObject)
      response = client.chat_completion(request)
      content = response.choices.first?.try(&.message.content).presence
      return unless content

      TicketExtractor.parse(content)
    rescue error
      AISupportAgent::Log.warn(exception: error) { "ticket extraction by the model failed; keeping the deterministic extraction" }
      nil
    end

    # Reads a model reply. Missing or oddly typed keys are ignored.
    def self.parse(content : String) : TicketExtraction
      text = content.strip
      text = text.lchop("```json").lchop("```").rchop("```").strip if text.starts_with?("```")
      reply = JSON.parse(text).as_h? || raise ArgumentError.new("the reply is not a JSON object")

      category = string(reply["category"]?).try(&.downcase)
      environment = string(reply["environment"]?).try(&.downcase)
      TicketExtraction.new(
        summary: string(reply["summary"]?),
        category: category.try { |value| TicketExtraction::CATEGORIES.includes?(value) ? value : nil } || "unknown",
        environment: environment == "unknown" ? nil : environment,
        hosts: strings(reply["hosts"]?),
        systems: strings(reply["systems"]?),
        modules: strings(reply["modules"]?),
        locations: strings(reply["locations"]?),
        errors: strings(reply["errors"]?).map { |value| value[0, 200] },
        urgency: string(reply["urgency"]?).try(&.downcase),
        evidence_requests: strings(reply["evidence_requests"]?),
        method: "ai"
      )
    end

    def self.deterministic(ticket : SupportTicket) : TicketExtraction
      text = ticket.text
      summary = ticket.summary

      ids = text.scan(PLACEOS_ID).map { |match| match[0].rstrip("-_.") }.uniq
      hosts = (text.scan(URL_HOST).map(&.[1]) + text.scan(PLACEOS_HOST).map(&.[1])).map(&.downcase).uniq
        .reject { |host| host.ends_with?("atlassian.net") || host.includes?("github.com") || host.includes?("kubernetes.io") }

      modules = INTEGRATIONS.compact_map { |name, pattern| name if pattern.matches?(text) }
      text.scan(NAMED_UNIT) do |match|
        phrase = match[1].split.map(&.strip).reject { |word| STOPWORDS.includes?(word.downcase) }.join(" ")
        modules << phrase if phrase.size >= 3 && phrase.size <= 40
      end

      systems = [] of String
      [summary, text].each do |source|
        source.scan(ROOM) { |match| systems << match[1].rstrip(".,") }
        source.scan(LEVEL_ROOM) { |match| systems << match[1] }
      end
      summary.scan(PARENTHESES) { |match| systems << match[1] }
      summary.scan(QUOTED) { |match| systems << match[1] }

      locations = [] of String
      text.scan(LOCATION) { |match| locations << match[1].rstrip(".,") }
      summary.scan(BUILDING) { |match| locations << match[1] }

      errors = text.lines.compact_map do |line|
        stripped = line.strip
        stripped[0, 200] if stripped.size >= 8 && ERROR_LINE.matches?(stripped)
      end.first(6)

      TicketExtraction.new(
        category: category_for(summary, text),
        environment: environment_for(summary, text),
        module_ids: ids.select(&.starts_with?("mod-")),
        system_ids: ids.select(&.starts_with?("sys-")),
        zone_ids: ids.select(&.starts_with?("zone-")),
        driver_ids: ids.select(&.starts_with?("driver-")),
        hosts: hosts,
        systems: clean_list(systems, 8),
        modules: clean_list(modules, 8),
        locations: clean_list(locations, 6),
        errors: errors,
        urgency: urgency_for(ticket, summary, text)
      )
    end

    private def self.category_for(summary : String, text : String) : String
      scores = CATEGORY_WORDS.to_h do |name, pattern|
        in_summary = summary.scan(pattern).map { |match| match[0].downcase }.uniq.size
        in_text = text.scan(pattern).map { |match| match[0].downcase }.uniq.size
        {name, in_text + 3 * in_summary}
      end
      best = scores.max_by { |_, score| score }
      return "unknown" if best[1] == 0
      return "unknown" if scores.count { |_, score| score == best[1] } > 1
      best[0]
    end

    private def self.environment_for(summary : String, text : String) : String?
      ENVIRONMENTS.each { |name, pattern| return name if pattern.matches?(summary) }
      ENVIRONMENTS.each { |name, pattern| return name if pattern.matches?(text) }
      nil
    end

    private def self.urgency_for(ticket : SupportTicket, summary : String, text : String) : String
      case ticket.priority.try(&.downcase)
      when "extreme", "very high", "highest", "blocker" then return "critical"
      when "high"                                       then return "high"
      end
      return "critical" if summary.matches?(/\b(?:outage|urgent|p1|critical|is down|site wide)\b/i)
      return "high" if text.matches?(/\b(?:urgent|asap|outage|not working for (?:all|every)|blocked)\b/i)
      ticket.priority.try(&.downcase) == "low" ? "low" : "medium"
    end

    private def self.clean_list(values : Array(String), limit : Int32) : Array(String)
      values.map(&.strip).reject(&.empty?).uniq { |value| value.downcase }.first(limit)
    end

    private def self.string(value : JSON::Any?) : String?
      value.try(&.as_s?).try(&.strip.presence)
    end

    private def self.strings(value : JSON::Any?) : Array(String)
      case raw = value.try(&.raw)
      when Array(JSON::Any) then raw.compact_map { |item| string(item) }
      when String           then [raw.strip].reject(&.empty?)
      else                       [] of String
      end
    end

    private def prompt_for(ticket : SupportTicket) : String
      {
        reference:    ticket.reference,
        organisation: ticket.organisation,
        priority:     ticket.priority,
        request_type: ticket.request_type,
        attachments:  ticket.attachments.map(&.filename),
        text:         ticket.text[0, 6000],
      }.to_json
    end
  end
end
