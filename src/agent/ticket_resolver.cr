require "set"

module AISupportAgent
  struct TicketCandidate
    include JSON::Serializable

    getter kind : String
    getter id : String
    getter name : String?
    getter score : Float64
    getter matched : String

    def initialize(@kind : String, @id : String, @name : String?, @score : Float64, @matched : String)
    end
  end

  # The PlaceOS records a ticket was matched to, with every candidate considered.
  struct TicketResolution
    include JSON::Serializable

    getter tenant_id : String? = nil
    getter system_id : String? = nil
    getter module_id : String? = nil
    getter module_name : String? = nil
    getter candidates : Array(TicketCandidate) = [] of TicketCandidate
    getter notes : Array(String) = [] of String
    getter method : String = "none"

    def initialize(
      @tenant_id : String? = nil,
      @system_id : String? = nil,
      @module_id : String? = nil,
      @module_name : String? = nil,
      @candidates : Array(TicketCandidate) = [] of TicketCandidate,
      @notes : Array(String) = [] of String,
      @method : String = "none",
    )
    end

    def resolved? : Bool
      !module_id.nil? || !system_id.nil?
    end

    def ambiguous? : Bool
      !resolved? && !candidates.empty?
    end
  end

  # Maps the names and ids in a `TicketExtraction` to PlaceOS records through the
  # REST API. A lookup that fails or finds several equally good matches leaves the
  # id blank and records the candidates. Never raises.
  class TicketResolver
    # a candidate below this is not chosen on its own
    CHOOSE_AT = 0.8
    # a runner-up this close to the best makes the match ambiguous
    MARGIN = 0.15

    def initialize(@context : PlaceOSContext)
    end

    def resolve(extraction : TicketExtraction, io_timeout_seconds : Int32 = 10) : TicketResolution
      candidates = [] of TicketCandidate
      notes = [] of String
      methods = [] of String

      unless @context.rest_available?
        notes << "PlaceOS REST API is not configured; ids were taken from the ticket text only"
        return TicketResolution.new(
          system_id: extraction.system_ids.first?,
          module_id: extraction.module_ids.first?,
          notes: notes,
          method: extraction.module_ids.empty? && extraction.system_ids.empty? ? "none" : "ticket_ids"
        )
      end

      tenant_id = tenant_for(extraction, candidates, notes, io_timeout_seconds)

      system_id, system_name = system_by_id(extraction, candidates, notes, io_timeout_seconds)
      methods << "system_id" if system_id
      module_id, module_name, module_system = module_by_id(extraction, candidates, notes, io_timeout_seconds)
      methods << "module_id" if module_id
      system_id ||= module_system

      if system_id.nil? && !extraction.systems.empty?
        zone_ids = zones_for(extraction, candidates, notes, io_timeout_seconds)
        system_id, system_name = system_by_name(extraction, zone_ids, candidates, notes, io_timeout_seconds)
        methods << "system_name" if system_id
      end

      if module_id.nil? && !extraction.modules.empty?
        module_id, module_name, module_system = module_by_name(extraction, system_id, candidates, notes, io_timeout_seconds)
        methods << "module_name" if module_id
        system_id ||= module_system
      end

      if module_id.nil? && system_id.nil?
        notes << (extraction.targets? ? "no PlaceOS record matched the names in the ticket" : "the ticket names no system or module")
      end

      TicketResolution.new(
        tenant_id: tenant_id,
        system_id: system_id,
        module_id: module_id,
        module_name: module_name,
        candidates: candidates,
        notes: notes,
        method: methods.empty? ? "none" : methods.join("+")
      )
    rescue error
      AISupportAgent::Log.warn(exception: error) { "ticket resolution failed" }
      TicketResolution.new(notes: ["resolution failed: #{error.class}: #{error.message}"])
    end

    private def tenant_for(extraction, candidates, notes, timeout) : String?
      domains = get("/api/engine/v2/domains/?limit=50", timeout).as_a
      authorities = domains.compact_map do |authority|
        data = authority.as_h
        id = data["id"]?.try(&.as_s?)
        domain = data["domain"]?.try(&.as_s?)
        {id, domain, data["name"]?.try(&.as_s?)} if id && domain
      end
      matched = authorities.select { |_, domain, _| extraction.hosts.any? { |host| host.downcase == domain.downcase } }
      chosen = matched.first? || (authorities.size == 1 ? authorities.first : nil)
      return unless chosen

      candidates << TicketCandidate.new("authority", chosen[0], chosen[2] || chosen[1], 1.0, matched.empty? ? "only authority" : "host #{chosen[1]}")
      chosen[0]
    rescue error
      notes << "authority lookup failed: #{error.message}"
      nil
    end

    private def system_by_id(extraction, candidates, notes, timeout) : {String?, String?}
      extraction.system_ids.each do |system_id|
        data = get("/api/engine/v2/systems/#{URI.encode_path_segment(system_id)}", timeout).as_h
        name = data["display_name"]?.try(&.as_s?).presence || data["name"]?.try(&.as_s?)
        candidates << TicketCandidate.new("system", system_id, name, 1.0, "id in ticket")
        return {system_id, name}
      rescue error
        notes << "system #{system_id} named in the ticket could not be read: #{error.message}"
      end
      {nil, nil}
    end

    private def module_by_id(extraction, candidates, notes, timeout) : {String?, String?, String?}
      extraction.module_ids.each do |module_id|
        data = get("/api/engine/v2/modules/#{URI.encode_path_segment(module_id)}", timeout).as_h
        name = module_label(data)
        candidates << TicketCandidate.new("module", module_id, name, 1.0, "id in ticket")
        return {module_id, name, data["control_system_id"]?.try(&.as_s?)}
      rescue error
        notes << "module #{module_id} named in the ticket could not be read: #{error.message}"
      end
      {nil, nil, nil}
    end

    private def zones_for(extraction, candidates, notes, timeout) : Array(String)
      zone_ids = extraction.zone_ids.dup
      extraction.locations.first(3).each do |location|
        zones = get("/api/engine/v2/zones/?#{URI::Params.encode({"q" => location, "limit" => "5"})}", timeout).as_a
        zones.each do |zone|
          data = zone.as_h
          id = data["id"]?.try(&.as_s?) || next
          name = data["display_name"]?.try(&.as_s?).presence || data["name"]?.try(&.as_s?)
          candidates << TicketCandidate.new("zone", id, name, similarity(location, name), "location #{location.inspect}")
          zone_ids << id
        end
      rescue error
        notes << "zone search for #{location.inspect} failed: #{error.message}"
      end
      zone_ids.uniq
    end

    private def system_by_name(extraction, zone_ids, candidates, notes, timeout) : {String?, String?}
      found = [] of TicketCandidate
      in_zone = Set(String).new
      extraction.systems.first(4).each do |phrase|
        query = {"q" => phrase, "limit" => "5"}
        systems = get("/api/engine/v2/systems/?#{URI::Params.encode(query)}", timeout).as_a
        systems.each do |system|
          data = system.as_h
          id = data["id"]?.try(&.as_s?) || next
          name = data["display_name"]?.try(&.as_s?).presence || data["name"]?.try(&.as_s?)
          system_zones = data["zones"]?.try(&.as_a?).try(&.compact_map(&.as_s?)) || [] of String
          in_zone << id unless (system_zones & zone_ids).empty?
          found << TicketCandidate.new("system", id, name, similarity(phrase, name), "name #{phrase.inspect}")
        end
      rescue error
        notes << "system search for #{phrase.inspect} failed: #{error.message}"
      end
      candidates.concat(found)
      unless in_zone.empty?
        notes << "kept the #{in_zone.size} system(s) inside the zone named in the ticket"
        found = found.select { |candidate| in_zone.includes?(candidate.id) }
      end
      choose(found, "system", notes)
    end

    private def module_by_name(extraction, system_id, candidates, notes, timeout) : {String?, String?, String?}
      found = [] of TicketCandidate
      systems = {} of String => String?
      extraction.modules.first(4).each do |phrase|
        query = {"q" => phrase, "limit" => "10"}
        query["control_system_id"] = system_id if system_id
        modules = get("/api/engine/v2/modules/?#{URI::Params.encode(query)}", timeout).as_a
        modules.each do |mod|
          data = mod.as_h
          id = data["id"]?.try(&.as_s?) || next
          name = module_label(data)
          score = similarity(phrase, name)
          score = {score, 0.8}.max if modules.size == 1
          found << TicketCandidate.new("module", id, name, score, "name #{phrase.inspect}")
          systems[id] = data["control_system_id"]?.try(&.as_s?)
        end
      rescue error
        notes << "module search for #{phrase.inspect} failed: #{error.message}"
      end
      candidates.concat(found)
      id, name = choose(found, "module", notes)
      {id, name, id.try { |chosen| systems[chosen]? }}
    end

    private def choose(found : Array(TicketCandidate), kind : String, notes : Array(String)) : {String?, String?}
      best = found.uniq(&.id).sort_by(&.score).reverse
      return {nil, nil} if best.empty?
      top = best[0]
      if top.score < CHOOSE_AT
        notes << "#{kind} candidates were too weak to choose (best #{top.name.inspect} at #{top.score})"
        return {nil, nil}
      end
      if (second = best[1]?) && second.score > top.score - MARGIN
        notes << "ambiguous #{kind}: #{best.count { |candidate| candidate.score > top.score - MARGIN }} candidates match equally well"
        return {nil, nil}
      end
      {top.id, top.name}
    end

    # Token overlap between a phrase from the ticket and a PlaceOS name, 0 to 1.
    private def similarity(phrase : String, name : String?) : Float64
      return 0.5 unless name
      left = tokens(phrase)
      right = tokens(name)
      return 0.5 if left.empty? || right.empty?
      return 1.0 if left == right
      overlap = (left & right).size.to_f
      return 0.9 if overlap == left.size && left.size >= 2
      {0.5 + 0.5 * overlap / {left.size, right.size}.max, 0.95}.min
    end

    private def tokens(text : String) : Array(String)
      text.downcase.scan(/[a-z0-9]+/).map(&.[0]).reject { |token| token.in?("the", "a", "of", "and", "room", "module", "driver") }.uniq
    end

    private def module_label(data : Hash(String, JSON::Any)) : String?
      data["custom_name"]?.try(&.as_s?).presence || data["name"]?.try(&.as_s?)
    end

    private def get(path : String, timeout : Int32) : JSON::Any
      @context.get_json(path, timeout)
    end
  end
end
