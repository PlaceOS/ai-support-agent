module AISupportAgent
  module WebhookIngest
    extend self

    def grafana(body : String) : IncidentEvent
      payload = JSON.parse(body)
      object = payload.as_h
      labels = object["commonLabels"]?.try(&.as_h?) || first_alert_labels(object)

      IncidentEvent.new(
        source: IncidentSource::Grafana,
        severity: grafana_severity(object, labels),
        tenant_id: label(labels, "tenant_id"),
        system_id: label(labels, "system_id"),
        module_id: label(labels, "module_id"),
        module_name: label(labels, "module_name") || label(labels, "module"),
        module_index: label(labels, "module_index").try(&.to_i?),
        correlation_key: text(object["groupKey"]?) || label(labels, "alertname") || UUID.random.to_s,
        payload: payload
      )
    end

    def generic(body : String) : IncidentEvent
      payload = JSON.parse(body)
      object = payload.as_h

      IncidentEvent.new(
        source: parse_source(object["source"]?.try(&.as_s?)),
        severity: parse_severity(object["severity"]?.try(&.as_s?)),
        tenant_id: object["tenant_id"]?.try(&.as_s?),
        system_id: object["system_id"]?.try(&.as_s?),
        module_id: object["module_id"]?.try(&.as_s?),
        module_name: object["module_name"]?.try(&.as_s?),
        module_index: object["module_index"]?.try(&.as_i?).try(&.to_i32),
        correlation_key: text(object["correlation_key"]?) || UUID.random.to_s,
        payload: object["payload"]? || payload
      )
    end

    private def first_alert_labels(object : Hash(String, JSON::Any)) : Hash(String, JSON::Any)
      object["alerts"]?
        .try(&.as_a?)
        .try(&.first?)
        .try(&.as_h["labels"]?)
        .try(&.as_h?) || {} of String => JSON::Any
    end

    private def label(labels : Hash(String, JSON::Any), key : String) : String?
      text(labels[key]?)
    end

    # the string at `value`, or nil when it is missing, not a string, or blank
    private def text(value : JSON::Any?) : String?
      IncidentEvent.scope_value(value.try(&.as_s?))
    end

    private def grafana_severity(object : Hash(String, JSON::Any), labels : Hash(String, JSON::Any)) : IncidentSeverity
      severity = label(labels, "severity")
      severity ||= object["status"]?.try(&.as_s?)
      parse_severity(severity)
    end

    private def parse_source(source : String?) : IncidentSource
      case source.try(&.downcase)
      when "grafana"
        IncidentSource::Grafana
      when "module_state"
        IncidentSource::ModuleState
      when "scheduled"
        IncidentSource::Scheduled
      else
        IncidentSource::Webhook
      end
    end

    private def parse_severity(severity : String?) : IncidentSeverity
      case severity.try(&.downcase)
      when "critical", "firing"
        IncidentSeverity::Critical
      when "warning", "warn"
        IncidentSeverity::Warning
      when "error"
        IncidentSeverity::Error
      else
        IncidentSeverity::Info
      end
    end
  end
end
