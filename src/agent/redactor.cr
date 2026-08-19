module AISupportAgent
  module Redactor
    SENSITIVE_KEYS = %w[
      api_key
      authorization
      bearer
      bearer_token
      client_secret
      key
      password
      secret
      token
    ]

    REDACTED = JSON::Any.new("[redacted]")

    def self.redact(value : JSON::Any) : JSON::Any
      case raw = value.raw
      when Hash
        redacted = {} of String => JSON::Any
        raw.each do |key, child|
          redacted[key] = sensitive?(key) ? REDACTED : redact(child)
        end
        JSON::Any.new(redacted)
      when Array
        JSON::Any.new(raw.map { |child| redact(child) })
      else
        value
      end
    end

    def self.sensitive?(key : String) : Bool
      normalized = key.downcase.gsub("-", "_")
      SENSITIVE_KEYS.any? { |sensitive| normalized.includes?(sensitive) }
    end
  end
end
