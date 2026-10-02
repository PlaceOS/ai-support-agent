require "action-controller/logger"

module AISupportAgent
  APP_NAME = "ai-support-agent"
  {% begin %}
    VERSION = {{ `shards version "#{__DIR__}"`.chomp.stringify.downcase }}
  {% end %}

  Log         = ::Log.for(self)
  LOG_BACKEND = ActionController.default_backend

  ENVIRONMENT = ENV["SG_ENV"]?.presence || "development"

  BUILD_TIME   = {{ system("date -u").stringify.chomp }}
  BUILD_COMMIT = {{ env("PLACE_COMMIT") || "DEV" }}

  DEFAULT_PORT          = (ENV["SG_SERVER_PORT"]? || 3015).to_i
  DEFAULT_HOST          = ENV["SG_SERVER_HOST"]? || "127.0.0.1"
  DEFAULT_PROCESS_COUNT = (ENV["SG_PROCESS_COUNT"]? || 1).to_i

  OPENAI_API_KEY  = ENV["OPENAI_API_KEY"]?.presence
  OPENAI_API_BASE = ENV["OPENAI_API_BASE"]?.presence
  OPENAI_MODEL    = ENV["OPENAI_MODEL"]?.presence || "gpt-4o-mini"

  REPORT_WEBHOOK_URL    = ENV["REPORT_WEBHOOK_URL"]?.presence
  REPORT_EMAIL_TO       = ENV["REPORT_EMAIL_TO"]?.to_s.split(',').compact_map(&.strip.presence)
  REPORT_TEMPLATE_ID    = ENV["REPORT_TEMPLATE_ID"]?.presence || "operator-report"
  REPORT_TEMPLATES_PATH = ENV["REPORT_TEMPLATES_PATH"]?.presence

  REPORT_DELIVERY_TIMEOUT_SECONDS    = (ENV["REPORT_DELIVERY_TIMEOUT_SECONDS"]? || 10).to_i.clamp(1, 120)
  REPORT_DELIVERY_MAX_ATTEMPTS       = (ENV["REPORT_DELIVERY_MAX_ATTEMPTS"]? || 3).to_i.clamp(1, 10)
  REPORT_DELIVERY_RETRY_BASE_SECONDS = (ENV["REPORT_DELIVERY_RETRY_BASE_SECONDS"]? || 30).to_i.clamp(1, 3600)

  SMTP_SERVER      = ENV["SMTP_SERVER"]?.presence
  SMTP_PORT        = (ENV["SMTP_PORT"]? || 25).to_i
  SMTP_USER        = ENV["SMTP_USER"]?.presence
  SMTP_PASS        = ENV["SMTP_PASS"]?.presence
  SMTP_SECURE      = ENV["SMTP_SECURE"]?.presence || "NONE"
  SMTP_FROM_EMAIL  = ENV["SMTP_FROM_EMAIL"]?.presence
  SMTP_FROM_NAME   = ENV["SMTP_FROM_NAME"]?.presence || "PlaceOS Support Agent"
  SMTP_HELO_DOMAIN = ENV["SMTP_HELO_DOMAIN"]?.presence

  INCIDENT_CLAIM_LEASE_SECONDS     = (ENV["INCIDENT_CLAIM_LEASE_SECONDS"]? || 30).to_i.clamp(10, 300)
  INCIDENT_CLAIM_WAIT_MILLISECONDS = (ENV["INCIDENT_CLAIM_WAIT_MILLISECONDS"]? || 2_000).to_i.clamp(0, 30_000)
  INCIDENT_CLAIM_POLL_MILLISECONDS = (ENV["INCIDENT_CLAIM_POLL_MILLISECONDS"]? || 100).to_i.clamp(10, 1_000)
  INCIDENT_CLAIM_RENEWAL_SECONDS   = {INCIDENT_CLAIM_LEASE_SECONDS // 3, 1}.max

  class_getter? production : Bool = ENVIRONMENT.downcase == "production"

  def self.boolean_environment(key : String) : Bool
    !!ENV[key]?.presence.try(&.downcase.in?("1", "true"))
  end
end
