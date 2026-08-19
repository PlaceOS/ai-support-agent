require "spec"
require "webmock"
require "action-controller/spec_helper"
require "placeos-models/spec/generator"

require "../src/config"

module AISupportAgent::SpecPlaceOS
  extend self

  def configure_api_key : Nil
    token = ENV["PLACE_API_KEY"]? || raise "PLACE_API_KEY must be configured for the spec suite"
    parts = token.split('.', 2)
    raise "PLACE_API_KEY must use the id.secret format" unless parts.size == 2
    key_id, secret = parts

    authority = ::PlaceOS::Model::Authority.find_by_domain("rest-api") || begin
      created = ::PlaceOS::Model::Authority.new
      created.id = "ai-support-agent-spec-authority"
      created.name = "AI Support Agent Specs"
      created.domain = "rest-api"
      created.save!
      created
    end

    user = ::PlaceOS::Model::User.find?("ai-support-agent-spec-user") || begin
      created = ::PlaceOS::Model::User.new
      created.id = "ai-support-agent-spec-user"
      created.name = "AI Support Agent Specs"
      created.email = ::PlaceOS::Model::Email.new("ai-support-agent@example.test")
      created.authority = authority
      created.save!
      created
    end

    ::PlaceOS::Model::ApiKey.find?(key_id).try(&.destroy)
    api_key = ::PlaceOS::Model::ApiKey.new
    api_key.id = key_id
    api_key.name = "AI Support Agent Specs"
    api_key.secret = secret
    api_key.permissions = ::PlaceOS::Model::UserJWT::Permissions::AdminSupport
    api_key.user = user
    api_key.save!
  end
end

Spec.before_suite do
  unless AISupportAgent.database_configured? && AISupportAgent.configure_database
    raise "Postgres persistence must be available for the spec suite: #{AISupportAgent.persistence_schema_status.summary}"
  end

  AISupportAgent::SpecPlaceOS.configure_api_key
end

Spec.before_each do
  WebMock.reset

  unless AISupportAgent.configure_persistence(AISupportAgent::PostgresIncidentRepository.new)
    raise "Postgres persistence must be available for the spec suite: #{AISupportAgent.persistence_schema_status.summary}"
  end

  PgORM::Database.connection do |database|
    database.exec <<-SQL
      TRUNCATE TABLE
        ai_incidents,
        ai_maintenance_runs,
        ai_correlation_findings,
        ai_trend_reports
      RESTART IDENTITY CASCADE
      SQL
  end

  AISupportAgent.incidents.clear
  AISupportAgent.agent_runs.clear
  AISupportAgent.deliveries.clear
  AISupportAgent.delivery.configure(AISupportAgent::ReportDeliveryConfig.new)
  AISupportAgent.approvals.clear
  AISupportAgent.verification_runs.clear
  AISupportAgent.escalations.clear
  AISupportAgent.maintenance_runs.clear
  AISupportAgent.correlation_findings.clear
  AISupportAgent.feedback.clear
  AISupportAgent.trend_reports.clear
end

module AISupportAgent::SpecClient
  private CLIENT = ActionController::SpecHelper.client

  def client
    CLIENT
  end
end

include AISupportAgent::SpecClient
