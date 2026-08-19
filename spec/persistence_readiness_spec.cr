require "./helper"

module AISupportAgent
  describe PersistenceSchema do
    it "accepts the complete persistence contract" do
      checked_at = Time.utc
      status = PersistenceSchema.validate(complete_persistence_inventory, checked_at)

      status.ready?.should be_true
      status.state.should eq "ready"
      status.checked_at.should eq checked_at
      status.missing_tables.should be_empty
      status.missing_columns.should be_empty
      status.missing_indexes.should be_empty
      status.missing_foreign_keys.should be_empty
      status.missing_checks.should be_empty
      status.error.should be_nil
    end

    it "reports missing tables, columns, indexes, and foreign keys together" do
      inventory = complete_persistence_inventory
      inventory.tables.delete("ai_trend_reports")
      inventory.tables["ai_incidents"].delete("resolved_at")
      inventory.indexes.delete("ai_incidents_active_correlation_key_index")
      inventory.foreign_keys.delete("ai_incident_reports_incident_id_fkey")
      inventory.checks.delete("ai_incidents_claim_state_check")

      status = PersistenceSchema.validate(inventory)

      status.ready?.should be_false
      status.state.should eq "invalid"
      status.missing_tables.should eq ["ai_trend_reports"]
      status.missing_columns.should eq({"ai_incidents" => ["resolved_at"]})
      status.missing_indexes.should eq ["ai_incidents_active_correlation_key_index"]
      status.missing_foreign_keys.should eq ["ai_incident_reports_incident_id_fkey"]
      status.missing_checks.should eq ["ai_incidents_claim_state_check"]
      status.summary.should contain "persistence schema is incomplete"
      status.summary.should contain "ai_incidents columns: resolved_at"
    end

    it "represents database inspection failures without claiming readiness" do
      status = PersistenceSchemaStatus.unavailable(Exception.new("database offline"))

      status.ready?.should be_false
      status.state.should eq "unavailable"
      status.error.should_not be_nil
      status.error.try(&.should contain "database offline")
      status.checked_at.should_not be_nil
    end
  end

  describe ".configure_persistence" do
    it "attaches every persistent store only after schema validation passes" do
      repository = SchemaStatusRepository.new(
        PersistenceSchema.validate(complete_persistence_inventory)
      )

      AISupportAgent.configure_persistence(repository).should be_true

      AISupportAgent.persistence_schema_status.ready?.should be_true
      AISupportAgent.incidents.persistence_enabled?.should be_true
      AISupportAgent.agent_runs.persistence_enabled?.should be_true
      AISupportAgent.deliveries.persistence_enabled?.should be_true
      AISupportAgent.approvals.persistence_enabled?.should be_true
      AISupportAgent.verification_runs.persistence_enabled?.should be_true
      AISupportAgent.escalations.persistence_enabled?.should be_true
      AISupportAgent.maintenance_runs.persistence_enabled?.should be_true
      AISupportAgent.correlation_findings.persistence_enabled?.should be_true
      AISupportAgent.feedback.persistence_enabled?.should be_true
      AISupportAgent.trend_reports.persistence_enabled?.should be_true
    end

    it "keeps persistence disabled when the schema is incomplete" do
      inventory = complete_persistence_inventory
      inventory.tables.delete("ai_incidents")
      repository = SchemaStatusRepository.new(PersistenceSchema.validate(inventory))

      AISupportAgent.configure_persistence(repository).should be_false

      AISupportAgent.persistence_schema_status.state.should eq "invalid"
      AISupportAgent.incidents.persistence_enabled?.should be_false
      AISupportAgent.agent_runs.persistence_enabled?.should be_false
      AISupportAgent.deliveries.persistence_enabled?.should be_false
      AISupportAgent.approvals.persistence_enabled?.should be_false
      AISupportAgent.verification_runs.persistence_enabled?.should be_false
      AISupportAgent.escalations.persistence_enabled?.should be_false
      AISupportAgent.maintenance_runs.persistence_enabled?.should be_false
      AISupportAgent.correlation_findings.persistence_enabled?.should be_false
      AISupportAgent.feedback.persistence_enabled?.should be_false
      AISupportAgent.trend_reports.persistence_enabled?.should be_false
    end

    it "keeps persistence disabled when database inspection is unavailable" do
      repository = SchemaStatusRepository.new(
        PersistenceSchemaStatus.unavailable(Exception.new("connection refused"))
      )

      AISupportAgent.configure_persistence(repository).should be_false

      AISupportAgent.persistence_schema_status.state.should eq "unavailable"
      AISupportAgent.persistence_schema_status.error.should_not be_nil
      AISupportAgent.persistence_schema_status.error.try(&.should contain "connection refused")
      AISupportAgent.incidents.persistence_enabled?.should be_false
    end
  end

  private class SchemaStatusRepository < PostgresIncidentRepository
    def initialize(@status : PersistenceSchemaStatus)
    end

    def persistence_schema_status : PersistenceSchemaStatus
      @status
    end
  end

  private def self.complete_persistence_inventory : PersistenceSchemaInventory
    tables = {} of String => Array(String)
    PersistenceSchema::REQUIRED_COLUMNS.each do |table, columns|
      tables[table] = columns.dup
    end
    PersistenceSchemaInventory.new(
      tables,
      PersistenceSchema::REQUIRED_INDEXES.dup,
      PersistenceSchema::REQUIRED_FOREIGN_KEYS.dup,
      PersistenceSchema::REQUIRED_CHECKS.dup
    )
  end
end
