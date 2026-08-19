require "./helper"

module AISupportAgent
  class FailingIncidentRepository < PostgresIncidentRepository
    def claim_incident(
      event : IncidentEvent,
      incident_id : String,
      owner_token : String,
      lease_seconds : Int32 = INCIDENT_CLAIM_LEASE_SECONDS,
    ) : IncidentClaim
      raise "database offline"
    end

    def find_by_correlation_key(correlation_key : String) : IncidentReport?
      nil
    end

    def find_report(id : String) : IncidentReport?
      nil
    end

    def find_run(id : String) : AgentRun?
      nil
    end

    def save_report(report : IncidentReport, event : IncidentEvent? = nil) : IncidentReport
      raise "database offline"
    end

    def save_run(run : AgentRun) : AgentRun
      raise "database offline"
    end

    def save_approval_request(request : ApprovalRequest) : ApprovalRequest
      raise "database offline"
    end

    def find_approval_request(id : String) : ApprovalRequest?
      nil
    end

    def approval_requests_for_incident(incident_id : String) : Array(ApprovalRequest)
      [] of ApprovalRequest
    end
  end

  describe AgentRunStore do
    it "persists agent runs when incidents are ingested" do
      report = AISupportAgent.ingest(IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "run-store",
        payload: JSON.parse({message: "runtime error"}.to_json),
        module_id: "mod-run"
      ))

      AISupportAgent.incidents.clear
      AISupportAgent.agent_runs.clear

      AISupportAgent.incidents.find(report.incident_id).should_not be_nil
      run = AISupportAgent.agent_runs.find(report.incident_id)
      AISupportAgent.agent_runs.persistence_error.should be_nil
      run.should_not be_nil
      if saved = run
        saved.investigation_plan.should_not be_nil
        saved.investigation_plan.try(&.playbook_id).should_not be_nil
        saved.investigation_plan.try(&.playbook_hash.to_s.size).should eq 64
        saved.decision.should_not be_nil
        saved.remediation_proposal.should be_nil
        saved.investigation.map(&.name).should contain "build_agent_decision"
      end
    end

    it "suppresses duplicate incident signals by correlation key" do
      event = IncidentEvent.new(
        source: IncidentSource::Webhook,
        severity: IncidentSeverity::Error,
        correlation_key: "duplicate-run-store",
        payload: JSON.parse({message: "runtime error"}.to_json),
        module_id: "mod-run"
      )

      first = AISupportAgent.ingest(event)
      second = AISupportAgent.ingest(event)

      first.incident_id.should eq second.incident_id
      second.duplicate_count.should eq 1
      second.investigation.map(&.name).should contain "deduplicate_signal"
      AISupportAgent.incidents.all.size.should eq 1
    end

    it "refuses a new uncoordinated incident when postgres claiming fails" do
      repository = FailingIncidentRepository.new
      AISupportAgent.incidents.persist_with(repository)
      AISupportAgent.agent_runs.persist_with(repository)

      expect_raises(IncidentClaimUnavailable, "database offline") do
        AISupportAgent.ingest(IncidentEvent.new(
          source: IncidentSource::Webhook,
          severity: IncidentSeverity::Error,
          correlation_key: "persistence-fallback",
          payload: JSON.parse({message: "runtime error"}.to_json),
          module_id: "mod-run"
        ))
      end

      incident_error = AISupportAgent.incidents.persistence_error
      run_error = AISupportAgent.agent_runs.persistence_error
      incident_error.should_not be_nil
      incident_error.try(&.should contain "database offline")
      run_error.should be_nil
      AISupportAgent.disable_persistence
      AISupportAgent.incidents.all.should be_empty
      AISupportAgent.agent_runs.all.should be_empty
      AISupportAgent.deliveries.all.should be_empty
    end
  end
end
