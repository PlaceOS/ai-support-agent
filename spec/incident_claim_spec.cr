require "./helper"

module AISupportAgent
  enum ClaimTestMode
    Acquired
    Existing
    Takeover
    Failed
  end

  class ClaimTestRepository < PostgresIncidentRepository
    property mode = ClaimTestMode::Acquired
    property winner_report : IncidentReport?
    property? fail_save = false
    property? lose_on_save = false
    getter claim_calls = 0
    getter renewal_calls = 0
    getter saved_token : String?

    def claim_incident(
      event : IncidentEvent,
      incident_id : String,
      owner_token : String,
      lease_seconds : Int32 = INCIDENT_CLAIM_LEASE_SECONDS,
    ) : IncidentClaim
      @claim_calls += 1
      case mode
      in .acquired?
        IncidentClaim.acquired(incident_id, owner_token, Time.utc + lease_seconds.seconds)
      in .existing?
        IncidentClaim.existing("aisup-existing-claim", Time.utc + lease_seconds.seconds)
      in .takeover?
        if claim_calls == 1
          IncidentClaim.existing("aisup-stale-claim", Time.utc - 1.second)
        else
          IncidentClaim.acquired("aisup-stale-claim", owner_token, Time.utc + lease_seconds.seconds)
        end
      in .failed?
        raise "database offline"
      end
    end

    def renew_incident_claim(
      incident_id : String,
      owner_token : String,
      lease_seconds : Int32 = INCIDENT_CLAIM_LEASE_SECONDS,
    ) : Bool
      @renewal_calls += 1
      true
    end

    def find_by_correlation_key(correlation_key : String) : IncidentReport?
      nil
    end

    def find_report(id : String) : IncidentReport?
      winner_report.try { |report| report.incident_id == id ? report : nil }
    end

    def incident_observations_since(time : Time) : Array(IncidentObservation)
      [] of IncidentObservation
    end

    def save_report(
      report : IncidentReport,
      event : IncidentEvent? = nil,
      claim_token : String? = nil,
    ) : IncidentReport
      @saved_token = claim_token
      raise IncidentClaimLost.new(report.incident_id) if lose_on_save?
      raise "database offline" if fail_save?
      report
    end
  end

  describe "incident claim leases" do
    it "acquires and renews an owned database claim" do
      repository = ClaimTestRepository.new
      store = IncidentStore.new
      store.persist_with(repository)

      claim = store.claim(claim_event("claim:acquire"), "aisup-proposed")

      claim.should_not be_nil
      claim.try(&.acquired?).should be_true
      claim.try(&.incident_id).should eq "aisup-proposed"
      claim.try(&.token).should_not be_nil
      claim.try { |owned| store.renew_claim(owned) }.should be_true
      repository.claim_calls.should eq 1
      repository.renewal_calls.should eq 1
    end

    it "returns the database winner instead of acquiring a second incident" do
      repository = ClaimTestRepository.new
      repository.mode = ClaimTestMode::Existing
      store = IncidentStore.new
      store.persist_with(repository)

      claim = store.claim(claim_event("claim:existing"), "aisup-loser")

      claim.should_not be_nil
      claim.try(&.acquired?).should be_false
      claim.try(&.incident_id).should eq "aisup-existing-claim"
      claim.try(&.owner_token).should be_nil
    end

    it "takes over an expired claim using the original incident ID" do
      repository = ClaimTestRepository.new
      repository.mode = ClaimTestMode::Takeover
      store = IncidentStore.new
      store.persist_with(repository)
      event = claim_event("claim:takeover")

      stale = store.claim(event, "aisup-loser").as(IncidentClaim)
      takeover = store.claim(event, "aisup-another-proposal").as(IncidentClaim)

      stale.acquired?.should be_false
      takeover.acquired?.should be_true
      takeover.incident_id.should eq stale.incident_id
      takeover.incident_id.should eq "aisup-stale-claim"
    end

    it "does not cache a claimed report when authoritative finalization fails" do
      repository = ClaimTestRepository.new
      repository.fail_save = true
      store = IncidentStore.new
      store.persist_with(repository)
      claim = store.claim(claim_event("claim:strict"), "aisup-strict")
      claim.should_not be_nil
      owned = claim.as(IncidentClaim)
      report = claim_report("aisup-strict", "claim:strict")

      expect_raises(Exception, "database offline") do
        store.save(report, claim_token: owned.token)
      end

      store.persistence_error.try(&.should contain "database offline")
      store.disable_persistence
      store.find(report.incident_id).should be_nil
    end

    it "renews an owned claim until the heartbeat is stopped" do
      repository = ClaimTestRepository.new
      store = IncidentStore.new
      store.persist_with(repository)
      claim = store.claim(claim_event("claim:heartbeat"), "aisup-heartbeat").as(IncidentClaim)
      heartbeat = IncidentClaimHeartbeat.new(store, claim, 1.millisecond)

      20.times do
        break if repository.renewal_calls > 0
        sleep 1.millisecond
      end
      repository.renewal_calls.should be > 0

      heartbeat.stop
      sleep 3.milliseconds
      settled_count = repository.renewal_calls
      sleep 3.milliseconds
      repository.renewal_calls.should eq settled_count
    end

    it "fences an owner whose token was replaced" do
      repository = ClaimTestRepository.new
      repository.lose_on_save = true
      store = IncidentStore.new
      store.persist_with(repository)
      claim = store.claim(claim_event("claim:lost"), "aisup-lost").as(IncidentClaim)
      report = claim_report("aisup-lost", "claim:lost")

      expect_raises(IncidentClaimLost, "aisup-lost") do
        store.save(report, claim_token: claim.token)
      end

      store.disable_persistence
      store.find(report.incident_id).should be_nil
    end

    it "serializes the same local correlation key without blocking another key" do
      store = IncidentStore.new
      entered = Channel(String).new
      release = Channel(Nil).new
      completed = Channel(Nil).new

      spawn do
        store.synchronize_correlation("same") do
          entered.send("first")
          release.receive
        end
        completed.send(nil)
      end
      entered.receive.should eq "first"

      spawn do
        store.synchronize_correlation("same") { entered.send("second") }
        completed.send(nil)
      end
      spawn do
        store.synchronize_correlation("different") { entered.send("different") }
        completed.send(nil)
      end

      entered.receive.should eq "different"
      release.send(nil)
      entered.receive.should eq "second"
      3.times { completed.receive }
    end

    it "uses the completed winner and records the competing signal as a duplicate" do
      repository = ClaimTestRepository.new
      repository.mode = ClaimTestMode::Existing
      repository.winner_report = claim_report("aisup-existing-claim", "claim:winner")
      AISupportAgent.incidents.persist_with(repository)
      AISupportAgent.agent_runs.disable_persistence

      report = AISupportAgent.ingest(claim_event("claim:winner"))

      report.incident_id.should eq "aisup-existing-claim"
      report.duplicate_count.should eq 1
      repository.claim_calls.should eq 1
      repository.saved_token.should be_nil
    end

    it "returns a retryable conflict while another worker owns the claim" do
      repository = ClaimTestRepository.new
      repository.mode = ClaimTestMode::Existing
      AISupportAgent.incidents.persist_with(repository)

      result = client.post(
        "/api/ai-support/v1/webhooks/generic",
        body: {
          source:          "webhook",
          severity:        "error",
          correlation_key: "claim:pending",
          payload:         {message: "runtime error"},
        }.to_json,
        headers: HTTP::Headers{"Content-Type" => "application/json"}
      )

      result.status_code.should eq 409
      result.headers["Retry-After"]?.should eq "2"
      result.headers["X-Request-ID"]?.should_not be_nil
      result.body.should contain "already being investigated"
      repository.claim_calls.should eq 2
      AISupportAgent.deliveries.all.should be_empty
    end

    it "does not deliver a claimed report when final persistence fails" do
      repository = ClaimTestRepository.new
      repository.fail_save = true
      AISupportAgent.incidents.persist_with(repository)

      expect_raises(Exception, "database offline") do
        AISupportAgent.ingest(claim_event("claim:commit-failure"))
      end

      AISupportAgent.incidents.disable_persistence
      AISupportAgent.incidents.all.should be_empty
      AISupportAgent.deliveries.all.should be_empty
    end

    it "returns service unavailable when persistent claiming fails" do
      repository = ClaimTestRepository.new
      repository.mode = ClaimTestMode::Failed
      AISupportAgent.incidents.persist_with(repository)

      result = client.post(
        "/api/ai-support/v1/webhooks/generic",
        body: {
          source:          "webhook",
          severity:        "error",
          correlation_key: "claim:unavailable",
          payload:         {message: "runtime error"},
        }.to_json,
        headers: HTTP::Headers{"Content-Type" => "application/json"}
      )

      result.status_code.should eq 503
      result.headers["Retry-After"]?.should eq "5"
      result.body.should contain "claim service is unavailable"
      AISupportAgent.disable_persistence
      AISupportAgent.incidents.all.should be_empty
      AISupportAgent.deliveries.all.should be_empty
    end
  end

  private def self.claim_event(correlation_key : String) : IncidentEvent
    IncidentEvent.new(
      source: IncidentSource::Webhook,
      severity: IncidentSeverity::Error,
      correlation_key: correlation_key,
      payload: JSON.parse({message: "runtime error"}.to_json),
      module_id: "mod-claim"
    )
  end

  private def self.claim_report(incident_id : String, correlation_key : String) : IncidentReport
    IncidentReport.new(
      incident_id: incident_id,
      status: IncidentStatus::Open,
      summary: "Claimed incident",
      classification: DiagnosticClassification::RuntimeError,
      confidence: 0.7,
      severity: IncidentSeverity::Error,
      source: IncidentSource::Webhook,
      correlation_key: correlation_key,
      created_at: Time.utc,
      evidence: [] of Evidence,
      actions_taken: ["report_only_no_remediation"],
      next_steps: [] of String,
      module_id: "mod-claim"
    )
  end
end
