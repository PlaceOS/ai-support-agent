require "./helper"

module AISupportAgent
  def self.runtime_error_module
    mod = ::PlaceOS::Model::Module.new
    mod.id = "mod-runtime-1"
    mod.name = "Display"
    mod.has_runtime_error = true
    mod.error_timestamp = Time.unix(1_735_689_600)
    mod.running = true
    mod.connected = false
    mod
  end

  describe ModuleRuntimeErrorResource do
    it "creates incidents for modules with existing runtime errors during startup load" do
      mod = AISupportAgent.runtime_error_module
      resource = ModuleRuntimeErrorResource.new

      result = resource.process_resource(PgORM::ChangeReceiver::Event::Created, mod)

      result.success?.should be_true
      report = AISupportAgent.incidents.all.first
      report.source.module_state?.should be_true
      report.module_id.should eq "mod-runtime-1"
      report.correlation_key.should contain "module-runtime-error:mod-runtime-1"
      report.actions_taken.should eq ["report_only_no_remediation"]
    end

    it "creates incidents when runtime error flags update" do
      mod = AISupportAgent.runtime_error_module
      resource = ModuleRuntimeErrorResource.new

      result = resource.process_resource(PgORM::ChangeReceiver::Event::Updated, mod)

      result.success?.should be_true
      AISupportAgent.incidents.all.size.should eq 1
    end

    it "skips runtime error clears" do
      mod = AISupportAgent.runtime_error_module
      mod.clear_changes_information
      mod.has_runtime_error = false

      result = ModuleRuntimeErrorResource.new.process_resource(PgORM::ChangeReceiver::Event::Updated, mod)

      result.skipped?.should be_true
      AISupportAgent.incidents.all.should be_empty
    end
  end
end
