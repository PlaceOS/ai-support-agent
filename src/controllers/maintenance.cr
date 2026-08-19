module AISupportAgent
  class Maintenance < Application
    base "/api/ai-support/v1/maintenance"

    @[AC::Route::GET("/runs")]
    def runs : Array(MaintenanceRun)
      AISupportAgent.maintenance_runs.all
    end

    @[AC::Route::POST("/:id/runs", status_code: HTTP::Status::CREATED)]
    def create_run(id : String) : MaintenanceRun
      procedure = AISupportAgent.workflow_catalog.maintenance(id) ||
                  raise Error::NotFound.new("maintenance procedure #{id} not found")
      AISupportAgent.maintenance_runner.run(procedure)
    end
  end
end
