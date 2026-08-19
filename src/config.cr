require "./logging"

require "action-controller"
require "openai"
require "pg-orm"
require "placeos"
require "placeos-models"
require "placeos-resource"

require "./constants"
require "./controllers/application"
require "./controllers/*"
require "./agent"

require "action-controller/server"

filter_params = ["password", "token", "secret", "authorization", "bearer_token", "api_key"]
keeps_headers = ["X-Request-ID"]

ActionController::Server.before(
  ActionController::ErrorHandler.new(AISupportAgent.production?, keeps_headers),
  ActionController::LogHandler.new(filter_params, ms: true),
)
