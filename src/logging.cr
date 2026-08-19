require "./constants"

module AISupportAgent::Logging
  ::Log.progname = APP_NAME

  log_level = AISupportAgent.production? ? ::Log::Severity::Info : ::Log::Severity::Debug
  namespaces = ["action-controller.*", "place_os.*"]

  builder = ::Log.builder
  builder.bind "*", log_level, LOG_BACKEND

  namespaces.each do |namespace|
    builder.bind namespace, log_level, LOG_BACKEND
  end

  ::Log.setup_from_env(
    default_level: log_level,
    builder: builder,
    backend: LOG_BACKEND,
    log_level_env: "LOG_LEVEL",
  )
end
