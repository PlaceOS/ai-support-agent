require "http/client"
require "option_parser"

require "./constants"

port = AISupportAgent::DEFAULT_PORT
host = AISupportAgent::DEFAULT_HOST
process_count = AISupportAgent::DEFAULT_PROCESS_COUNT
check_persistence = false

OptionParser.parse(ARGV.dup) do |parser|
  parser.banner = "Usage: #{AISupportAgent::APP_NAME} [arguments]"

  parser.on("-b HOST", "--bind=HOST", "Specifies the server host") { |bind_host| host = bind_host }
  parser.on("-p PORT", "--port=PORT", "Specifies the server port") { |bind_port| port = bind_port.to_i }

  parser.on("-w COUNT", "--workers=COUNT", "Specifies the number of processes to handle requests") do |workers|
    process_count = workers.to_i
  end

  parser.on("-r", "--routes", "List the application routes") do
    ActionController::Server.print_routes
    exit 0
  end

  parser.on("-v", "--version", "Display the application version") do
    puts "#{AISupportAgent::APP_NAME} v#{AISupportAgent::VERSION}"
    exit 0
  end

  parser.on("-c URL", "--curl=URL", "Perform a basic health check by requesting the URL") do |url|
    begin
      response = HTTP::Client.get url
      exit 0 if (200..499).includes? response.status_code
      puts "health check failed, received response code #{response.status_code}"
      exit 1
    rescue error
      error.inspect_with_backtrace(STDOUT)
      exit 2
    end
  end

  parser.on("-d", "--docs", "Outputs OpenAPI documentation for this service") do
    puts ActionController::OpenAPI.generate_open_api_docs(
      title: AISupportAgent::APP_NAME,
      version: AISupportAgent::VERSION,
      description: "AI Support Agent report-only MVP"
    ).to_yaml
    exit 0
  end

  parser.on("--check-persistence", "Validate the configured Postgres schema and exit") do
    check_persistence = true
  end

  parser.on("-h", "--help", "Show this help") do
    puts parser
    exit 0
  end
end

require "./config"

if check_persistence
  unless AISupportAgent.database_configured?
    puts AISupportAgent.persistence_schema_status.to_json
    exit 2
  end

  ready = AISupportAgent.configure_database
  puts AISupportAgent.persistence_schema_status.to_json
  exit ready ? 0 : 1
end

module AISupportAgent
  Log.info { "launching #{APP_NAME} v#{VERSION}" }

  server = ActionController::Server.new(port, host)
  server.cluster(process_count, "-w", "--workers") if process_count != 1

  terminate = Proc(Signal, Nil).new do |signal|
    puts " > terminating gracefully"
    spawn { server.close }
    signal.ignore
  end

  Signal::INT.trap &terminate
  Signal::TERM.trap &terminate

  start_resources

  server.run do
    Log.info { "listening on #{server.print_addresses}" }
  end

  stop_resources

  Log.info { "#{APP_NAME} shutdown complete" }
end
