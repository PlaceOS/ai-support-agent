require "http/client"
require "uri"

module AISupportAgent
  # Posts a text message to a Google Chat space through an incoming webhook URL.
  class GoogleChatClient
    class Error < Exception
      getter status : Int32

      def initialize(@status : Int32, message : String)
        super(message)
      end
    end

    # Google Chat rejects a text message longer than this
    MAX_TEXT_CHARS = 4096

    def self.from_environment : GoogleChatClient?
      GOOGLE_CHAT_WEBHOOK_URL.try { |url| new(url) }
    end

    def initialize(@webhook_url : String, @timeout : Time::Span = REPORT_DELIVERY_TIMEOUT_SECONDS.seconds)
    end

    # @returns the HTTP status Google Chat answered with; raises `Error` for anything but success
    def post(text : String) : Int32
      uri = URI.parse(@webhook_url)
      client = HTTP::Client.new(uri)
      client.connect_timeout = @timeout
      client.read_timeout = @timeout
      client.write_timeout = @timeout
      headers = HTTP::Headers{"Content-Type" => "application/json; charset=UTF-8"}
      response = client.post(uri.request_target, headers: headers, body: {text: text[0, MAX_TEXT_CHARS]}.to_json)
      raise Error.new(response.status_code, "Google Chat returned HTTP #{response.status_code}") unless response.success?
      response.status_code
    ensure
      client.try(&.close)
    end
  end
end
