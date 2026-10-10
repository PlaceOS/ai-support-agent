require "base64"
require "http/client"

module AISupportAgent
  # Minimal Jira Cloud REST v3 client: comments and fields on an issue.
  class JiraClient
    class Error < Exception
      getter status : Int32?

      def initialize(message : String, @status : Int32? = nil)
        super(message)
      end
    end

    getter base : URI

    def self.from_environment : JiraClient?
      url = JIRA_URL
      email = JIRA_EMAIL
      token = JIRA_API_TOKEN
      return unless url && email && token

      new(url, email, token)
    end

    def initialize(base : String, @email : String, @token : String, @timeout : Time::Span = 10.seconds)
      @base = URI.parse(base.rstrip('/'))
    end

    # Adds a comment. An internal comment is visible to agents only in Jira Service Management.
    def add_comment(key : String, body : JSON::Any, internal : Bool = true) : JSON::Any
      request = JSON.build do |json|
        json.object do
          json.field "body" { body.to_json(json) }
          if internal
            json.field "properties" do
              json.array do
                json.object do
                  json.field "key", "sd.public.comment"
                  json.field "value" { json.object { json.field "internal", true } }
                end
              end
            end
          end
        end
      end
      status, response = exec("POST", "/rest/api/3/issue/#{URI.encode_path_segment(key)}/comment", request)
      raise Error.new("Jira returned HTTP #{status} adding a comment to #{key}", status) unless status == 201
      JSON.parse(response)
    end

    # The requested fields of an issue, by field id.
    def fields(key : String, names : Array(String)) : Hash(String, JSON::Any)
      path = "/rest/api/3/issue/#{URI.encode_path_segment(key)}?fields=#{URI.encode_www_form(names.join(","))}"
      status, response = exec("GET", path)
      raise Error.new("Jira returned HTTP #{status} reading #{key}", status) unless status == 200
      JSON.parse(response)["fields"]?.try(&.as_h?) || {} of String => JSON::Any
    end

    def update_fields(key : String, fields : Hash(String, JSON::Any)) : Nil
      status, response = exec("PUT", "/rest/api/3/issue/#{URI.encode_path_segment(key)}", {fields: fields}.to_json)
      raise Error.new("Jira returned HTTP #{status} updating #{key}: #{response[0, 300]}", status) unless status == 204
    end

    def browse_url(key : String) : String
      "#{base}/browse/#{key}"
    end

    private def exec(method : String, path : String, body : String? = nil) : {Int32, String}
      client = HTTP::Client.new(base)
      client.connect_timeout = @timeout
      client.read_timeout = @timeout
      client.write_timeout = @timeout
      headers = HTTP::Headers{
        "Authorization" => "Basic " + Base64.strict_encode("#{@email}:#{@token}"),
        "Accept"        => "application/json",
        "Content-Type"  => "application/json",
      }
      response = client.exec(method, path, headers, body)
      {response.status_code, response.body}
    ensure
      client.try(&.close)
    end
  end
end
