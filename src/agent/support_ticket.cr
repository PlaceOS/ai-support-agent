module AISupportAgent
  struct TicketComment
    include JSON::Serializable

    getter author : String? = nil
    getter body : String
    getter? public : Bool = true
    getter created_at : Time? = nil

    def initialize(@body : String, @author : String? = nil, @public : Bool = true, @created_at : Time? = nil)
    end
  end

  struct TicketAttachment
    include JSON::Serializable

    getter filename : String
    getter mime_type : String? = nil
    getter size : Int64? = nil

    def initialize(@filename : String, @mime_type : String? = nil, @size : Int64? = nil)
    end
  end

  # A service desk ticket normalised to the fields the agent reads.
  #
  # `reference` is the ticket key (for example SD-8601). It is not called `key`
  # because `Redactor` blanks every payload field whose name contains "key".
  struct SupportTicket
    include JSON::Serializable

    # how a quoted email tail or a service desk footer starts inside a description
    QUOTED_TAIL = /^\s*(?:From:\s|-{3,}\s*Original Message|Reply above this line|On .{6,80} wrote:|Sent from my )/m

    getter reference : String
    getter summary : String
    getter description : String? = nil
    getter organisation : String? = nil
    getter reporter_email : String? = nil
    getter reporter_name : String? = nil
    getter priority : String? = nil
    getter request_type : String? = nil
    getter issue_type : String? = nil
    getter status : String? = nil
    getter? resolved : Bool = false
    getter url : String? = nil
    getter created_at : Time? = nil
    getter comments : Array(TicketComment) = [] of TicketComment
    getter attachments : Array(TicketAttachment) = [] of TicketAttachment
    # what the service desk reported: created, commented, updated or resolved
    getter event : String? = nil

    def initialize(
      @reference : String,
      @summary : String,
      @description : String? = nil,
      @organisation : String? = nil,
      @reporter_email : String? = nil,
      @reporter_name : String? = nil,
      @priority : String? = nil,
      @request_type : String? = nil,
      @issue_type : String? = nil,
      @status : String? = nil,
      @resolved : Bool = false,
      @url : String? = nil,
      @created_at : Time? = nil,
      @comments : Array(TicketComment) = [] of TicketComment,
      @attachments : Array(TicketAttachment) = [] of TicketAttachment,
      @event : String? = nil,
    )
      @reference = @reference.strip
      @summary = @summary.strip
      @description = SupportTicket.clean(@description)
      raise ArgumentError.new("a ticket needs a reference") if @reference.empty?
      raise ArgumentError.new("a ticket needs a summary") if @summary.empty?
    end

    def after_initialize
      @reference = @reference.strip
      @summary = @summary.strip
      @description = SupportTicket.clean(@description)
      raise ArgumentError.new("a ticket needs a reference") if @reference.empty?
      raise ArgumentError.new("a ticket needs a summary") if @summary.empty?
    end

    # The summary, description and comments in order, as one block of text.
    def text : String
      String.build do |io|
        io << summary << '\n'
        description.try { |body| io << body << '\n' }
        comments.each do |comment|
          io << '\n' << (comment.author || "comment") << ": " << comment.body << '\n'
        end
      end
    end

    def with_event(event : String) : SupportTicket
      SupportTicket.new(
        reference: reference, summary: summary, description: description, organisation: organisation,
        reporter_email: reporter_email, reporter_name: reporter_name, priority: priority,
        request_type: request_type, issue_type: issue_type, status: status, resolved: resolved?,
        url: url, created_at: created_at, comments: comments, attachments: attachments, event: event
      )
    end

    # Drops a quoted email tail and Jira wiki image and colour macros.
    def self.clean(text : String?) : String?
      return unless text
      body = text.gsub(/!\S+?(?:\|[^!]*)?!/, "[image]").gsub(/\{color(?::[^}]*)?\}/, "")
      if match = QUOTED_TAIL.match(body)
        body = body[0, match.begin(0)]
      end
      body.strip.presence
    end

    # Reads a Jira Cloud webhook body or a `GET /rest/api/2|3/issue/:key` response.
    def self.from_jira(body : String) : SupportTicket
      payload = JSON.parse(body)
      object = payload.as_h
      issue = object["issue"]?.try(&.as_h?) || object
      fields = issue["fields"]?.try(&.as_h?) || raise ArgumentError.new("the Jira payload has no issue fields")
      reference = issue["key"]?.try(&.as_s?) || raise ArgumentError.new("the Jira payload has no issue key")

      status = fields["status"]?.try(&.as_h?)
      status_category = status.try(&.["statusCategory"]?).try(&.as_h?).try(&.["key"]?).try(&.as_s?)
      resolved = status_category == "done" || !fields["resolution"]?.try(&.raw).nil?

      comments = (fields["comment"]?.try(&.as_h?).try(&.["comments"]?).try(&.as_a?) || [] of JSON::Any).map { |comment| jira_comment(comment) }
      if comment = object["comment"]?.try(&.as_h?)
        parsed = jira_comment(JSON::Any.new(comment))
        comments << parsed unless comments.any? { |existing| existing.body == parsed.body && existing.author == parsed.author }
      end

      attachments = (fields["attachment"]?.try(&.as_a?) || [] of JSON::Any).map do |attachment|
        data = attachment.as_h
        TicketAttachment.new(
          filename: data["filename"]?.try(&.as_s?) || "attachment",
          mime_type: data["mimeType"]?.try(&.as_s?),
          size: data["size"]?.try(&.as_i64?)
        )
      end

      reporter = fields["reporter"]?.try(&.as_h?)
      organisations = fields["customfield_10002"]?.try(&.as_a?).try(&.compact_map { |org| org.as_h?.try(&.["name"]?).try(&.as_s?) })
      request_type = fields["customfield_10024"]?.try(&.as_h?).try(&.["requestType"]?).try(&.as_h?).try(&.["name"]?).try(&.as_s?)
      self_url = issue["self"]?.try(&.as_s?)
      browse_url = self_url.try { |link| URI.parse(link).try { |uri| "#{uri.scheme}://#{uri.host}/browse/#{reference}" } }

      new(
        reference: reference,
        summary: fields["summary"]?.try(&.as_s?) || reference,
        description: jira_text(fields["description"]?),
        organisation: organisations.try(&.first?),
        reporter_email: reporter.try(&.["emailAddress"]?).try(&.as_s?),
        reporter_name: reporter.try(&.["displayName"]?).try(&.as_s?),
        priority: fields["priority"]?.try(&.as_h?).try(&.["name"]?).try(&.as_s?),
        request_type: request_type,
        issue_type: fields["issuetype"]?.try(&.as_h?).try(&.["name"]?).try(&.as_s?),
        status: status.try(&.["name"]?).try(&.as_s?),
        resolved: resolved,
        url: browse_url,
        created_at: jira_time(fields["created"]?),
        comments: comments,
        attachments: attachments,
        event: jira_event(object["webhookEvent"]?.try(&.as_s?), resolved)
      )
    end

    private def self.jira_event(webhook_event : String?, resolved : Bool) : String
      return "resolved" if resolved
      case webhook_event
      when "jira:issue_created" then "created"
      when "comment_created"    then "commented"
      when "jira:issue_updated" then "updated"
      else                           "created"
      end
    end

    private def self.jira_comment(comment : JSON::Any) : TicketComment
      data = comment.as_h
      TicketComment.new(
        body: jira_text(data["body"]?) || "",
        author: data["author"]?.try(&.as_h?).try(&.["displayName"]?).try(&.as_s?),
        public: data["jsdPublic"]?.try(&.as_bool?) != false,
        created_at: jira_time(data["created"]?)
      )
    end

    private def self.jira_time(value : JSON::Any?) : Time?
      text = value.try(&.as_s?)
      return unless text
      Time.parse_rfc3339(text)
    rescue
      Time.parse(text.as(String), "%Y-%m-%dT%H:%M:%S.%L%z", Time::Location::UTC) rescue nil
    end

    # Jira sends a description or comment body as wiki markup text (REST v2 and
    # webhooks) or as an Atlassian Document Format object (REST v3).
    def self.jira_text(value : JSON::Any?) : String?
      return unless value
      case raw = value.raw
      when String then raw.presence
      when Hash   then adf_text(value).strip.presence
      end
    end

    private def self.adf_text(node : JSON::Any) : String
      data = node.as_h? || return node.as_s? || ""
      case data["type"]?.try(&.as_s?)
      when "text"       then return data["text"]?.try(&.as_s?) || ""
      when "hardBreak"  then return "\n"
      when "mention"    then return data["attrs"]?.try(&.as_h?).try(&.["text"]?).try(&.as_s?) || ""
      when "inlineCard" then return data["attrs"]?.try(&.as_h?).try(&.["url"]?).try(&.as_s?) || ""
      when "media"      then return "[image]"
      end
      children = data["content"]?.try(&.as_a?) || [] of JSON::Any
      text = children.join { |child| adf_text(child) }
      block = data["type"]?.try(&.as_s?).in?("paragraph", "heading", "listItem", "codeBlock", "blockquote", "tableRow")
      block ? text + "\n" : text
    end
  end
end
