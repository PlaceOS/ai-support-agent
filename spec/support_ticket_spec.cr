require "./helper"

module AISupportAgent
  def self.jira_issue_fields(**overrides)
    {
      summary:           "Module Error Stopping Azure AD to PlaceOS User Sync",
      description:       "Hi Team,\n\nOne of the modules was throwing an error !image-1.png|width=200! and stopping the sync.\n\nThanks\nJega\n\nFrom: PlaceOS Service Desk <jira@example.test>\nSent: Friday\nquoted tail",
      issuetype:         {name: "Bug"},
      priority:          {name: "Medium"},
      status:            {name: "Waiting for support", statusCategory: {key: "new"}},
      reporter:          {displayName: "Jega", emailAddress: "jega@example.test", accountType: "customer"},
      customfield_10002: [{id: "48", name: "Suncorp"}],
      customfield_10024: {requestType: {name: "Report a bug"}},
      attachment:        [{filename: "image-1.png", mimeType: "image/png", size: 100}],
      created:           "2026-05-01T15:46:00.000+1000",
    }.merge(overrides)
  end

  describe SupportTicket do
    it "reads a Jira issue created webhook" do
      body = {
        timestamp:    1,
        webhookEvent: "jira:issue_created",
        issue:        {id: "1", key: "SD-8601", self: "https://acaprojects.atlassian.net/rest/api/2/issue/1", fields: AISupportAgent.jira_issue_fields},
      }.to_json

      ticket = SupportTicket.from_jira(body)

      ticket.reference.should eq "SD-8601"
      ticket.summary.should eq "Module Error Stopping Azure AD to PlaceOS User Sync"
      ticket.organisation.should eq "Suncorp"
      ticket.request_type.should eq "Report a bug"
      ticket.issue_type.should eq "Bug"
      ticket.priority.should eq "Medium"
      ticket.reporter_email.should eq "jega@example.test"
      ticket.description.to_s.should contain "[image]"
      ticket.description.to_s.should contain "stopping the sync"
      ticket.description.to_s.should_not contain "quoted tail"
      ticket.resolved?.should be_false
      ticket.event.should eq "created"
      ticket.url.should eq "https://acaprojects.atlassian.net/browse/SD-8601"
      ticket.attachments.map(&.filename).should eq ["image-1.png"]
      ticket.created_at.should_not be_nil
      ticket.comments.should be_empty
    end

    it "appends the comment from a comment created webhook" do
      body = {
        webhookEvent: "comment_created",
        issue:        {id: "1", key: "SD-8601", fields: AISupportAgent.jira_issue_fields},
        comment:      {body: "Could you review the module error?", author: {displayName: "Jega"}, jsdPublic: true, created: "2026-05-02T09:00:00.000+1000"},
      }.to_json

      ticket = SupportTicket.from_jira(body)

      ticket.event.should eq "commented"
      ticket.comments.size.should eq 1
      ticket.comments.first.author.should eq "Jega"
      ticket.comments.first.public?.should be_true
      ticket.text.should contain "Jega: Could you review the module error?"
    end

    it "flattens an Atlassian Document Format description" do
      description = {
        type:    "doc",
        version: 1,
        content: [
          {type: "paragraph", content: [{type: "text", text: "Hello "}, {type: "mention", attrs: {text: "@Viv"}}]},
          {type: "paragraph", content: [{type: "text", text: "the display is offline"}]},
        ],
      }
      body = {issue: {key: "SD-1", fields: AISupportAgent.jira_issue_fields(description: description)}}.to_json

      ticket = SupportTicket.from_jira(body)

      ticket.description.should eq "Hello @Viv\nthe display is offline"
    end

    it "marks a done status as resolved" do
      status = {name: "Resolved", statusCategory: {key: "done"}}
      body = {webhookEvent: "jira:issue_updated", issue: {key: "SD-1", fields: AISupportAgent.jira_issue_fields(status: status)}}.to_json

      ticket = SupportTicket.from_jira(body)

      ticket.resolved?.should be_true
      ticket.event.should eq "resolved"
      ticket.status.should eq "Resolved"
    end

    it "rejects a payload without an issue" do
      expect_raises(ArgumentError) { SupportTicket.from_jira({webhookEvent: "jira:issue_created"}.to_json) }
    end

    it "normalises a ticket posted directly" do
      ticket = SupportTicket.from_json({reference: " SD-1 ", summary: " Display offline ", comments: [{body: "internal note", author: "Kester", public: false}]}.to_json)

      ticket.reference.should eq "SD-1"
      ticket.summary.should eq "Display offline"
      ticket.comments.first.public?.should be_false
      ticket.resolved?.should be_false
    end

    it "rejects a ticket with a blank summary" do
      expect_raises(ArgumentError) { SupportTicket.from_json({reference: "SD-1", summary: " "}.to_json) }
    end
  end
end
