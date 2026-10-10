require "./helper"

module AISupportAgent
  describe JiraClient do
    it "posts an internal comment with an ADF body" do
      captured = nil.as(String?)
      WebMock.stub(:post, "http://jira.test/rest/api/3/issue/SD-1/comment").to_return do |request|
        captured = request.body.try(&.gets_to_end)
        HTTP::Client::Response.new(201, body: {id: "10001"}.to_json, headers: HTTP::Headers{"Content-Type" => "application/json"})
      end
      client = JiraClient.new("http://jira.test/", "agent@example.test", "token")

      created = client.add_comment("SD-1", Adf.doc { |adf| adf.paragraph("hello") }, internal: true)

      created["id"].as_s.should eq "10001"
      sent = JSON.parse(captured.not_nil!)
      sent["body"]["type"].as_s.should eq "doc"
      sent["body"]["content"][0]["content"][0]["text"].as_s.should eq "hello"
      sent["properties"][0]["key"].as_s.should eq "sd.public.comment"
      sent["properties"][0]["value"]["internal"].as_bool.should be_true
    end

    it "omits the internal property for a public comment and raises on an error status" do
      captured = nil.as(String?)
      WebMock.stub(:post, "http://jira.test/rest/api/3/issue/SD-1/comment").to_return do |request|
        captured = request.body.try(&.gets_to_end)
        HTTP::Client::Response.new(201, body: {id: "1"}.to_json)
      end
      client = JiraClient.new("http://jira.test", "agent@example.test", "token")
      client.add_comment("SD-1", Adf.doc { |adf| adf.paragraph("public") }, internal: false)
      JSON.parse(captured.not_nil!)["properties"]?.should be_nil

      WebMock.stub(:post, "http://jira.test/rest/api/3/issue/SD-2/comment").to_return(status: 403, body: "forbidden")
      error = expect_raises(JiraClient::Error) { client.add_comment("SD-2", Adf.doc { |adf| adf.paragraph("x") }) }
      error.status.should eq 403
    end

    it "reads and updates fields" do
      WebMock.stub(:get, "http://jira.test/rest/api/3/issue/SD-1").with(query: {"fields" => "customfield_10035"})
        .to_return(body: {fields: {customfield_10035: nil}}.to_json)
      captured = nil.as(String?)
      WebMock.stub(:put, "http://jira.test/rest/api/3/issue/SD-1").to_return do |request|
        captured = request.body.try(&.gets_to_end)
        HTTP::Client::Response.new(204)
      end
      client = JiraClient.new("http://jira.test", "agent@example.test", "token")

      client.fields("SD-1", ["customfield_10035"])["customfield_10035"].raw.should be_nil
      client.update_fields("SD-1", {"customfield_10035" => Adf.doc { |adf| adf.paragraph("root cause") }})

      JSON.parse(captured.not_nil!)["fields"]["customfield_10035"]["content"][0]["content"][0]["text"].as_s.should eq "root cause"
      client.browse_url("SD-1").should eq "http://jira.test/browse/SD-1"
    end
  end

  describe Adf do
    it "builds headings, labelled paragraphs and bullet lists" do
      doc = Adf.doc do |adf|
        adf.heading("Title", 3)
        adf.labelled("Read as:", "a stalled sync")
        adf.bullets(["one", "two"])
        adf.bullets([] of String)
      end

      doc["version"].as_i.should eq 1
      doc["content"].as_a.size.should eq 3
      doc["content"][1]["content"][0]["marks"][0]["type"].as_s.should eq "strong"
      doc["content"][2]["content"].as_a.size.should eq 2
      SupportTicket.jira_text(doc).to_s.should contain "Read as: a stalled sync"
    end
  end
end
