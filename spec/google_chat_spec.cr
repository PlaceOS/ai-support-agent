require "./helper"

module AISupportAgent
  describe GoogleChatClient do
    url = "https://chat.googleapis.com/v1/spaces/AAAA/messages?key=k&token=t"

    it "posts the text to the webhook" do
      sent = nil.as(String?)
      WebMock.stub(:post, "https://chat.googleapis.com/v1/spaces/AAAA/messages").with(query: {"key" => "k", "token" => "t"}).to_return do |request|
        sent = request.body.try(&.gets_to_end)
        HTTP::Client::Response.new(200, body: {name: "spaces/AAAA/messages/1"}.to_json)
      end

      GoogleChatClient.new(url).post("hello *there*").should eq 200

      JSON.parse(sent.not_nil!)["text"].as_s.should eq "hello *there*"
    end

    it "raises with the status when the space rejects the message" do
      WebMock.stub(:post, "https://chat.googleapis.com/v1/spaces/AAAA/messages").with(query: {"key" => "k", "token" => "t"}).to_return(status: 403, body: "{}")

      error = expect_raises(GoogleChatClient::Error) { GoogleChatClient.new(url).post("hello") }

      error.status.should eq 403
    end

    it "is switched off without a webhook URL" do
      GoogleChatClient.from_environment.should be_nil
    end
  end
end
