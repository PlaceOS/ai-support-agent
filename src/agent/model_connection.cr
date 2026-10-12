module AISupportAgent
  # The OpenAI client keeps its socket open between calls and the server closes
  # idle ones, so the first request after a quiet spell can die with an IO::Error.
  module ModelConnection
    # @returns the completion for `request`; after an `IO::Error` the client is
    # rebuilt from its config and the request sent once more
    private def chat_completion(client : ::OpenAI::Client, request : ::OpenAI::ChatCompletionRequest) : ::OpenAI::ChatCompletionResponse
      client.chat_completion(request)
    rescue error : IO::Error
      AISupportAgent::Log.info { "model request failed on a dropped connection (#{error.class}); retrying on a new one" }
      fresh = ::OpenAI::Client.new(client.config)
      @client = fresh
      fresh.chat_completion(request)
    end
  end
end
