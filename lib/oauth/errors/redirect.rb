# frozen_string_literal: true

module OAuth
  # Raised when a token endpoint responds with a redirect that the client
  # is not allowed to follow.
  #
  # The redirect is never attempted when this is raised, so the consumer
  # credentials are not disclosed to the rejected destination.
  class RedirectNotAllowed < OAuth::Error
    attr_reader :response, :location, :reason

    def initialize(response = nil, location = nil, reason = nil)
      @response = response
      @location = location
      @reason = reason
      super(reason)
    end

    def to_s
      reason || "Redirect not allowed"
    end
  end
end
