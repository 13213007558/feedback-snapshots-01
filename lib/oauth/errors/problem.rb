# frozen_string_literal: true

require "oauth/errors/error"
require "oauth/errors/unauthorized"

module OAuth
  class Problem < OAuth::Unauthorized
    attr_reader :problem, :params

    def initialize(problem, request = nil, params = {})
      super(request)
      @problem = problem
      @params  = params
    end

    def to_s
      problem
    end
  end

  # Raised when the same OAuth protocol parameters are delivered through more
  # than one credential carrier (the Authorization header and the request query
  # string and/or form body) on a single request. Such a request is ambiguous:
  # the server cannot tell which carrier the client actually intended, so it is
  # rejected instead of silently letting one location override the other.
  #
  # The message deliberately contains only parameter *names* and the locations
  # involved, never the credential values, so it is safe to write to a log or
  # re-raise without leaking tokens, signatures or nonces.
  class AmbiguousCredentials < OAuth::Error
    # Locations, in the order they are merged by the request proxy.
    LOCATIONS = %i[body query header].freeze

    attr_reader :locations, :parameter_names

    def initialize(locations, parameter_names)
      @locations = Array(locations).map(&:to_sym).sort
      @parameter_names = Array(parameter_names).sort
      super(build_message)
    end

    # Structured data suitable for a structured log line. It never contains the
    # credential values, only where protocol parameters were found and which
    # names were duplicated.
    def to_h
      {
        error: "oauth.ambiguous_credentials",
        locations: locations,
        duplicated_parameters: parameter_names
      }
    end

    private

    def build_message
      "OAuth protocol parameters were present in more than one location " \
        "(#{locations.join(", ")}): #{parameter_names.join(", ")}. " \
        "Send credentials in exactly one carrier."
    end
  end
end
