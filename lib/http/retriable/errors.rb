# frozen_string_literal: true

module HTTP
  # Retriable performance ran out of attempts
  class OutOfRetriesError < Error
    # The last response received before failure
    #
    # @example
    #   error.response
    #
    # @return [HTTP::Response, nil] the last response received
    # @api public
    attr_accessor :response

    # Set the underlying exception
    #
    # @example
    #   error.cause = original_error
    #
    # @return [Exception, nil]
    # @api public
    attr_writer :cause

    # Returns the cause of the error
    #
    # @example
    #   error.cause
    #
    # @api public
    # @return [Exception, nil]
    def cause
      @cause || super
    end
  end

  # The operation deadline (lease) elapsed before another attempt could run.
  #
  # Unlike {OutOfRetriesError}, this means the client stopped because it ran
  # out of its own permitted time window, not because the server refused to
  # accept another attempt. It is a subclass of {OutOfRetriesError} so code
  # that already rescues that class keeps working.
  class DeadlineExceededError < OutOfRetriesError
  end
end
