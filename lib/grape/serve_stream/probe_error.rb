# frozen_string_literal: true

module Grape
  module ServeStream
    # Carries the exception a stream's first-chunk probe raised, before any
    # byte has been sent. The formatter re-raises it through the middleware
    # stack without reporting it itself, so the error middleware renders a
    # normal error response and keeps the original's message out of stderr.
    # The wrapped exception is preserved as the cause and restored by the
    # middleware before rescue handlers run, so classification sees it as it
    # was raised.
    #
    # Its own message is deliberately static: nothing should render this
    # wrapper directly, but if something does it must not relay the original
    # exception's internal state.
    class ProbeError < StandardError
      def initialize(cause)
        super('stream failed before the first byte')
        @cause = cause
      end

      def cause
        @cause
      end
    end
  end
end
