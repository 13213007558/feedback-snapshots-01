# frozen_string_literal: true

module Grape
  module ServeStream
    # Wraps the body of a streamed response so an error raised while it is being
    # read cannot take an internal exception, or the state inside its message,
    # out past Grape.
    #
    # The timing decides what is still possible. {#probe} pulls the first chunk
    # before the status and headers are sent: a failure there re-raises inside
    # the error middleware, which answers with a normal error response and the
    # wrapped body is closed. Once a chunk has been yielded the response is
    # committed and the status can no longer change, so a later failure ends the
    # stream cleanly, closes the body, and is logged and published on the env
    # without its details leaving the process.
    class SafeStream
      # The one line written about a failure after the response committed. It
      # names the exception's class but never its message, which may carry
      # internal state.
      LOG_TEMPLATE = 'Grape stream aborted after the response was committed: %<class>s'.freeze

      def initialize(body, env)
        @body = body
        @env = env
        @iterator = body.to_enum(:each)
        @first_chunk = nil
        @has_first_chunk = false
        @probed = false
        @committed = false
        @closed = false
      end

      # Reads the first chunk so the formatter can still fail into the error
      # middleware while nothing has been sent. The chunk is buffered and
      # replayed by {#each}, so the body is driven through one enumerator
      # either way.
      #
      # @return [self]
      def probe
        return self if @probed

        @probed = true
        @first_chunk = @iterator.next
        @has_first_chunk = true
        self
      rescue StopIteration
        # An empty stream has no first chunk to fail on; #each just ends.
        self
      rescue StandardError => error
        close
        raise Grape::ServeStream::ProbeError.new(error)
      end

      def each
        probe unless @probed

        if @has_first_chunk
          yield @first_chunk
          @committed = true
        end
        loop { yield @iterator.next }
      rescue StopIteration
        # The enumerator is exhausted; its body is closed by #close below.
      rescue StandardError => error
        raise unless @committed

        abort_stream(error)
      ensure
        close
      end

      def close
        return if @closed

        @closed = true
        @body.close if @body.respond_to?(:close)
      end

      private

      # The response is already on the wire, so there is no status or header to
      # change and nothing can be raised out of the body: end the stream and
      # record the failure without its internals. Ending the body is the abort
      # the caller observes -- a truncated stream and a clean close.
      def abort_stream(error)
        record_failure(error)
      ensure
        close
      end

      # Keep the original exception for loggers and error trackers mounted in
      # the process, but write only its class name to rack.errors and the API
      # logger so the failure's details never reach the response or a log a
      # caller can read.
      def record_failure(error)
        @env[Grape::Env::GRAPE_EXCEPTION] = error
        @env[Grape::Env::RACK_EXCEPTION] = error
        message = format(LOG_TEMPLATE, class: error.class.name)
        @env[Rack::RACK_ERRORS]&.write("#{message}\n")
        endpoint&.logger&.error(message)
      end

      def endpoint
        @env[Grape::Env::API_ENDPOINT]
      end
    end
  end
end
