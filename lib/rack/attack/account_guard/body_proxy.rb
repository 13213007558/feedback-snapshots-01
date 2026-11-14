# frozen_string_literal: true

module Rack
  class Attack
    class AccountGuard
      # Wraps the downstream response body so that an unclosed/streaming body
      # still releases the request's pending entry.
      #
      # Accounting itself happens as soon as the downstream returns its
      # status/headers; this proxy is only a safety net for pending cleanup.
      # `settle` marks the proxy accounted once the failure/success has been
      # recorded, so a later `close` or stream error cannot roll that
      # accounting back. Both `close` and an exception while iterating run the
      # cleanup exactly once.
      class BodyProxy
        def initialize(body, &cleanup)
          @body      = body
          @cleanup   = cleanup
          @closed    = false
          @accounted = false
        end

        def accounted!
          @accounted = true
        end

        def each(&block)
          return enum_for(:each) unless block

          begin
            @body.each(&block)
          rescue StandardError
            run_cleanup
            raise
          end
          self
        end

        def close
          @body.close if @body.respond_to?(:close)
          run_cleanup
          nil
        end

        def respond_to_missing?(name, include_private = false)
          @body.respond_to?(name, include_private) || super
        end

        def method_missing(name, *args, &block)
          if @body.respond_to?(name)
            @body.public_send(name, *args, &block)
          else
            super
          end
        end

        private

        def run_cleanup
          return if @closed

          @closed = true
          # Only release pending state when settle() never ran. Once accounted,
          # the pending entry was already removed and the recorded result must
          # survive body close / stream failures.
          @cleanup.call unless @accounted
        end
      end
    end
  end
end
