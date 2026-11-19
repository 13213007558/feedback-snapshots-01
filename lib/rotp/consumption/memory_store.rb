require 'monitor'

module ROTP
  module Consumption
    # Thread-safe, in-memory Store used for tests and as the reference
    # implementation. Every method takes the same monitor, so the
    # compare-and-swap is atomic across Ruby threads without a database.
    class MemoryStore
      include Store
      include MonitorMixin

      def initialize
        super
        @records = {}
        @depth = 0
      end

      def get(account_id, authenticator_id)
        synchronize { @records[[account_id, authenticator_id]] }
      end

      def compare_and_swap(account_id, authenticator_id, expected_state, next_state)
        synchronize do
          key = [account_id, authenticator_id]
          current = @records[key]
          expected_version = expected_state&.version

          if expected_version.nil?
            # Insert path: the row must still be absent.
            return false unless current.nil?
          else
            # Update path: the version the verifier read must be unchanged.
            return false unless current && current.version == expected_version
          end

          @records[key] = next_state
          true
        end
      end

      def transaction
        synchronize do
          return yield if @depth.positive?

          @depth = 1
          snapshot = @records.dup
          begin
            yield
          rescue
            @records = snapshot
            raise
          ensure
            @depth = 0
          end
        end
      end
    end
  end
end
