# frozen_string_literal: true

require "digest"

module Rack
  class Attack
    module Risk
      # Per-request risk scoring budget. All risk rules evaluated during one
      # request share a single Budget instance (stored in the request env):
      #
      # - a monotonic deadline caps the total time spent waiting on the
      #   scorer across all rules of the request;
      # - results are memoized per query, so several rules asking the same
      #   question share one scorer call and one verdict. A confirmed verdict
      #   (allow or deny) is final for the request: once the budget is spent,
      #   later rules asking the same query still see the confirmed verdict
      #   instead of a timeout.
      class Budget
        ENV_KEY = "rack.attack.risk_budget"

        def self.for(request, total)
          request.env[ENV_KEY] ||= new(total)
        end

        def self.digest(query)
          Digest::SHA256.hexdigest(query.to_s)
        end

        def self.monotonic_now
          Process.clock_gettime(Process::CLOCK_MONOTONIC)
        end

        attr_reader :total

        def initialize(total)
          @total = total
          @deadline = Budget.monotonic_now + total
          @memo = {}
        end

        def remaining
          [@deadline - Budget.monotonic_now, 0.0].max
        end

        def exhausted?
          remaining <= 0.0
        end

        # Yields the remaining budget and memoizes whatever the block
        # returns, keyed by a digest of the query. The raw query is never
        # stored here.
        def fetch(query)
          key = Budget.digest(query)
          return @memo[key] if @memo.key?(key)

          @memo[key] = yield(remaining)
        end
      end
    end
  end
end
