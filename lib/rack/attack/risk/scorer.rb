# frozen_string_literal: true

module Rack
  class Attack
    module Risk
      # Outcome of a single risk evaluation. +state+ is one of:
      #   :deny    - the scorer returned a high-risk verdict
      #   :allow   - the scorer returned a low-risk verdict
      #   :unknown - no verdict was reached (timeout, full queue, exhausted
      #              budget or scorer error). Unknown is never treated as
      #              low risk; each rule decides via its on_timeout policy.
      class Result
        attr_reader :state, :reason

        def initialize(state, reason)
          @state = state
          @reason = reason
        end

        def deny?
          state == :deny
        end

        def allow?
          state == :allow
        end

        def unknown?
          state == :unknown
        end

        def self.allow
          new(:allow, :scored)
        end

        def self.deny
          new(:deny, :scored)
        end

        def self.unknown(reason)
          new(:unknown, reason)
        end
      end

      # Adapts a synchronous, user-supplied scorer callable to the bounded
      # pool. The callable receives the query built by the rule and may
      # return:
      #   - a Numeric score (denied when >= deny_at)
      #   - :deny / true  (high risk)
      #   - :allow / false / nil (low risk)
      #
      # The callable runs on a Pool worker; evaluate waits at most +timeout+
      # seconds and maps every failure mode to Result.unknown.
      class Scorer
        DEFAULT_DENY_AT = 0.5

        attr_reader :deny_at

        def initialize(callable = nil, deny_at: DEFAULT_DENY_AT, pool: nil, &block)
          @callable = callable || block
          raise ArgumentError, "scorer must respond to #call" unless @callable.respond_to?(:call)

          @deny_at = deny_at
          @pool = pool
        end

        def evaluate(query, timeout:)
          return Result.unknown(:budget_exhausted) if timeout <= 0

          future = pool.submit(-> { @callable.call(query) })
          return Result.unknown(:queue_full) unless future

          status, value = future.result(timeout)
          case status
          when :ok then classify(value)
          when :error then Result.unknown(:error)
          else Result.unknown(:timeout)
          end
        end

        private

        def pool
          @pool || Rack::Attack.risk_pool
        end

        def classify(value)
          case value
          when :deny, true then Result.deny
          when Numeric then value >= @deny_at ? Result.deny : Result.allow
          else Result.allow
          end
        end
      end
    end
  end
end
