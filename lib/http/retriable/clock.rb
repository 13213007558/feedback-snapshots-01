# frozen_string_literal: true

module HTTP
  module Retriable
    # Monotonic time source used to bound retries by an operation deadline.
    #
    # The clock is intentionally tiny so tests can substitute a controllable
    # implementation instead of waiting for real time to pass.
    # @api private
    class Clock
      # Current monotonic time, in seconds
      #
      # @api private
      # @return [Numeric]
      def now
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end

      # Suspends the current thread for the given number of seconds
      #
      # @param [Numeric] seconds
      # @api private
      # @return [Numeric]
      def sleep(seconds)
        Kernel.sleep(seconds)
      end
    end
  end
end
