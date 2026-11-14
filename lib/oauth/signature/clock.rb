# frozen_string_literal: true

require "time"

module OAuth
  module Signature
    # A clock tells signature verification what the server considers "now".
    #
    # The default implementation reads the real system clock. Tests and hosts
    # that need to exercise overlapping validity windows, revocations and
    # expiries deterministically can inject any object that responds to
    # +#now+ (for example, an +OAuth::Signature::Clock+ with a fixed time).
    class Clock
      # @param now [Time, #to_time] initial current time, defaults to the real clock
      def initialize(now = nil)
        @now = now
      end

      # @return [Time] the current time according to this clock
      def now
        (@now || Time.now).to_time
      end

      # Move a fixed clock forward.
      #
      # @param seconds [Numeric] number of seconds to advance
      # @return [Time] the new current time
      def advance(seconds)
        @now = now + seconds
        now
      end

      # Pin the clock to an explicit time.
      #
      # @param time [Time, #to_time]
      # @return [Time]
      def now=(time)
        @now = time.to_time
      end
    end
  end
end
