# frozen_string_literal: true

module Rack
  class Attack
    module Replay
      # Mutable virtual clock. The replay engine sets #time to each event's
      # timestamp before evaluating it, so rule evaluation never depends on
      # the wall clock.
      class Clock
        attr_accessor :time

        def initialize(start = Time.at(0))
          @time = start
        end
      end
    end
  end
end
