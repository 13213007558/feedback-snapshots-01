# frozen_string_literal: true

module Rack
  class Attack
    module Replay
      # A Rack::Attack::Cache backed by the in-memory replay store, keyed
      # against the virtual clock so throttle windows and ban expiries are
      # fully deterministic.
      class Cache < Rack::Attack::Cache
        def initialize(clock)
          @clock = clock
          super(store: Store.new(clock))
        end

        private

        def current_time
          @clock.time
        end
      end
    end
  end
end
