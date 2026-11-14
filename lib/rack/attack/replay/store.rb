# frozen_string_literal: true

module Rack
  class Attack
    module Replay
      # In-memory cache store used exclusively by offline replay. Expiry is
      # computed against the virtual clock, never the wall clock, and nothing
      # here ever touches a production cache.
      class Store
        def initialize(clock)
          @clock = clock
          @data = {}
        end

        def read(key)
          entry = @data[key]
          return nil unless entry
          return nil if expired?(entry)

          entry.first
        end

        def write(key, value, options = nil)
          expires_in = options && options[:expires_in]
          @data[key] = [value, expires_in ? @clock.time.to_i + expires_in.to_i : nil]
          true
        end

        def increment(key, amount = 1, options = nil)
          entry = @data[key]
          return nil if entry.nil? || expired?(entry)

          entry[0] += amount
          entry[0]
        end

        def delete(key)
          @data.delete(key)
          true
        end

        def delete_matched(pattern)
          @data.delete_if { |key, _| key =~ pattern }
          true
        end

        private

        def expired?(entry)
          expires_at = entry[1]
          !expires_at.nil? && expires_at <= @clock.time.to_i
        end
      end
    end
  end
end
