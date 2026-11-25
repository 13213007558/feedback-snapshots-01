# frozen_string_literal: true

require "digest"

module Sidekiq
  module Job
    module Iterable
      # Persists iteration progress. The default store keeps state in Redis
      # under the job's iteration key. A local store is provided so examples
      # and tests can pause and resume jobs without a Redis server.
      #
      # A store must implement:
      #
      #   read(key)              -> Hash of persisted fields
      #   write(key, fields)     -> the current cancellation marker or nil
      #   unlink(key)            -> remove all state for the key
      #   cancel(key)            -> set and return the cancellation marker
      #   ledger(key, digest)    -> an object with committed?/record/clear/count
      class RedisStateStore
        def self.instance
          @instance ||= new
        end

        def read(key)
          Sidekiq.redis { |conn| conn.hgetall(key) }
        end

        def write(key, fields)
          Sidekiq.redis do |conn|
            conn.multi do |pipe|
              pipe.hset(key, fields)
              pipe.expire(key, Iterable::STATE_TTL, "nx")
              pipe.hget(key, "cancelled")
            end
          end.last
        end

        def unlink(key)
          Sidekiq.redis { |conn| conn.unlink(key) }
        end

        def cancel(key)
          _, result, _ = Sidekiq.redis do |conn|
            conn.pipelined do |pipe|
              pipe.hsetnx(key, "cancelled", Time.now.to_i)
              pipe.hget(key, "cancelled")
              pipe.expire(key, Iterable::STATE_TTL, "nx")
            end
          end
          result.to_i
        end

        def cancelled_marker(key)
          Sidekiq.redis { |conn| conn.hget(key, "cancelled") }
        end

        def ledger(key, scope_digest)
          RedisCommitLedger.new("#{key}-ledger-#{scope_digest[0, 16]}")
        end
      end

      # An in-process store for local demos and tests. State and commit
      # ledgers survive across job attempts as long as the store object does.
      class MemoryStateStore
        def initialize
          @states = {}
          @ledgers = {}
          @failed_writes = 0
          @writes = 0
        end

        attr_reader :writes, :failed_writes

        def read(key)
          (@states[key] || {}).dup
        end

        def write(key, fields)
          @writes += 1
          if @fail_next_write
            @fail_next_write = false
            @failed_writes += 1
            raise IOError, "simulated iteration progress save failure"
          end

          state = (@states[key] ||= {})
          fields.each { |(k, v)| state[k.to_s] = v }
          state["cancelled"]
        end

        def unlink(key)
          @states.delete(key)
          nil
        end

        def cancel(key)
          state = (@states[key] ||= {})
          state["cancelled"] ||= Time.now.to_i.to_s
          state["cancelled"].to_i
        end

        def cancelled_marker(key)
          @states.dig(key, "cancelled")
        end

        # Make the next progress write fail, simulating a crash or a Redis
        # outage after an iteration has already committed its work.
        def fail_next_write!
          @fail_next_write = true
          self
        end

        def ledger(key, scope_digest)
          @ledgers[[key, scope_digest]] ||= MemoryCommitLedger.new
        end

        # Read-only access for demos and assertions.
        def ledger_for(key, scope_digest)
          @ledgers[[key, scope_digest]]
        end

        def keys
          @states.keys
        end
      end

      # Redis-backed commit ledger. Only digests of commit keys are stored,
      # so the ledger cannot leak record identifiers or payloads.
      class RedisCommitLedger
        def initialize(key)
          @key = key
        end

        def committed?(commit_key)
          !Sidekiq.redis { |conn| conn.hget(@key, digest(commit_key)) }.nil?
        end

        def record(commit_key)
          Sidekiq.redis do |conn|
            conn.multi do |pipe|
              pipe.hset(@key, digest(commit_key), "1")
              pipe.expire(@key, Iterable::STATE_TTL, "nx")
            end
          end
          true
        end

        def clear
          Sidekiq.redis { |conn| conn.unlink(@key) }
          true
        end

        def count
          Sidekiq.redis { |conn| conn.hlen(@key) }
        end

        private

        def digest(commit_key)
          Digest::SHA256.hexdigest(commit_key.to_s)
        end
      end

      # In-memory commit ledger used by MemoryStateStore.
      class MemoryCommitLedger
        def initialize
          @entries = {}
        end

        def committed?(commit_key)
          @entries.key?(Digest::SHA256.hexdigest(commit_key.to_s))
        end

        def record(commit_key)
          @entries[Digest::SHA256.hexdigest(commit_key.to_s)] = true
          true
        end

        def clear
          @entries.clear
          true
        end

        def count
          @entries.size
        end
      end
    end
  end
end
