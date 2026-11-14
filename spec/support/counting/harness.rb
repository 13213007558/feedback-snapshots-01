# frozen_string_literal: true

require "timecop"

# Deterministic state-machine harness for Rack::Attack::Cache counting.
#
# A *script* is a short sequence of events:
#   [:run, tid]       - advance the logical thread +tid+'s count operation by
#                       one atomic store step (spawns it on first use)
#   [:request, tid]   - run the logical thread +tid+'s count to completion
#   [:tick, seconds]  - advance the logical clock (anchors expiry positions)
#   [:fault, kind]    - arm a one-shot fault for the next store operation
#
# Modeling assumptions:
#   * A count operation always completes within the expiry slack (the +1s
#     that Rack::Attack adds to expires_in). Therefore the runner drains
#     in-flight counts before applying a :tick; time never advances in the
#     middle of a suspended count.
#   * Fault kinds distinguish "confirmed failure" from "unknown outcome":
#       :confirm_miss    - definitely NOT applied, caller sees nil
#       :timeout_before  - not applied, caller sees nil and cannot tell
#       :timeout_after   - IS applied, caller sees nil (response lost)
#       :write_rejected  - add-if-absent write loses the race, returns false
module CountingHarness
  FAULTS = [:confirm_miss, :timeout_before, :timeout_after, :write_rejected].freeze

  UNKNOWN_OUTCOME_FAULTS = [:timeout_before, :timeout_after].freeze

  class LogicalClock
    attr_reader :now

    def initialize(start = 1_700_000_000)
      @now = start
    end

    def advance(seconds)
      @now += seconds
    end
  end

  # In-memory adapter with configurable capabilities, fault injection and
  # preemption points. Preemption is driven through a +suspender+ hook that
  # the Runner installs; used directly (no suspender) every operation is
  # executed eagerly, which is convenient for plain fault-semantics probes.
  class ScriptedStore
    attr_accessor :suspender

    def initialize(clock, increment_style: :atomic, ttl: true)
      @clock = clock
      @increment_style = increment_style # :atomic | :nil_on_miss | :non_atomic
      @ttl = ttl
      @entries = {} # key => [value, expires_at]
      @fault = nil
      @suspender = ->(_info) {}
    end

    # The capabilities this store claims to provide (used by the reference
    # model). A broken store claims capabilities it does not actually deliver;
    # the checker is expected to refute the claim with a counterexample.
    def capabilities
      {
        atomic_increment: @increment_style == :atomic,
        nil_means_absent: @increment_style == :nil_on_miss,
        confirmed_write: true,
        ttl: @ttl
      }
    end

    def arm_fault(kind)
      raise ArgumentError, "unknown fault: #{kind.inspect}" unless FAULTS.include?(kind)

      @fault = kind
    end

    def read(key)
      suspend(:read, key)
      value_of(key)
    end

    def write(key, value, options = {})
      suspend(:write, key)
      fault = take_fault
      return nil if fault == :confirm_miss || fault == :timeout_before

      if fault == :write_rejected
        return false if live?(key) # add-if-absent: first-write conflict lost

        apply_write(key, value, options[:expires_in])
        return true
      end

      apply_write(key, value, options[:expires_in])
      fault == :timeout_after ? nil : true
    end

    def increment(key, amount, options = {})
      if @increment_style == :non_atomic
        non_atomic_increment(key, amount, options)
      else
        atomic_increment(key, amount, options)
      end
    end

    def delete(key)
      suspend(:delete, key)
      @entries.delete(key)
      true
    end

    def value_of(key)
      purge_key(key)
      entry = @entries[key]
      entry && entry[0]
    end

    def keys
      purge_all
      @entries.keys
    end

    private

    def atomic_increment(key, amount, options)
      suspend(:increment, key)
      fault = take_fault
      return nil if fault == :confirm_miss || fault == :timeout_before

      current = value_of(key)
      if current.nil? && @increment_style == :nil_on_miss
        return nil # memcached-style: nil means "not initialized" (confirmed)
      end

      new_value = (current || 0) + amount
      if current.nil?
        apply_write(key, new_value, options[:expires_in])
      else
        @entries[key][0] = new_value # keep the original expiry (fixed window)
      end
      fault == :timeout_after ? nil : new_value
    end

    # Deliberately broken read-modify-write increment: the read and the write
    # are separate atomic steps with a preemption point in between, so two
    # interleaved increments can lose one update.
    def non_atomic_increment(key, amount, options)
      suspend(:incr_read, key)
      fault = take_fault
      current = value_of(key)
      suspend(:incr_write, key)
      return nil if fault == :confirm_miss || fault == :timeout_before

      new_value = (current || 0) + amount
      apply_write(key, new_value, options[:expires_in])
      fault == :timeout_after ? nil : new_value
    end

    def apply_write(key, value, expires_in)
      expires_at = @ttl && expires_in ? @clock.now + expires_in : nil
      @entries[key] = [value, expires_at]
    end

    def live?(key)
      !value_of(key).nil?
    end

    def purge_key(key)
      entry = @entries[key]
      @entries.delete(key) if entry && entry[1] && @clock.now >= entry[1]
    end

    def purge_all
      @entries.keys.each { |key| purge_key(key) }
    end

    def take_fault
      fault = @fault
      @fault = nil
      fault
    end

    def suspend(op, key)
      @suspender.call([op, key])
    end
  end

  # Replays a script against a real Rack::Attack::Cache (or a subclass),
  # scheduling each logical thread's count operation one store step at a time
  # through fibers. Fully deterministic: no real threads, no sleeps.
  class Runner
    Result = Struct.new(:counts, :windows, :trace) do
      # Requests admitted per window, worst window first. The threshold
      # promise is per window: admitted(limit) <= limit must hold for the
      # busiest window, not for the whole script.
      def admitted(limit)
        per_window = Hash.new(0)
        counts.each do |tid, count|
          per_window[windows[tid]] += 1 if count <= limit
        end
        per_window.values.max || 0
      end

      def tids
        counts.keys
      end
    end

    attr_reader :trace

    def initialize(cache, clock, period, key: "attack")
      @cache = cache
      @clock = clock
      @period = period
      @key = key
      @trace = []
      install_suspender
    end

    def run(script)
      fibers = {}
      counts = {}
      windows = {}
      script.each do |event|
        case event[0]
        when :tick
          drain(fibers) # counts complete within the expiry slack
          @clock.advance(event[1])
          @trace << [:tick, event[1]]
        when :fault
          @cache.store.arm_fault(event[1])
          @trace << [:fault, event[1]]
        when :run
          tid = event[1]
          fibers[tid] ||= spawn_count_fiber(counts, windows, tid)
          step(fibers[tid], tid)
        when :request
          tid = event[1]
          fibers[tid] ||= spawn_count_fiber(counts, windows, tid)
          step(fibers[tid], tid) while fibers[tid].alive?
        else
          raise ArgumentError, "unknown event: #{event.inspect}"
        end
      end
      drain(fibers)
      Result.new(counts, windows, @trace)
    end

    private

    def install_suspender
      store = @cache.store
      return unless store.respond_to?(:suspender=)

      store.suspender = ->(info) { Fiber.yield(info) }
    end

    def spawn_count_fiber(counts, windows, tid)
      Fiber.new do
        counts[tid] = @cache.count(@key, @period)
        windows[tid] = @cache.last_epoch_time / @period
      end
    end

    def step(fiber, tid)
      return unless fiber.alive?

      yielded = Timecop.freeze(Time.at(@clock.now)) { fiber.resume }
      @trace << [:op, tid, yielded] if yielded.is_a?(Array)
      @trace << [:done, tid] unless fiber.alive?
    end

    # Finish any counts the script left in flight, oldest thread id first,
    # so that every script denotes a complete, deterministic execution.
    def drain(fibers)
      loop do
        alive = fibers.select { |_tid, fiber| fiber.alive? }
        break if alive.empty?

        alive.sort_by { |tid, _fiber| tid.to_s }.each do |tid, fiber|
          step(fiber, tid)
        end
      end
    end
  end
end
