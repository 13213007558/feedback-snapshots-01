# frozen_string_literal: true

module CountingHarness
  # Seeded generator of short operation sequences. Deterministic for a given
  # seed: no randomness leaks in from the environment.
  class Generator
    def initialize(seed, tids: [:a, :b], period: 30, max_length: 9, faults: [])
      @random = Random.new(seed)
      @tids = tids
      @period = period
      @max_length = max_length
      @faults = faults
    end

    def next
      length = 4 + @random.rand(@max_length - 3)
      fault_count = 0
      Array.new(length) do
        roll = @random.rand(10)
        if roll < 5
          [:run, random_tid]
        elsif roll < 7
          [:request, random_tid]
        elsif roll < 8
          [:tick, [1, @period - 1, @period, @period + 1][@random.rand(4)]]
        elsif !@faults.empty? && fault_count < 2
          fault_count += 1
          [:fault, @faults[@random.rand(@faults.length)]]
        else
          [:run, random_tid]
        end
      end
    end

    private

    def random_tid
      @tids[@random.rand(@tids.length)]
    end
  end

  # Shrinks a failing script by deletion only: events are never reordered, so
  # the relative thread interleaving is preserved. Tick events anchor expiry
  # positions and are never removed, and every thread keeps at least one
  # :run/:request event so the interleaving cannot be shrunk away entirely.
  class Shrinker
    def initialize(&fails)
      @fails = fails
    end

    def shrink(script)
      tids = thread_events(script).map { |event| event[1] }.uniq
      current = script.dup
      improved = true
      while improved
        improved = false
        index = 0
        while index < current.length
          event = current[index]
          if event[0] == :tick
            index += 1
            next
          end
          candidate = current[0...index] + current[(index + 1)..-1]
          if keeps_interleaving?(candidate, tids) && @fails.call(candidate)
            current = candidate
            improved = true
          else
            index += 1
          end
        end
      end
      current
    end

    private

    def thread_events(script)
      script.select { |event| event[0] == :run || event[0] == :request }
    end

    def keeps_interleaving?(script, tids)
      remaining = thread_events(script).map { |event| event[1] }
      tids.all? { |tid| remaining.include?(tid) }
    end
  end
end
