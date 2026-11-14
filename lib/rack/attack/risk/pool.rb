# frozen_string_literal: true

module Rack
  class Attack
    module Risk
      # A bounded worker pool used to run synchronous risk scorer calls off the
      # request path. The number of threads executing scorer code never exceeds
      # +size+, and the number of queued calls never exceeds +queue_capacity+,
      # so a stalled scorer can never create unbounded threads or backlog.
      #
      # Callers that time out simply abandon their Future; the worker either
      # skips the stale task or finishes it and discards the result. Workers
      # are never interrupted mid-call (see docs/risk_scoring.md for why
      # interrupting synchronous Ruby code is unsafe).
      class Pool
        STOP = Object.new.freeze

        # Result handle for a submitted task. #result waits at most the given
        # timeout and never spawns threads.
        class Future
          def initialize
            @mutex = Mutex.new
            @condition = ConditionVariable.new
            @finished = false
            @abandoned = false
            @value = nil
            @error = nil
          end

          def fulfill(value)
            @mutex.synchronize do
              @finished = true
              @value = value
              @condition.broadcast
            end
          end

          def fail(error)
            @mutex.synchronize do
              @finished = true
              @error = error
              @condition.broadcast
            end
          end

          def abandoned?
            @mutex.synchronize { @abandoned }
          end

          # Returns [:ok, value], [:error, exception] or [:timeout, nil].
          # On timeout the future is marked abandoned so the worker can skip
          # or discard it.
          def result(timeout)
            deadline = monotonic_now + timeout
            @mutex.synchronize do
              until @finished
                remaining = deadline - monotonic_now
                if remaining <= 0
                  @abandoned = true
                  return [:timeout, nil]
                end
                @condition.wait(@mutex, remaining)
              end
              return [:error, @error] if @error

              [:ok, @value]
            end
          end

          private

          def monotonic_now
            Process.clock_gettime(Process::CLOCK_MONOTONIC)
          end
        end

        attr_reader :size, :queue_capacity

        def initialize(size:, queue_capacity:)
          @size = size
          @queue_capacity = queue_capacity
          @queue = SizedQueue.new(queue_capacity)
          @workers = Array.new(size) { spawn_worker }
        end

        # Returns a Future, or nil when the queue is full (caller must treat
        # that as an immediately unknown result).
        def submit(task)
          future = Future.new
          @queue.push([task, future], true)
          future
        rescue ThreadError
          nil
        end

        def pending
          @queue.size
        end

        def worker_count
          @workers.count(&:alive?)
        end

        # Best-effort stop: queued stale work is skipped, in-flight calls run
        # to completion. Workers blocked inside a scorer call are never
        # killed; they exit once the call returns.
        def shutdown
          @workers.size.times do
            begin
              @queue.push([STOP, nil], true)
            rescue ThreadError
              break
            end
          end
          @workers.each { |worker| worker.join(1) }
        end

        private

        def spawn_worker
          Thread.new do
            Thread.current.name = "rack-attack-risk-worker" if Thread.current.respond_to?(:name=)
            loop do
              task, future = @queue.pop
              break if task.equal?(STOP)
              next if future.abandoned?

              begin
                future.fulfill(task.call)
              rescue => error
                future.fail(error)
              end
            end
          end
        end
      end
    end
  end
end
