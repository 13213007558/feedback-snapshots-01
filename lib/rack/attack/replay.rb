# frozen_string_literal: true

require 'rack/attack/replay/clock'
require 'rack/attack/replay/store'
require 'rack/attack/replay/cache'
require 'rack/attack/replay/request'
require 'rack/attack/replay/event'
require 'rack/attack/replay/evaluator'

module Rack
  class Attack
    # Offline replay of sanitized request events against two rulesets
    # (old vs new), reporting how each event's decision changes.
    #
    # Isolation guarantees:
    # - evaluation runs against a private in-memory cache keyed by a
    #   virtual clock; the configured production cache is never touched
    # - notifications are silenced for the duration of the run
    # - responders are never invoked; only decisions are computed
    #
    # Determinism guarantees:
    # - events are replayed ordered by (timestamp, input position)
    # - the report contains no wall-clock timestamps or random values, so
    #   identical input yields an identical report
    #
    # Usage:
    #   report = Rack::Attack::Replay.run(
    #     old:    ->(config) { ... }, # see Rack::Attack::Replay.ruleset
    #     new:    ->(config) { ... },
    #     events: [{ "at" => "...", "method" => "GET", "path" => "/", ... }]
    #   )
    module Replay
      class InvalidEventError < Rack::Attack::Error; end

      # How restrictive each verdict is; used to classify diffs.
      SEVERITY = { "allow" => 0, "throttle" => 1, "block" => 2 }.freeze

      class << self
        # Helper for ruleset files: the file's last expression is
        # `Rack::Attack::Replay.ruleset do |config| ... end`, which simply
        # returns the block so it can be loaded and passed to .run.
        def ruleset(&block)
          block
        end

        def run(old:, new:, events:)
          parsed = events.each_with_index.map { |raw, i| Event.new(raw, i) }.sort

          old_decisions = run_ruleset(old, parsed)
          new_decisions = run_ruleset(new, parsed)

          {
            "version" => 1,
            "events" => parsed.map(&:report_entry),
            "runs" => {
              "old" => old_decisions,
              "new" => new_decisions
            },
            "diffs" => diffs(parsed, old_decisions, new_decisions)
          }
        end

        private

        def run_ruleset(ruleset, events)
          clock = Clock.new
          cache = Cache.new(clock)

          with_isolated_state(cache) do
            config = Rack::Attack::Configuration.new
            ruleset.call(config)
            evaluator = Evaluator.new(config)

            events.map do |event|
              clock.time = event.at
              evaluator.evaluate(event)
            end
          end
        end

        # Swap in the replay cache and silence notifications, restoring
        # global state afterwards no matter what.
        def with_isolated_state(cache)
          previous_cache = Rack::Attack.instance_variable_get(:@cache)
          previous_notifier = Rack::Attack.notifier

          Rack::Attack.instance_variable_set(:@cache, cache)
          Rack::Attack.notifier = nil

          yield
        ensure
          Rack::Attack.instance_variable_set(:@cache, previous_cache)
          Rack::Attack.notifier = previous_notifier
        end

        def diffs(events, old_decisions, new_decisions)
          events.each_with_index.each_with_object([]) do |(event, position), result|
            old_decision = old_decisions[position]
            new_decision = new_decisions[position]
            kind = diff_kind(old_decision, new_decision)
            next unless kind

            result << {
              "event" => event.index,
              "at" => event.at.utc.iso8601,
              "kind" => kind,
              "old" => old_decision,
              "new" => new_decision
            }
          end
        end

        def diff_kind(old_decision, new_decision)
          old_verdict = old_decision["verdict"]
          new_verdict = new_decision["verdict"]

          if old_verdict == "undecidable" || new_verdict == "undecidable"
            return nil if old_decision == new_decision
            return "undecidable"
          end

          return nil if old_verdict == new_verdict

          if SEVERITY.fetch(new_verdict) > SEVERITY.fetch(old_verdict)
            "tightened"
          elsif SEVERITY.fetch(new_verdict) < SEVERITY.fetch(old_verdict)
            "loosened"
          else
            "changed"
          end
        end
      end
    end
  end
end
