# frozen_string_literal: true

module Rack
  class Attack
    module Replay
      # Evaluates one ruleset against one event, mirroring the decision
      # order of Rack::Attack#call (safelist -> blocklist -> throttle ->
      # track). Responders are never invoked and no notifications are
      # emitted; only the decision is recorded.
      class Evaluator
        def initialize(config)
          @config = config
        end

        def evaluate(event)
          request = Request.new(event.build_env, event.provided_fields)
          decision = decide(request)
          apply_effects(event) if decision["verdict"] == "allow"
          decision
        end

        private

        def decide(request)
          tracker = MissingFieldTracker.new(request)

          if (rule = first_match(safelist_rules, request, tracker))
            return finalize(request, "allow", rule, tracker)
          end

          if (rule = first_match(blocklist_rules, request, tracker))
            return finalize(request, "block", rule, tracker)
          end

          if (rule = first_match(throttle_rules, request, tracker))
            return finalize(request, "throttle", rule, tracker)
          end

          # Tracks never change the verdict, so fields only they read are
          # reported as warnings rather than making the event undecidable.
          pre_track_count = request.missing_reads.length
          @config.tracks.each_value { |track| track.matched_by?(request) }
          track_missing = request.missing_reads[pre_track_count..-1] || []

          finalize(request, "allow", nil, tracker, request.missing_reads[0...pre_track_count]).tap do |decision|
            decision["track_warnings"] = track_missing if track_missing.any?
          end
        end

        def finalize(request, verdict, rule, tracker, missing = nil)
          missing ||= tracker.missing_so_far
          unless missing.empty?
            return {
              "verdict" => "undecidable",
              "missing" => missing,
              "missing_rule" => tracker.first_missing_rule,
              "would_be" => verdict
            }
          end

          decision = { "verdict" => verdict }
          decision["rule"] = rule if rule
          if (discriminator = request.env["rack.attack.match_discriminator"])
            decision["discriminator_sha256"] = Event.digest(discriminator)
          end
          decision
        end

        def first_match(rules, request, tracker)
          rules.each do |label, filter|
            matched = false
            tracker.around(label) { matched = filter.matched_by?(request) }
            return label if matched
          end
          nil
        end

        def safelist_rules
          labeled(@config.anonymous_safelists, "anonymous safelist") + @config.safelists.to_a
        end

        def blocklist_rules
          labeled(@config.anonymous_blocklists, "anonymous blocklist") + @config.blocklists.to_a
        end

        def throttle_rules
          @config.throttles.to_a
        end

        def labeled(filters, fallback)
          filters.each_with_index.map { |filter, i| ["(#{fallback} ##{i + 1})", filter] }
        end

        def apply_effects(event)
          event.effects.each do |effect|
            if (reset = effect["allow2ban_reset"])
              Rack::Attack::Allow2Ban.reset(reset.fetch("discriminator"), findtime: reset.fetch("findtime"))
            elsif (reset = effect["fail2ban_reset"])
              Rack::Attack::Fail2Ban.reset(reset.fetch("discriminator"), findtime: reset.fetch("findtime"))
            end
          end
        end

        # Notes which rule was being evaluated when a missing field was read.
        class MissingFieldTracker
          def initialize(request)
            @request = request
            @first_missing_rule = nil
          end

          def around(rule_label)
            before = @request.missing_reads.length
            yield
            @first_missing_rule ||= rule_label if @request.missing_reads.length > before
          end

          def missing_so_far
            @request.missing_reads
          end

          attr_reader :first_missing_rule
        end
      end
    end
  end
end
