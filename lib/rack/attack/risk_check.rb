# frozen_string_literal: true

module Rack
  class Attack
    # A blocklist-style check backed by an external risk scorer, executed
    # under a bounded per-request budget (see Rack::Attack::Risk).
    #
    # Options:
    #   scorer:     a Rack::Attack::Risk::Scorer, or any callable (wrapped
    #               automatically). Called with the query on a pool worker.
    #   query:      required proc building the scorer query from the request.
    #               Return nil to make the rule not apply to a request.
    #   on_timeout: policy applied when the verdict is unknown (timeout,
    #               full queue, exhausted budget or scorer error):
    #                 :deny   - treat the request as matched (fail closed)
    #                 :local  - fall back to the local rule block
    #                 :ignore - treat the rule as not matched (fail open)
    #   type:       match type used for instrumentation
    #               (default :risk_blocklist)
    #
    # The block, when given, is the local fallback rule used by the :local
    # policy. Every evaluation (matched or not) is recorded in
    # env["rack.attack.risk.decisions"] with the policy actually adopted;
    # only a digest of the query is recorded, never the raw query.
    class RiskCheck < Check
      ON_TIMEOUT_POLICIES = %i[deny local ignore].freeze

      DECISIONS_ENV_KEY = "rack.attack.risk.decisions"
      RISK_ENV_KEY = "rack.attack.risk"

      attr_reader :on_timeout

      def initialize(name, options = {}, &block)
        super
        @type = options.fetch(:type, :risk_blocklist)
        @on_timeout = options.fetch(:on_timeout, :deny)

        unless ON_TIMEOUT_POLICIES.include?(@on_timeout)
          raise ArgumentError, "on_timeout must be one of #{ON_TIMEOUT_POLICIES.inspect}"
        end
        if @on_timeout == :local && block.nil?
          raise ArgumentError, "on_timeout: :local requires a local rule block"
        end

        @query = options[:query]
        raise ArgumentError, "Must pass :query option" unless @query.respond_to?(:call)

        scorer = options[:scorer]
        raise ArgumentError, "Must pass :scorer option" unless scorer

        @scorer = scorer.is_a?(Risk::Scorer) ? scorer : Risk::Scorer.new(scorer)
      end

      def matched_by?(request)
        query = @query.call(request)
        return false if query.nil?

        budget = Risk::Budget.for(request, Rack::Attack.risk_budget)
        result = budget.fetch(query) { |remaining| @scorer.evaluate(query, timeout: remaining) }

        matched, policy = resolve(request, result)
        record_decision(request, query, result, policy)

        matched.tap do |match|
          annotate_request(request, query, result, policy) if match
        end
      end

      private

      def resolve(request, result)
        case result.state
        when :deny then [true, :scored_deny]
        when :allow then [false, :scored_allow]
        else
          case @on_timeout
          when :deny then [true, :deny_on_unknown]
          when :local then [!!@block.call(request), :local_on_unknown]
          else [false, :ignore_on_unknown]
          end
        end
      end

      def record_decision(request, query, result, policy)
        decisions = (request.env[DECISIONS_ENV_KEY] ||= [])
        decisions << {
          rule: name,
          outcome: result.state,
          reason: result.reason,
          policy: policy,
          query_digest: Risk::Budget.digest(query)
        }
      end

      def annotate_request(request, query, result, policy)
        request.env["rack.attack.matched"] = name
        request.env["rack.attack.match_type"] = type
        request.env[RISK_ENV_KEY] = {
          policy: policy,
          outcome: result.state,
          reason: result.reason,
          query_digest: Risk::Budget.digest(query)
        }
        Rack::Attack.instrument(request)
      end
    end
  end
end
