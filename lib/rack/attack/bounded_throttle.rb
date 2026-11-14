# frozen_string_literal: true

require 'ipaddr'
require 'openssl'
require 'rack/attack/throttle'

module Rack
  class Attack
    # A throttle whose cache-key cardinality is bounded by configuration rather
    # than by the number of distinct discriminators observed.
    #
    # Strategies:
    #
    # * :gate   - evaluate exact budgets over trusted dimensions first. Only
    #             requests that pass every budget reach the exact per-account
    #             counter. The global budget therefore also bounds the number
    #             of per-account keys created in a period.
    # * :budget - evaluate only the exact budgets. There is no per-account
    #             counter; this is the smallest and most predictable state.
    # * :sketch - a count-min sketch for the per-account limit. The
    #             discriminator is never a key; it is hashed into <buckets>
    #             slots in each of <depth> rows and the minimum row is used.
    # * :hybrid - budgets first, then the sketch for admitted requests. The
    #             budget keeps a high-cardinality flood from polluting the
    #             sketch after the budget trips.
    #
    # Every counter is updated with the store's atomic #increment. Counters
    # expire after at most period + 1 seconds, so two generations can coexist
    # at a period boundary.
    class BoundedThrottle < Throttle
      STRATEGIES = [:gate, :budget, :sketch, :hybrid].freeze

      DEFAULT_STRATEGY = :sketch
      DEFAULT_BUCKETS = 4096
      DEFAULT_DEPTH = 3
      DEFAULT_SCOPE_BUCKETS = 1
      DEFAULT_BUDGET_BUCKETS = 1024
      MAX_DEPTH = 8
      MAX_STRING_BYTES = 256

      attr_reader :strategy, :buckets, :depth, :scope_buckets, :budgets, :hash_key

      def initialize(name, options, &block)
        super

        @strategy = options.fetch(:strategy, DEFAULT_STRATEGY).to_sym
        unless STRATEGIES.include?(@strategy)
          raise ArgumentError, "strategy must be one of #{STRATEGIES.inspect}"
        end

        @buckets = positive_integer(options.fetch(:buckets, DEFAULT_BUCKETS), :buckets)
        @depth = positive_integer(options.fetch(:depth, DEFAULT_DEPTH), :depth)
        if @depth > MAX_DEPTH
          raise ArgumentError, "depth must be less than or equal to #{MAX_DEPTH}"
        end

        if sketch? && !limit.respond_to?(:call) && @buckets <= limit
          raise ArgumentError, 'buckets must be greater than limit to avoid guaranteed false blocks'
        end

        @scope = options[:scope]
        @scope_buckets = positive_integer(options.fetch(:scope_buckets, DEFAULT_SCOPE_BUCKETS), :scope_buckets)
        @hash_key = options[:hash_key] || Rack::Attack.bounded_throttle_hash_key
        @budgets = build_budgets(options[:budgets])

        if budget? && @budgets.empty?
          raise ArgumentError, "strategy #{@strategy.inspect} requires at least one entry in :budgets"
        end

        if @strategy == :gate
          if period.respond_to?(:call)
            raise ArgumentError, 'strategy :gate requires a literal throttle period'
          end
          unless @budgets.all? { |budget| budget[:period] == period.to_i }
            raise ArgumentError, 'strategy :gate requires every budget period to equal the throttle period'
          end
        end

        @admitted_bound = @strategy == :gate ? @budgets.map { |b| b[:limit] * b[:buckets] }.min : 0
      end

      def sketch?
        strategy == :sketch || strategy == :hybrid
      end

      def budget?
        strategy == :gate || strategy == :budget || strategy == :hybrid
      end

      # Upper bound on the number of cache keys this throttle can create in one
      # period. At a period boundary two generations may overlap.
      def max_state_keys
        keys = 0
        if budget?
          @budgets.each { |budget| keys += budget[:buckets] }
        end
        keys += @scope_buckets * @depth * @buckets if sketch?
        keys += @admitted_bound if @strategy == :gate
        keys
      end

      def max_state_keys_at_boundary
        max_state_keys * 2
      end

      def matched_by?(request)
        discriminator = discriminator_for(request)
        return false unless discriminator

        normalized_discriminator = bounded_string(discriminator)
        return false if normalized_discriminator.empty?

        current_period = period_for(request)
        current_limit = limit_for(request)

        budget_data = budget? ? increment_budgets(request) : []
        blocked_budget = budget_data.find { |budget| budget[:count] > budget[:limit] }

        if blocked_budget
          count = blocked_budget[:count]
          matched_period = blocked_budget[:period]
          matched_limit = blocked_budget[:limit]
        elsif @strategy == :gate
          account_key = "#{name}:bounded:account:#{scope_slot_for(request)}:#{digest_hex(normalized_discriminator)}"
          count = cache.count(account_key, current_period)
          matched_period = current_period
          matched_limit = current_limit
        elsif sketch?
          count = increment_sketch(request, normalized_discriminator, current_period)
          matched_period = current_period
          matched_limit = current_limit
        else
          count = 0
          matched_period = current_period
          matched_limit = current_limit
        end

        throttled = !!blocked_budget || (@strategy != :budget && count > matched_limit)

        data = {
          discriminator: normalized_discriminator,
          count: count,
          period: matched_period,
          limit: matched_limit,
          epoch_time: cache.last_epoch_time,
          strategy: @strategy,
          sketch: sketch?,
          buckets: @buckets,
          depth: @depth,
          scope_buckets: @scope_buckets,
          state_key_bound: max_state_keys,
          matched_budget: blocked_budget ? blocked_budget[:name] : nil,
          budgets: budget_data
        }

        annotate_request_with_throttle_data(request, data)

        if throttled
          annotate_request_with_matched_data(request, data)
          Rack::Attack.instrument(request)
        end
        throttled
      end

      private

      def build_budgets(config)
        return [] if config.nil?
        raise ArgumentError, 'budgets must be a Hash' unless config.is_a?(Hash)

        config.map do |name, raw_options|
          options = raw_options == true ? {} : raw_options
          raise ArgumentError, "budget #{name.inspect} must be a Hash" unless options.is_a?(Hash)

          limit = options[:limit]
          raise ArgumentError, "budget #{name.inspect} must pass :limit" unless limit

          budget_period = options[:period] || default_budget_period
          unless budget_period
            raise ArgumentError, "budget #{name.inspect} must pass :period when the throttle period is a Proc"
          end

          discriminator = options[:discriminator]
          if name != :global && !discriminator.respond_to?(:call)
            raise ArgumentError, "budget #{name.inspect} must pass :discriminator"
          end

          {
            name: name,
            limit: positive_integer(limit, :limit),
            period: positive_integer(budget_period, :period),
            buckets: positive_integer(options.fetch(:buckets, DEFAULT_BUDGET_BUCKETS), :buckets),
            discriminator: discriminator,
            prefix: options[:prefix]
          }
        end
      end

      def default_budget_period
        period.respond_to?(:call) ? nil : period
      end

      def increment_budgets(request)
        results = []
        @budgets.each do |budget|
          value = budget[:discriminator] ? budget[:discriminator].call(request) : 'global'
          value = normalize_principal(value, budget[:prefix])
          slot = slot_for("budget\0#{budget[:name]}\0#{value}", budget[:buckets])
          count = cache.count("#{name}:bounded:budget:#{budget[:name]}:#{slot}", budget[:period])
          results << {
            name: budget[:name],
            count: count,
            limit: budget[:limit],
            period: budget[:period],
            buckets: budget[:buckets]
          }
          break if count > budget[:limit]
        end
        results
      end

      def normalize_principal(value, prefix)
        value = bounded_string(value)
        return '' if value.empty?

        if prefix
          begin
            value = IPAddr.new(value).mask(prefix).to_s
          rescue ArgumentError
            # Keep the original value; a malformed client IP must not disable
            # the budget entirely.
          end
        end

        bounded_string(value)
      end

      def increment_sketch(request, discriminator, current_period)
        scope_slot = scope_slot_for(request)
        counts = (0...@depth).map do |row|
          bucket = slot_for("#{row}\0#{discriminator}", @buckets)
          cache.count("#{name}:bounded:sketch:#{scope_slot}:#{row}:#{bucket}", current_period)
        end
        counts.min
      end

      def scope_slot_for(request)
        return 0 unless @scope
        return 0 if @scope_buckets == 1

        value = normalize_principal(@scope.call(request), nil)
        return 0 if value.empty?

        slot_for("scope\0#{value}", @scope_buckets)
      end

      def slot_for(value, buckets)
        return 0 if buckets == 1

        hash_to_integer(value) % buckets
      end

      def hash_to_integer(value)
        OpenSSL::Digest::SHA256.digest(digest_input(value)).unpack('N').first
      end

      def digest_hex(value)
        if @hash_key
          OpenSSL::HMAC.hexdigest('SHA256', @hash_key.to_s, value)
        else
          OpenSSL::Digest::SHA256.hexdigest(value)
        end
      end

      def digest_input(value)
        @hash_key ? OpenSSL::HMAC.digest('SHA256', @hash_key.to_s, value) : value
      end

      def bounded_string(value)
        value.to_s.byteslice(0, MAX_STRING_BYTES).to_s.scrub
      end

      def positive_integer(value, option_name)
        integer = Integer(value)
        raise ArgumentError, "#{option_name} must be a positive integer" unless integer > 0

        integer
      rescue ArgumentError, TypeError
        raise ArgumentError, "#{option_name} must be a positive integer"
      end
    end
  end
end
