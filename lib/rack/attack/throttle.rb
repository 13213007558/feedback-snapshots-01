# frozen_string_literal: true

module Rack
  class Attack
    class Throttle
      MANDATORY_OPTIONS = [:limit, :period].freeze

      attr_reader :name, :limit, :period, :block, :type

      def initialize(name, options, &block)
        @name = name
        @block = block
        MANDATORY_OPTIONS.each do |opt|
          raise ArgumentError, "Must pass #{opt.inspect} option" unless options[opt]
        end
        @limit = options[:limit]
        @period = options[:period].respond_to?(:call) ? options[:period] : options[:period].to_i
        @type   = options.fetch(:type, :throttle)
      end

      def cache
        Rack::Attack.cache
      end

      # Metering contract: counts the current request against this throttle,
      # exactly once per request, without any decision side effects (no match
      # annotation, no instrumentation).
      #
      # Returns true/false when the throttle applies to the request (i.e. the
      # discriminator is present), indicating whether the limit is exceeded.
      # Returns nil when the throttle does not apply; in that case nothing is
      # written to the cache.
      def meter(request)
        metered = (request.env['rack.attack.metered_throttles'] ||= {})

        return metered[name] if metered.key?(name)

        metered[name] = perform_metering(request)
      end

      # Legacy contract: meters the request and, when the limit is exceeded,
      # annotates the request and instruments the match. Kept for backwards
      # compatibility; new code should rely on Configuration#evaluate instead.
      def matched_by?(request)
        !!meter(request).tap do |throttled|
          if throttled
            data = request.env['rack.attack.throttle_data'][name]
            annotate_request_with_matched_data(request, data)
            Rack::Attack.instrument(request)
          end
        end
      end

      private

      def perform_metering(request)
        discriminator = discriminator_for(request)
        return nil unless discriminator

        current_period  = period_for(request)
        current_limit   = limit_for(request)
        count           = cache.count("#{name}:#{discriminator}", current_period)

        data = {
          discriminator: discriminator,
          count: count,
          period: current_period,
          limit: current_limit,
          epoch_time: cache.last_epoch_time
        }

        annotate_request_with_throttle_data(request, data)

        count > current_limit
      end

      def discriminator_for(request)
        discriminator = block.call(request)
        if discriminator && Rack::Attack.throttle_discriminator_normalizer
          discriminator = Rack::Attack.throttle_discriminator_normalizer.call(discriminator)
        end
        discriminator
      end

      def period_for(request)
        period.respond_to?(:call) ? period.call(request) : period
      end

      def limit_for(request)
        limit.respond_to?(:call) ? limit.call(request) : limit
      end

      def annotate_request_with_throttle_data(request, data)
        (request.env['rack.attack.throttle_data'] ||= {})[name] = data
      end

      def annotate_request_with_matched_data(request, data)
        request.env['rack.attack.matched']             = name
        request.env['rack.attack.match_discriminator'] = data[:discriminator]
        request.env['rack.attack.match_type']          = type
        request.env['rack.attack.match_data']          = data
      end
    end
  end
end
