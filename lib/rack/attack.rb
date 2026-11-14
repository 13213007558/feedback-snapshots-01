# frozen_string_literal: true

require 'rack'
require 'forwardable'
require 'rack/attack/cache'
require 'rack/attack/configuration'
require 'rack/attack/path_normalizer'
require 'rack/attack/request'
require 'rack/attack/store_proxy/dalli_proxy'
require 'rack/attack/store_proxy/mem_cache_store_proxy'
require 'rack/attack/store_proxy/redis_proxy'
require 'rack/attack/store_proxy/redis_store_proxy'
require 'rack/attack/store_proxy/redis_cache_store_proxy'
require 'rack/attack/risk/pool'
require 'rack/attack/risk/scorer'
require 'rack/attack/risk/budget'

require 'rack/attack/railtie' if defined?(::Rails)

module Rack
  class Attack
    class Error < StandardError; end

    class MisconfiguredStoreError < Error; end

    class MissingStoreError < Error; end

    class IncompatibleStoreError < Error; end

    autoload :Check,                'rack/attack/check'
    autoload :Throttle,             'rack/attack/throttle'
    autoload :Safelist,             'rack/attack/safelist'
    autoload :Blocklist,            'rack/attack/blocklist'
    autoload :Track,                'rack/attack/track'
    autoload :Fail2Ban,             'rack/attack/fail2ban'
    autoload :Allow2Ban,            'rack/attack/allow2ban'
    autoload :RiskCheck,            'rack/attack/risk_check'

    class << self
      attr_accessor :enabled, :notifier, :throttle_discriminator_normalizer,
                    :risk_budget, :risk_pool_size, :risk_queue_capacity
      attr_reader :configuration

      def instrument(request)
        if notifier
          event_type = request.env["rack.attack.match_type"]
          notifier.instrument("#{event_type}.rack_attack", request: request)

          # Deprecated: Keeping just for backwards compatibility
          notifier.instrument("rack.attack", request: request)
        end
      end

      def cache
        @cache ||= Cache.new
      end

      def clear!
        warn "[DEPRECATION] Rack::Attack.clear! is deprecated. Please use Rack::Attack.clear_configuration instead"
        @configuration.clear_configuration
      end

      def reset!
        cache.reset!
      end

      # Shared bounded pool for risk scorer calls. Lazily created from
      # risk_pool_size / risk_queue_capacity; change those before first use
      # or call reset_risk_pool! afterwards.
      def risk_pool
        @risk_pool ||= Risk::Pool.new(size: risk_pool_size, queue_capacity: risk_queue_capacity)
      end

      def reset_risk_pool!
        @risk_pool&.shutdown
        @risk_pool = nil
      end

      # Exposes the risk policy actually adopted for a blocked request as a
      # response header, so downstream logs and clients see how the decision
      # was reached (e.g. scored_deny vs deny_on_unknown).
      def annotate_risk_policy(response, env)
        risk = env["rack.attack.risk"]
        return response unless risk

        status, headers, body = response
        [status, headers.merge("x-rack-attack-risk-policy" => risk[:policy].to_s), body]
      end

      extend Forwardable
      def_delegators(
        :@configuration,
        :safelist,
        :blocklist,
        :blocklist_ip,
        :safelist_ip,
        :throttle,
        :track,
        :risk_blocklist,
        :throttled_responder,
        :throttled_responder=,
        :blocklisted_responder,
        :blocklisted_responder=,
        :blocklisted_response,
        :blocklisted_response=,
        :throttled_response,
        :throttled_response=,
        :throttled_response_retry_after_header,
        :throttled_response_retry_after_header=,
        :clear_configuration,
        :safelists,
        :blocklists,
        :throttles,
        :tracks
      )
    end

    # Set defaults
    @enabled = true
    @notifier = ActiveSupport::Notifications if defined?(ActiveSupport::Notifications)
    @throttle_discriminator_normalizer = lambda do |discriminator|
      discriminator.to_s.strip.downcase
    end
    @risk_budget = 0.25
    @risk_pool_size = 2
    @risk_queue_capacity = 64
    @configuration = Configuration.new

    attr_reader :configuration

    def initialize(app)
      @app = app
      @configuration = self.class.configuration
    end

    def call(env)
      return @app.call(env) if !self.class.enabled || env["rack.attack.called"]

      env["rack.attack.called"] = true
      env['PATH_INFO'] = PathNormalizer.normalize_path(env['PATH_INFO'])
      request = Rack::Attack::Request.new(env)

      if configuration.safelisted?(request)
        @app.call(env)
      elsif configuration.blocklisted?(request)
        # Deprecated: Keeping blocklisted_response for backwards compatibility
        response =
          if configuration.blocklisted_response
            configuration.blocklisted_response.call(env)
          else
            configuration.blocklisted_responder.call(request)
          end
        self.class.annotate_risk_policy(response, env)
      elsif configuration.throttled?(request)
        # Deprecated: Keeping throttled_response for backwards compatibility
        if configuration.throttled_response
          configuration.throttled_response.call(env)
        else
          configuration.throttled_responder.call(request)
        end
      else
        configuration.tracked?(request)
        @app.call(env)
      end
    end
  end
end
