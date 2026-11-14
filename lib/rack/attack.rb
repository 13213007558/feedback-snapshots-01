# frozen_string_literal: true

require 'rack'
require 'forwardable'
require 'stringio'
require 'rack/attack/cache'
require 'rack/attack/configuration'
require 'rack/attack/path_normalizer'
require 'rack/attack/request'
require 'rack/attack/store_proxy/dalli_proxy'
require 'rack/attack/store_proxy/mem_cache_store_proxy'
require 'rack/attack/store_proxy/redis_proxy'
require 'rack/attack/store_proxy/redis_store_proxy'
require 'rack/attack/store_proxy/redis_cache_store_proxy'

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

    class << self
      attr_accessor :enabled, :notifier, :throttle_discriminator_normalizer
      attr_reader :configuration

      def instrument(request)
        if notifier
          event_type = request.env["rack.attack.match_type"]
          notifier.instrument("#{event_type}.rack_attack", request: request)

          # Deprecated: Keeping just for backwards compatibility
          notifier.instrument("rack.attack", request: request)
        end
      end

      # Instruments a hypothetical match from an observed (candidate) rule.
      # Uses a distinct event name and payload flag so that subscribers
      # reacting to enforced matches (e.g. penalty subscriptions) are not
      # triggered, and each event is explicitly marked as hypothetical.
      def instrument_observed(request)
        if notifier
          request.env["rack.attack.observed"] = true
          event_type = request.env["rack.attack.observed.match_type"]
          notifier.instrument("observed_#{event_type}.rack_attack", request: request, observed: true)
        end
      end

      def cache
        @cache ||= Cache.new
      end

      # Separate cache namespace for observed (candidate) rules, so that
      # their counters and virtual ban history never mix with enforced rules.
      def observed_cache
        @observed_cache ||= Cache.new.tap { |cache| cache.prefix = "rack::attack:observe" }
      end

      def clear!
        warn "[DEPRECATION] Rack::Attack.clear! is deprecated. Please use Rack::Attack.clear_configuration instead"
        @configuration.clear_configuration
      end

      def reset!
        cache.reset!
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
      else
        ensure_rewindable_input(env) if configuration.observing?

        response = enforced_response(request)

        # Candidate (observed) rules are always evaluated, even when an
        # enforced rule already rejected the request, so that they keep
        # receiving their attempt events. They never affect the response.
        observe_candidates(request)

        response || begin
          configuration.tracked?(request)
          @app.call(env)
        end
      end
    end

    private

    def enforced_response(request)
      if configuration.blocklisted?(request)
        # Deprecated: Keeping blocklisted_response for backwards compatibility
        if configuration.blocklisted_response
          configuration.blocklisted_response.call(request.env)
        else
          configuration.blocklisted_responder.call(request)
        end
      elsif configuration.throttled?(request)
        # Deprecated: Keeping throttled_response for backwards compatibility
        if configuration.throttled_response
          configuration.throttled_response.call(request.env)
        else
          configuration.throttled_responder.call(request)
        end
      end
    end

    def observe_candidates(request)
      rewind_body(request)
      configuration.observed?(request)
    ensure
      # Leave the input stream readable for the downstream app.
      rewind_body(request)
    end

    # Candidate rules must be able to read the same input stream as the
    # official rules and the downstream app, so make sure the stream can be
    # rewound between evaluations. Inputs that are not rewindable (against
    # the Rack spec) are buffered once, up front.
    def ensure_rewindable_input(env)
      input = env["rack.input"]
      return if input.nil? || input.respond_to?(:rewind)

      content = input.read
      input.close if input.respond_to?(:close)
      env["rack.input"] = StringIO.new(content.to_s)
    end

    def rewind_body(request)
      body = request.body
      body.rewind if body.respond_to?(:rewind)
    end
  end
end
