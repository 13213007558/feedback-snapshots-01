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

require 'rack/attack/railtie' if defined?(::Rails)

module Rack
  class Attack
    class Error < StandardError; end

    class MisconfiguredStoreError < Error; end

    class MissingStoreError < Error; end

    class IncompatibleStoreError < Error; end

    class InvalidRuleSetError < Error
      attr_reader :errors

      def initialize(errors)
        @errors = errors
        super("Invalid rule set: #{errors.join(', ')}")
      end
    end

    autoload :Check,                'rack/attack/check'
    autoload :Throttle,             'rack/attack/throttle'
    autoload :Safelist,             'rack/attack/safelist'
    autoload :Blocklist,            'rack/attack/blocklist'
    autoload :Track,                'rack/attack/track'
    autoload :Fail2Ban,             'rack/attack/fail2ban'
    autoload :Allow2Ban,            'rack/attack/allow2ban'
    autoload :RuleSet,              'rack/attack/rule_set'
    autoload :RollbackReport,       'rack/attack/rule_set'

    class << self
      attr_accessor :enabled, :notifier, :throttle_discriminator_normalizer
      attr_reader :configuration

      def instrument(request)
        if notifier
          event_type = request.env["rack.attack.match_type"]
          payload = { request: request }

          # Requests served by a published rule set report their version, so
          # a hit event can always be correlated with the rules that fired.
          version = request.env["rack.attack.rule_set_version"]
          payload[:rule_set_version] = version if version

          notifier.instrument("#{event_type}.rack_attack", **payload)

          # Deprecated: Keeping just for backwards compatibility
          notifier.instrument("rack.attack", **payload)
        end
      end

      def cache
        @cache ||= Cache.new
      end

      def clear!
        warn "[DEPRECATION] Rack::Attack.clear! is deprecated. Please use Rack::Attack.clear_configuration instead"
        clear_configuration
      end

      def reset!
        cache.reset!
      end

      # The rule set applied to incoming requests. Defaults to an implicit
      # "legacy" rule set backed by the global configuration, so existing
      # apps that never publish see no behavior change.
      def current_rule_set
        @current_rule_set ||= RuleSet.legacy(configuration)
      end

      # Previously active rule sets, oldest first. A rule set stays
      # reachable here (and thus cannot be reclaimed) while it is a
      # rollback target.
      def rule_set_history
        @rule_set_history ||= []
      end

      def build_rule_set(version:, namespace: nil, &block)
        RuleSet.build(version: version, namespace: namespace, &block)
      end

      # Atomically swaps the active rule set. Validation happens before the
      # swap and the request path never takes the publish mutex, so
      # publishing never blocks in-flight requests; an invalid rule set
      # raises and leaves the current version untouched.
      def publish(rule_set)
        rule_set.validate!
        rule_set.freeze

        publish_mutex.synchronize do
          rule_set_history.push(current_rule_set)
          @current_rule_set = rule_set
        end

        rule_set
      end

      # Restores the previously published rule set and reports which
      # fail2ban/allow2ban bans remain in effect. Bans live in the shared
      # cache under unversioned keys, so they survive the switch and are
      # enforced again as soon as the restored version consults them.
      def rollback
        from = publish_mutex.synchronize do
          raise Error, "No previous rule set to roll back to" if rule_set_history.empty?

          current = @current_rule_set
          @current_rule_set = rule_set_history.pop
          current
        end

        RollbackReport.new(
          from_version: from&.version,
          to_version: current_rule_set.version,
          active_bans: active_bans
        )
      end

      # Best-effort list of bans currently in effect, as
      # [{ filter: "allow2ban"|"fail2ban", discriminator: "..." }]. Reads
      # them from the store when it can enumerate keys, otherwise falls
      # back to bans observed by this process. Returns nil when neither is
      # available.
      def active_bans
        bans_from_store || bans_from_journal
      end

      # Records a ban written through Fail2Ban/Allow2Ban so rollback can
      # report it even when the store cannot enumerate keys.
      def note_ban(filter, discriminator, bantime)
        ban_journal_mutex.synchronize do
          ban_journal.reject! { |ban| ban[:filter] == filter && ban[:discriminator] == discriminator }
          ban_journal << { filter: filter, discriminator: discriminator, expires_at: Time.now.to_i + bantime.to_i }
        end
      end

      def reset_ban(filter, discriminator)
        ban_journal_mutex.synchronize do
          ban_journal.reject! { |ban| ban[:filter] == filter && ban[:discriminator] == discriminator }
        end
      end

      def clear_configuration
        configuration.clear_configuration

        publish_mutex.synchronize do
          @current_rule_set = nil
          @rule_set_history = []
          ban_journal_mutex.synchronize { ban_journal.clear }
        end
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
        :safelists,
        :blocklists,
        :throttles,
        :tracks
      )

      private

      BAN_KEY_PATTERN = /:(allow2ban|fail2ban):ban:(.+)\z/

      def publish_mutex
        @publish_mutex ||= Mutex.new
      end

      def ban_journal
        @ban_journal ||= []
      end

      def ban_journal_mutex
        @ban_journal_mutex ||= Mutex.new
      end

      def bans_from_store
        store = cache.store
        return nil unless store && store.respond_to?(:keys)

        store.keys.filter_map do |key|
          match = BAN_KEY_PATTERN.match(key.to_s)
          { filter: match[1], discriminator: match[2] } if match
        end
      rescue StandardError
        nil
      end

      def bans_from_journal
        now = Time.now.to_i

        ban_journal_mutex.synchronize do
          ban_journal.reject! { |ban| ban[:expires_at] <= now }
          ban_journal.map { |ban| ban.slice(:filter, :discriminator) }
        end
      end
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

      # Pin this request to the rule set that is current right now. Every
      # check, counter, responder and hit event below uses this version,
      # even if another version is published while the request runs.
      rule_set = self.class.current_rule_set
      rule_set.apply(env)
      configuration = rule_set.configuration

      if configuration.safelisted?(request)
        @app.call(env)
      elsif configuration.blocklisted?(request)
        # Deprecated: Keeping blocklisted_response for backwards compatibility
        if configuration.blocklisted_response
          configuration.blocklisted_response.call(env)
        else
          configuration.blocklisted_responder.call(request)
        end
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
