# frozen_string_literal: true

module Rack
  class Attack
    # A RuleSet is an immutable, validated snapshot of a Configuration:
    # the rule callbacks (safelists, blocklists, throttles, tracks), the
    # responders and the counter namespace all belong to exactly one
    # version. A request uses the rule set that was current when it entered
    # the middleware, from the first safelist check down to the hit event
    # it emits, so a request never mixes rules from two versions.
    class RuleSet
      attr_reader :version, :namespace, :configuration

      # The implicit rule set backed by the global Rack::Attack.configuration.
      # It carries no version and no counter namespace, so legacy cache keys,
      # event payloads and behavior are unchanged.
      def self.legacy(configuration)
        new(version: nil, namespace: nil, configuration: configuration)
      end

      def self.build(version:, namespace: nil, configuration: nil)
        config = configuration || Configuration.new
        yield config if block_given?
        new(version: version, namespace: namespace, configuration: config).tap(&:validate!)
      end

      def initialize(version:, namespace: nil, configuration:)
        @version = version&.to_s
        @namespace = namespace&.to_s
        @namespace = @version if @namespace.nil? && !@version.nil?
        @configuration = configuration
      end

      def legacy?
        @version.nil?
      end

      def validate!
        errors = []
        errors << "version must be present" if version.nil? || version.empty?
        validate_responders(errors)
        validate_checks(errors)
        validate_throttles(errors)

        raise InvalidRuleSetError, errors unless errors.empty?

        self
      end

      # A published rule set is immutable: its rule collections can no
      # longer be modified. The legacy rule set is never frozen, so the
      # global configuration stays mutable.
      def freeze
        configuration.safelists.freeze
        configuration.blocklists.freeze
        configuration.throttles.freeze
        configuration.tracks.freeze
        configuration.anonymous_safelists.freeze
        configuration.anonymous_blocklists.freeze
        super
      end

      # Stamps the request env so every later stage of this request (rule
      # callbacks, throttle counters, responders, instrumentation) stays
      # pinned to this version even if another version is published while
      # the request is in flight.
      def apply(env)
        env["rack.attack.rule_set"] = self
        return if legacy?

        env["rack.attack.rule_set_version"] = version
        env["rack.attack.rule_set_namespace"] = namespace
      end

      private

      def validate_responders(errors)
        responders = {
          "throttled_responder" => configuration.throttled_responder,
          "blocklisted_responder" => configuration.blocklisted_responder,
          "throttled_response" => configuration.throttled_response,
          "blocklisted_response" => configuration.blocklisted_response
        }

        responders.each do |name, responder|
          next if responder.nil? || responder.respond_to?(:call)

          errors << "#{name} must respond to #call"
        end
      end

      def validate_checks(errors)
        checks = []
        configuration.safelists.each { |name, check| checks << ["safelist", name, check] }
        configuration.blocklists.each { |name, check| checks << ["blocklist", name, check] }
        configuration.anonymous_safelists.each { |check| checks << ["safelist", nil, check] }
        configuration.anonymous_blocklists.each { |check| checks << ["blocklist", nil, check] }
        configuration.tracks.each { |name, track| checks << ["track", name, track.filter] }

        checks.each do |kind, name, check|
          next unless check.block.nil?

          label = name ? "#{kind} #{name.inspect}" : "anonymous #{kind}"
          errors << "#{label} has no block"
        end
      end

      def validate_throttles(errors)
        configuration.throttles.each do |name, throttle|
          errors << "throttle #{name.inspect} has no block" if throttle.block.nil?
          errors << "throttle #{name.inspect} limit must be callable or a positive number" unless positive_or_callable?(throttle.limit)
          errors << "throttle #{name.inspect} period must be callable or a positive number" unless positive_or_callable?(throttle.period)
        end
      end

      def positive_or_callable?(value)
        value.respond_to?(:call) || (value.respond_to?(:to_i) && value.to_i.positive?)
      end
    end

    # Returned by Rack::Attack.rollback. States which version was replaced,
    # which version is now active and which fail2ban/allow2ban bans remain
    # in effect (ban state lives in the shared cache and survives switches).
    class RollbackReport
      attr_reader :from_version, :to_version, :active_bans

      def initialize(from_version:, to_version:, active_bans:)
        @from_version = from_version
        @to_version = to_version
        @active_bans = active_bans
      end

      # false when the cache store cannot enumerate keys and no ban was
      # observed in this process; the report then cannot list active bans.
      def bans_enumerable?
        !active_bans.nil?
      end

      def summary
        "Rolled back from #{from_version || 'legacy'} to #{to_version || 'legacy'}; #{ban_summary}"
      end

      private

      def ban_summary
        if active_bans.nil?
          "active bans not enumerable from this store; fail2ban/allow2ban bans persist in the shared cache"
        elsif active_bans.empty?
          "no bans currently in effect"
        else
          bans = active_bans.map { |ban| "#{ban[:filter]}:#{ban[:discriminator]}" }.join(", ")
          "bans still in effect: #{bans}"
        end
      end
    end
  end
end
