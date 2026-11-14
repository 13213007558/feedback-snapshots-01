# frozen_string_literal: true

require "ipaddr"

module Rack
  class Attack
    class Configuration
      DEFAULT_BLOCKLISTED_RESPONDER = lambda { |_req| [403, { 'content-type' => 'text/plain' }, ["Forbidden\n"]] }

      DEFAULT_THROTTLED_RESPONDER = lambda do |req|
        if Rack::Attack.configuration.throttled_response_retry_after_header
          match_data = req.env['rack.attack.match_data']
          now = match_data[:epoch_time]
          retry_after = match_data[:period] - (now % match_data[:period])

          [429, { 'content-type' => 'text/plain', 'retry-after' => retry_after.to_s }, ["Retry later\n"]]
        else
          [429, { 'content-type' => 'text/plain' }, ["Retry later\n"]]
        end
      end

      attr_reader :safelists, :blocklists, :throttles, :tracks, :anonymous_blocklists, :anonymous_safelists
      attr_accessor :blocklisted_responder, :throttled_responder, :throttled_response_retry_after_header,
        :meter_safelisted_requests

      attr_reader :blocklisted_response, :throttled_response # Keeping these for backwards compatibility

      def blocklisted_response=(responder)
        warn "[DEPRECATION] Rack::Attack.blocklisted_response is deprecated. "\
          "Please use Rack::Attack.blocklisted_responder instead."
        @blocklisted_response = responder
      end

      def throttled_response=(responder)
        warn "[DEPRECATION] Rack::Attack.throttled_response is deprecated. "\
          "Please use Rack::Attack.throttled_responder instead"
        @throttled_response = responder
      end

      def initialize
        set_defaults
      end

      def safelist(name = nil, &block)
        safelist = Safelist.new(name, &block)

        if name
          @safelists[name] = safelist
        else
          @anonymous_safelists << safelist
        end
      end

      def blocklist(name = nil, &block)
        blocklist = Blocklist.new(name, &block)

        if name
          @blocklists[name] = blocklist
        else
          @anonymous_blocklists << blocklist
        end
      end

      def blocklist_ip(ip_address)
        @anonymous_blocklists << Blocklist.new do |request|
          request.ip && !request.ip.empty? && IPAddr.new(ip_address).include?(IPAddr.new(request.ip))
        end
      end

      def safelist_ip(ip_address)
        @anonymous_safelists << Safelist.new do |request|
          request.ip && !request.ip.empty? && IPAddr.new(ip_address).include?(IPAddr.new(request.ip))
        end
      end

      def throttle(name, options, &block)
        @throttles[name] = Throttle.new(name, options, &block)
      end

      def track(name, options = {}, &block)
        @tracks[name] = Track.new(name, options, &block)
      end

      # Decision contract: meters every applicable rule for the request
      # (counting each throttle at most once, even when another rule already
      # matched), then derives a single enforcement decision with a stable
      # priority: safelist, then blocklist, then throttle; within a category
      # the first defined rule wins.
      #
      # Annotates the request env with the winning rule (same keys as the
      # legacy flow) plus "rack.attack.matches" listing every matched rule,
      # and instruments the final decision exactly once.
      #
      # Returns :safelist, :blocklist, :throttle or nil (request allowed).
      def evaluate(request)
        matched_safelists  = all_safelists.select { |safelist| safelist.match(request) }
        matched_blocklists = all_blocklists.select { |blocklist| blocklist.match(request) }

        exceeded_throttles = []
        if matched_safelists.empty? || meter_safelisted_requests
          exceeded_throttles = @throttles.each_value.select { |throttle| throttle.meter(request) }
        end

        record_matches(request, matched_safelists, matched_blocklists, exceeded_throttles)

        if matched_safelists.any?
          decide(request, :safelist, matched_safelists.first)
        elsif matched_blocklists.any?
          decide(request, :blocklist, matched_blocklists.first)
        elsif exceeded_throttles.any?
          decide(request, :throttle, exceeded_throttles.first)
        else
          tracked?(request)
          nil
        end
      end

      def safelisted?(request)
        @anonymous_safelists.any? { |safelist| safelist.matched_by?(request) } ||
          @safelists.any? { |_name, safelist| safelist.matched_by?(request) }
      end

      def blocklisted?(request)
        @anonymous_blocklists.any? { |blocklist| blocklist.matched_by?(request) } ||
          @blocklists.any? { |_name, blocklist| blocklist.matched_by?(request) }
      end

      def throttled?(request)
        @throttles.any? do |_name, throttle|
          throttle.matched_by?(request)
        end
      end

      def tracked?(request)
        @tracks.each_value do |track|
          track.matched_by?(request)
        end
      end

      def clear_configuration
        set_defaults
      end

      private

      def all_safelists
        @anonymous_safelists + @safelists.values
      end

      def all_blocklists
        @anonymous_blocklists + @blocklists.values
      end

      def record_matches(request, safelists, blocklists, throttles)
        matches = (safelists + blocklists + throttles).map do |rule|
          { name: rule.name, type: rule.type }
        end

        request.env["rack.attack.matches"] = matches unless matches.empty?
      end

      def decide(request, decision, rule)
        request.env["rack.attack.matched"] = rule.name
        request.env["rack.attack.match_type"] = rule.type

        if decision == :throttle
          data = request.env["rack.attack.throttle_data"][rule.name]
          request.env["rack.attack.match_discriminator"] = data[:discriminator]
          request.env["rack.attack.match_data"] = data
        end

        Rack::Attack.instrument(request)

        decision
      end

      def set_defaults
        @safelists = {}
        @blocklists = {}
        @throttles = {}
        @tracks = {}
        @anonymous_blocklists = []
        @anonymous_safelists = []
        @throttled_response_retry_after_header = false
        @meter_safelisted_requests = true

        @blocklisted_responder = DEFAULT_BLOCKLISTED_RESPONDER
        @throttled_responder = DEFAULT_THROTTLED_RESPONDER

        # Deprecated: Keeping these for backwards compatibility
        @blocklisted_response = nil
        @throttled_response = nil
      end
    end
  end
end
