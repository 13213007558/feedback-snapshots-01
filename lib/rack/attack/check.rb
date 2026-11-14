# frozen_string_literal: true

module Rack
  class Attack
    class Check
      attr_reader :name, :block, :type

      def initialize(name, options = {}, &block)
        @name = name
        @block = block
        @type = options.fetch(:type, nil)
      end

      # Metering contract: evaluates the rule for the request without any
      # decision side effects (no env annotation, no instrumentation).
      # The result is memoized so the rule's block runs at most once per request.
      def match(request)
        matches = (request.env["rack.attack.check_matches"] ||= {})
        key = name || object_id

        return matches[key] if matches.key?(key)

        matches[key] = !!block.call(request)
      end

      # Legacy contract: evaluates the rule and, when matched, annotates the
      # request and instruments the match. Kept for backwards compatibility;
      # new code should rely on Configuration#evaluate instead.
      def matched_by?(request)
        match(request).tap do |matched|
          if matched
            request.env["rack.attack.matched"] = name
            request.env["rack.attack.match_type"] = type
            Rack::Attack.instrument(request)
          end
        end
      end
    end
  end
end
