# frozen_string_literal: true

module Rack
  class Attack
    class Check
      attr_reader :name, :block, :type

      def initialize(name, options = {}, &block)
        @name = name
        @block = block
        @type = options.fetch(:type, nil)
        @observe = options.fetch(:observe, false)
      end

      def observe?
        @observe
      end

      def matched_by?(request)
        block.call(request).tap do |match|
          if match
            if observe?
              request.env["rack.attack.observed.matched"] = name
              request.env["rack.attack.observed.match_type"] = type
              Rack::Attack.instrument_observed(request)
            else
              request.env["rack.attack.matched"] = name
              request.env["rack.attack.match_type"] = type
              Rack::Attack.instrument(request)
            end
          end
        end
      end
    end
  end
end
