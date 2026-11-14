# frozen_string_literal: true

module Rack
  class Attack
    class Blocklist < Check
      def initialize(name = nil, options = {}, &block)
        super
        @type = :blocklist
      end
    end
  end
end
