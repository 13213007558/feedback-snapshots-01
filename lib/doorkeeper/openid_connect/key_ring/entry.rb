# frozen_string_literal: true

module Doorkeeper
  module OpenidConnect
    class KeyRing
      # One configured key and the monotonic generation number it belongs to.
      # The JWK is built lazily: merely carrying a retired key must never force
      # it through `OpenSSL::PKey.read` on the ID-token signing hot path.
      class Entry
        attr_reader :generation, :raw

        def initialize(generation, raw, builder)
          @generation = generation
          @raw = raw
          @builder = builder
        end

        def jwk
          @jwk ||= @builder.call(raw)
        end

        def keypair
          jwk.keypair
        end

        def kid
          jwk.kid
        end

        def export
          jwk.export
        end
      end
    end
  end
end
