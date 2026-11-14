# frozen_string_literal: true

require 'openssl'
require 'jwt'

module Demo
  # Builds and holds the local signing keys used by the three samples.
  #
  # In production these would come from a KMS/JWKS endpoint. Here they are
  # generated in-memory so the demo is self-contained, while still keeping a
  # distinct key per participant (which is what makes per-hop consent meaningful).
  class Keyring
    def self.build
      new
    end

    def initialize
      @outer = OpenSSL::PKey::RSA.new(2048)
      @actor_keys = {}
    end

    attr_reader :outer

    def key_for(actor)
      @actor_keys[actor] ||= OpenSSL::PKey::RSA.new(2048)
    end

    # Only public keys are ever handed to verification.
    def verification_registry(actors)
      actors.each_with_object({}) { |actor, registry| registry[actor] = key_for(actor).public_key }
    end

    def outer_public
      @outer.public_key
    end
  end
end
