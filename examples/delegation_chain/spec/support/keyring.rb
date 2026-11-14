# frozen_string_literal: true

require 'openssl'
require 'jwt'

module Support
  # Generates distinct RSA keys per actor so per-hop consent is meaningful.
  class Keyring
    attr_reader :outer

    def initialize
      @outer = OpenSSL::PKey::RSA.new(2048)
      @actors = {}
    end

    def key_for(actor)
      @actors[actor] ||= OpenSSL::PKey::RSA.new(2048)
    end

    def public_registry(actors)
      actors.each_with_object({}) { |actor, registry| registry[actor] = key_for(actor).public_key }
    end

    def outer_public
      @outer.public_key
    end
  end

  # Builds outer JWTs with nested `act`, optionally attaching signed consent tokens.
  class TokenFactory
    def initialize(keyring, issuer: 'idp.example')
      @keyring = keyring
      @issuer = issuer
    end

    def issue(sub:, aud:, actors:, evidence: true, act_override: nil)
      payload = {
        'iss' => @issuer,
        'sub' => sub,
        'aud' => aud,
        'iat' => Time.now.to_i,
        'exp' => Time.now.to_i + 300,
        'act' => act_override || build_act(actors, sub, evidence)
      }
      JWT.encode(payload, @keyring.outer, 'RS256')
    end

    private

    def build_act(actors, origin, evidence)
      actors.reverse.reduce(nil) do |inner, actor|
        index = actors.index(actor)
        previous = index.zero? ? origin : actors[index - 1]
        node = { 'sub' => actor }
        node['act_token'] = consent(actor, previous) if evidence
        node['act'] = inner if inner
        node
      end
    end

    def consent(actor, previous)
      JWT.encode(
        { 'iss' => actor, 'sub' => actor, 'act' => { 'sub' => previous }, 'exp' => Time.now.to_i + 300 },
        @keyring.key_for(actor),
        'RS256'
      )
    end
  end
end
