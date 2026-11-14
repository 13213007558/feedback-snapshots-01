# frozen_string_literal: true

require 'jwt'
require_relative 'keyring'

module Demo
  # Issues the sample tokens.
  #
  # The outer JWT is signed once by the gateway/IdP (RS256). Each optional
  # `act_token` inside the chain is a *separate* JWT signed by that actor's own
  # key, which is the only thing that can evidence the actor's own consent.
  class TokenFactory
    def initialize(keyring:, issuer: 'idp.example')
      @keyring = keyring
      @issuer = issuer
    end

    # @param sub [String] original subject
    # @param aud [String, Array<String>] final audience
    # @param actors [Array<String>] ordered delegation path after `sub`
    # @param include_evidence [Boolean] attach per-hop signed consent tokens
    # @param ttl [Integer] token lifetime in seconds
    def issue(sub:, aud:, actors:, include_evidence: true, ttl: 300)
      now = Time.now.to_i
      payload = {
        'iss' => @issuer,
        'sub' => sub,
        'aud' => aud,
        'iat' => now,
        'nbf' => now,
        'exp' => now + ttl,
        'act' => build_act(actors, sub, now, include_evidence)
      }
      JWT.encode(payload, @keyring.outer, 'RS256', kid: 'outer-rs256')
    end

    private

    # Builds the nested structure from the outermost actor inward. RFC 8693
    # reads deepest `act` as the most recent actor.
    def build_act(actors, origin, now, include_evidence)
      actors.reverse.reduce(nil) do |inner, actor|
        previous = predecessor_of(actors, actor, origin)
        node = { 'sub' => actor }
        node['act_token'] = consent_token(actor, previous, now) if include_evidence
        node['act'] = inner if inner
        node
      end
    end

    def predecessor_of(actors, actor, origin)
      index = actors.index(actor)
      index.zero? ? origin : actors[index - 1]
    end

    # Inner JWT: actor signs "I (sub) act on behalf of previous (act.sub)".
    def consent_token(actor, previous, now)
      payload = {
        'iss' => actor,
        'sub' => actor,
        'act' => { 'sub' => previous },
        'iat' => now,
        'exp' => now + 300
      }
      JWT.encode(payload, @keyring.key_for(actor), 'RS256', kid: "#{actor}-rs256")
    end
  end
end
