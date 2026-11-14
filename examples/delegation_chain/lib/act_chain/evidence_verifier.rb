# frozen_string_literal: true

require 'jwt'

module ActChain
  # Verifies the optional per-hop consent token carried as `act_token`.
  #
  # The outer signature only proves that the outermost issuer signed the whole
  # blob. A participant's *agreement* to delegate is a separate claim that must
  # be backed by a signature from that participant. Here that means each actor
  # can publish an inner JWT, signed with its own key, asserting it acts on
  # behalf of the previous subject.
  #
  # Keys are resolved from an explicit registry of trusted keys only. There is
  # no fallback that treats an unknown key as valid.
  class EvidenceVerifier
    # @param keys [Hash{String => OpenSSL::PKey, String}] actor subject -> verification key.
    # @param algorithms [Array<String>] accepted signature algorithms.
    def initialize(keys:, algorithms: %w[RS256])
      @keys = keys.transform_keys(&:to_s)
      @algorithms = algorithms
    end

    # @return [Hash] `:status` one of :none / :verified / :unverified, plus
    #   `:reason`, `:claims` and `:header` for diagnostics and audit.
    def verify(step, expected_actor)
      return absent unless step.evidence?

      key = @keys[expected_actor]
      return unverified("no registered key for actor '#{expected_actor}'", step) unless key

      claims, header = decode(step.evidence_token, key)
      confirm_consent!(claims, expected_actor)
      { status: :verified, reason: nil, claims: claims, header: header }
    rescue JWT::Error => e
      unverified(e.message, step)
    end

    private

    def absent
      { status: :none, reason: 'no act_token evidence present', claims: nil, header: nil }
    end

    def unverified(reason, step)
      { status: :unverified, reason: reason, claims: nil, header: nil, raw: step.raw }
    end

    def decode(token, key)
      JWT.decode(token, key, true, algorithms: @algorithms, required_claims: %w[sub act])
    end

    # The inner token must say the signing actor acts for the immediately
    # preceding subject; a valid signature for the wrong content proves nothing.
    def confirm_consent!(claims, expected_actor)
      raise JWT::DecodeError, "evidence sub '#{claims['sub']}' != actor '#{expected_actor}'" unless claims['sub'].to_s == expected_actor.to_s
      raise JWT::DecodeError, 'evidence is missing the delegated act.sub' unless claims['act'].is_a?(Hash) && claims['act']['sub']
    end
  end
end
