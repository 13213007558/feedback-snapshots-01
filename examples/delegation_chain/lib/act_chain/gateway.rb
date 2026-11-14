# frozen_string_literal: true

require 'jwt'
require_relative 'verifier'
require_relative 'result'

module ActChain
  # Thin integration wrapper: verify the outer JWT exactly as ruby-jwt already
  # does, then apply the delegation-chain policy. The two stages stay separate so
  # a signature failure never reaches chain logic, and chain logic never re-trusts
  # the payload.
  class Gateway
    # @param outer_key [Object] key accepted by JWT.decode for the outer signature.
    # @param verifier [ActChain::Verifier]
    # @param decode_options [Hash] extra JWT.decode options (algorithms, iss, aud, ...).
    def initialize(outer_key:, verifier:, decode_options: {})
      @outer_key = outer_key
      @verifier = verifier
      @decode_options = decode_options
    end

    # @return [ActChain::Result]
    # @raise [JWT::Error] if the outer signature or standard claims are invalid.
    def authenticate(token)
      payload, _header = JWT.decode(token, @outer_key, true, @decode_options)
      @verifier.inspect(payload, final_audience: payload['aud'])
    end

    # Convenience predicate for callers that only need a yes/no on topology.
    def authenticate?(token)
      authenticate(token).valid?
    rescue JWT::Error
      false
    end
  end

  # The hand-off point to business authorization. Validation never grants a
  # permission; it only returns facts the policy engine can reason over.
  class AuthorizationDecision
    # @param result [ActChain::Result]
    # @param capabilities [Hash{String => Array<Symbol>}] subject -> permissions granted by an
    #   external authority (IAM, ACL, ...). Delegation never expands these.
    def initialize(result, capabilities:)
      @result = result
      @capabilities = capabilities
    end

    # A permission is granted only when the chain is valid AND the *original*
    # subject holds it. Intermediate actors cannot add rights the origin lacks.
    def permit?(permission)
      return false unless @result.valid?

      Array(@capabilities[@result.original_subject]).include?(permission.to_sym)
    end

    # Whether the caller may treat the chain as end-to-end consented. Most
    # sensitive operations should demand this, not just `valid?`.
    def fully_consented?
      @result.fully_consented?
    end

    def reason
      return "rejected: #{@result.policy_errors.map(&:message).join('; ')}" unless @result.valid?
      return 'granted with verified per-hop consent' if fully_consented?

      'topology valid, but one or more hops lack verifiable consent'
    end
  end
end
