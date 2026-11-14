# frozen_string_literal: true

module JWT
  module Policy
    # Purpose-scoped entry point for turning an encoded JWT into a usable
    # identity. A verifier is configured once, on the server, with one
    # {VerificationPolicy} per purpose. The application chooses the purpose for
    # each verification call; the token itself can never select a policy or a
    # key source.
    #
    # Verification is all-or-nothing: a {VerifiedIdentity} is returned only when
    # the issuer, algorithm, typ, audience, required claims, key and signature
    # all pass.
    #
    # @example
    #   verifier = JWT::Policy::IdentityVerifier.new do |register|
    #     register.policy(
    #       purpose: :login,
    #       issuers: 'https://issuer.example',
    #       algorithms: 'RS256',
    #       typ: 'login+jwt',
    #       audience: 'web-app',
    #       required_claims: %w[sub nonce],
    #       jwks: ->(options) { fetch_jwks }
    #     )
    #   end
    #
    #   identity = verifier.verify(token, purpose: :login)
    class IdentityVerifier
      # @yieldparam register [Builder] the policy builder.
      def initialize
        @registry = Registry.new
        yield(Builder.new(@registry)) if block_given?
      end

      # Registers an additional policy after construction.
      #
      # @param attributes [Hash] the policy attributes (see {VerificationPolicy#initialize}).
      # @return [void]
      def policy(**attributes)
        @registry.register(VerificationPolicy.new(**attributes))
      end

      # @return [Array<VerificationPolicy>] the registered policies.
      def policies
        @registry.policies
      end

      # Verifies a token against the policy registered for the given purpose.
      #
      # @param jwt [String] the encoded JWT.
      # @param purpose [Symbol, String] the server-chosen purpose to verify for.
      # @raise [JWT::Error] if any policy check, key lookup or signature check fails.
      # @return [VerifiedIdentity] the verified identity.
      def verify(jwt, purpose:)
        policy = @registry.fetch(purpose)
        token  = EncodedToken.new(jwt)

        # Everything that does not need the key is checked first, using only
        # the server policy. In particular the issuer gate runs before the key
        # loader is ever touched, so a token from an untrusted issuer cannot
        # trigger an external key fetch.
        verify_token_structure!(token)
        verify_header_constraints!(token, policy)
        verify_payload_claims!(token, policy)
        verify_signature!(token, policy, resolve_key(token, policy))

        build_identity(purpose, policy, token)
      end

      def build_identity(purpose, policy, token)
        VerifiedIdentity.new(purpose: purpose,
                             payload: token.unverified_payload,
                             header: token.header,
                             policy: policy)
      end

      # Predicate form of {#verify}.
      #
      # @return [Boolean] true when the token satisfies the purpose's policy.
      def valid?(jwt, purpose:)
        verify(jwt, purpose: purpose)
        true
      rescue JWT::Error
        false
      end

      private

      def verify_token_structure!(token)
        raise JWT::MalformedTokenError, 'Not enough or too many segments' unless token.jwt.count('.') == 2

        token.header
        token.unverified_payload
      end

      def verify_header_constraints!(token, policy)
        policy.reject_remote_key_headers!(token.header)
        verify_algorithm!(token, policy)
        TypVerifier.new(expected_types: policy.types).verify!(header: token.header)
      end

      def verify_algorithm!(token, policy)
        alg = token.header['alg']
        raise JWT::IncorrectAlgorithm, 'Token is missing alg header' unless alg
        return if policy.algorithms.include?(alg)

        raise JWT::IncorrectAlgorithm,
              "Expected one of #{policy.algorithms}, received #{alg}"
      end

      def verify_payload_claims!(token, policy)
        payload = token.unverified_payload
        context = Claims::VerificationContext.new(payload: payload)

        Claims::Issuer.new(issuers: policy.issuers).verify!(context: context)
        Claims::Audience.new(expected_audience: policy.audiences).verify!(context: context)
        verify_required_claims!(policy, context)
        verify_time_claims!(context)
      end

      def verify_required_claims!(policy, context)
        return if policy.required_claims.empty?

        Claims::Required.new(required_claims: policy.required_claims).verify!(context: context)
      end

      def verify_time_claims!(context)
        Claims::Expiration.new(leeway: 0).verify!(context: context)
        Claims::NotBefore.new(leeway: 0).verify!(context: context)
      end

      def resolve_key(token, policy)
        if policy.jwks?
          JWK::KeyFinder.new(**policy.jwk_options).call(token)
        else
          policy.key
        end
      end

      def verify_signature!(token, policy, key)
        raise JWT::SignatureError, 'No verification key available' unless key

        token.verify_signature!(algorithm: policy.algorithms, key: key)
      end

      # Small block-facing adapter so policies read naturally at the call site.
      class Builder
        def initialize(registry)
          @registry = registry
        end

        # @param attributes [Hash] the policy attributes.
        # @return [void]
        def policy(**attributes)
          @registry.register(VerificationPolicy.new(**attributes))
        end
      end
    end
  end
end
