# frozen_string_literal: true

module JWT
  module JWK
    # Selects the single JWK that verifies a token when a JWKS may contain
    # several keys sharing the same key id.
    #
    # Unlike {KeyFinder}, which returns the first matching key, the selector
    # filters every candidate by the caller's algorithm and key usage
    # constraints and verifies the token against each of them. The outcome is
    # independent of the order of the keys in the JWKS:
    #
    # * candidates sharing the same public key material are treated as one,
    # * exactly one distinct candidate verifying the token is accepted,
    # * several distinct candidates verifying the token raise
    #   {JWT::AmbiguousKeyError},
    # * more candidates than the configured limit raise
    #   {JWT::TooManyCandidateKeys}, a configuration error reported before any
    #   signature is tried.
    class KeySelector
      # Default upper bound for the number of compatible candidates.
      DEFAULT_MAX_CANDIDATES = 5

      # Initializes a new KeySelector instance.
      # @param options [Hash] the options to create a KeySelector with
      # @option options [Proc, JWT::JWK::Set] :jwks the jwks or a loader proc
      # @option options [Array<String, JWT::JWA::SigningAlgorithm>] :algorithms
      #   the algorithms accepted by the caller, defaults to no algorithm
      #   constraint
      # @option options [Boolean] :allow_nil_kid whether to allow a nil kid
      # @option options [Array<Symbol>] :key_fields the header fields used for
      #   key matching, defaults to [:kid]
      # @option options [Integer] :max_candidates maximum number of compatible
      #   candidates that may be tried, defaults to
      #   {DEFAULT_MAX_CANDIDATES}
      def initialize(options)
        @allow_nil_kid  = options[:allow_nil_kid]
        @key_fields     = options[:key_fields] || %i[kid]
        @max_candidates = options[:max_candidates] || DEFAULT_MAX_CANDIDATES
        @constraints    = KeyConstraints.new(Array(options[:algorithms]).map { |alg| JWA.resolve(alg) })

        jwks_or_loader = options[:jwks]
        @jwks_loader = if jwks_or_loader.respond_to?(:call)
                         jwks_or_loader
                       else
                         ->(_options) { jwks_or_loader }
                       end
      end

      # Resolves the key that verifies the given token.
      # @param token [JWT::EncodedToken] the token
      # @return [Object] the verification key of the selected JWK
      # @raise [JWT::SignatureError] when no key id is present and nil kids are
      #   not allowed or no candidate is usable
      # @raise [JWT::TooManyCandidateKeys] when the candidate limit is exceeded
      # @raise [JWT::AmbiguousKeyError] when several distinct candidates verify
      #   the token
      def call(token)
        key_field, kid = key_identifier(token)
        validate_kid(kid, key_field)

        candidates = resolve_candidates(kid, key_field)
        candidates.select! { |jwk| @constraints.allowed?(jwk) }

        raise ::JWT::VerificationKeyError, "No compatible public key for kid #{kid}" if candidates.empty?

        enforce_candidate_limit!(candidates, kid)

        verified = distinct_candidates(candidates).select { |jwk| verifies?(jwk, token) }

        raise ::JWT::AmbiguousKeyError, "#{verified.size} distinct keys matching kid #{kid} verify the token" if verified.size > 1
        raise ::JWT::SignatureError, "No key matching kid #{kid} verifies the token" if verified.empty?

        verified.first.verify_key
      end

      private

      def key_identifier(token)
        @key_fields.each do |key_field|
          field_value = token.header[key_field.to_s]
          return [key_field, field_value] if field_value
        end

        return [:kid, token.header['kid']] if @allow_nil_kid

        raise ::JWT::SignatureError, 'No key id (kid) or x5t found from token headers'
      end

      def validate_kid(kid, key_field)
        return if kid.nil? || kid.is_a?(String)

        raise ::JWT::MalformedTokenError, "Invalid type for #{key_field} header parameter"
      end

      def resolve_candidates(kid, key_field)
        key_matcher = ->(key) { (kid.nil? && @allow_nil_kid) || key[key_field] == kid }

        # First try without invalidation to facilitate application caching
        jwks = JWT::JWK::Set.new(@jwks_loader.call(key_field => kid))
        candidates = jwks.select { |key| key_matcher.call(key) }
        return candidates unless candidates.empty?

        # Second try, invalidate for backwards compatibility with the loader contract
        jwks = JWT::JWK::Set.new(@jwks_loader.call(invalidate: true, kid_not_found: true, key_field => kid))
        jwks.select { |key| key_matcher.call(key) }
      end

      # A thumbprint over the public parameters identifies the key material
      # without exposing any private component.
      def distinct_candidates(candidates)
        candidates.uniq { |jwk| Thumbprint.new(jwk).to_s }
      end

      def enforce_candidate_limit!(candidates, kid)
        return if candidates.size <= @max_candidates

        raise ::JWT::TooManyCandidateKeys,
              "#{candidates.size} compatible key candidates for kid #{kid} exceed the limit of #{@max_candidates}"
      end

      def verifies?(jwk, token)
        algorithm_name = @constraints.verification_algorithm_name(jwk, token)
        return false unless algorithm_name

        @constraints.algorithm(algorithm_name)
                    .verify(data: token.signing_input, signature: token.signature, verification_key: jwk.verify_key)
      rescue ::JWT::SignatureError
        false
      end
    end
  end
end
