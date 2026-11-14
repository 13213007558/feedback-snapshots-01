# frozen_string_literal: true

module JWT
  module Policy
    # A VerificationPolicy captures the complete, server-chosen set of rules that
    # a token must satisfy for a single purpose (for example a login callback or
    # an API request).
    #
    # The policy is deliberately built only from values the application supplies.
    # Nothing in an unverified token is ever allowed to select a policy, change
    # the trusted issuers or algorithms, or influence where verification keys are
    # fetched from.
    class VerificationPolicy
      # Header parameters that name an external location to fetch a key from.
      # These are rejected because honoring them would let an unverified token
      # choose the key source.
      UNSAFE_KEY_LOCATION_HEADERS = %w[jku x5u].freeze

      # The constraint dimensions used to decide whether two purposes can accept
      # the same token.
      CONSTRAINT_DIMENSIONS = %i[issuers algorithms typ audience].freeze

      # @!attribute [r] purpose
      #   @return [Symbol, String] the purpose this policy verifies.
      # @!attribute [r] issuers
      #   @return [Array<String>] the trusted `iss` values.
      # @!attribute [r] algorithms
      #   @return [Array<String>] the accepted `alg` values.
      # @!attribute [r] types
      #   @return [Array<String>] the accepted `typ` header values.
      # @!attribute [r] audiences
      #   @return [Array<String>] the accepted `aud` values.
      # @!attribute [r] required_claims
      #   @return [Array<String>] claims that must be present in the payload.
      attr_reader :purpose, :issuers, :algorithms, :types, :audiences, :required_claims

      # Builds a policy.
      #
      # @param purpose [Symbol, String] the purpose this policy verifies.
      # @param issuers [String, Array<String>] the trusted `iss` values.
      # @param algorithms [String, Array<String>] the accepted `alg` values.
      # @param typ [String, Array<String>] the accepted `typ` header values.
      # @param audience [String, Array<String>] the accepted `aud` values.
      # @param required_claims [Array<String>] claims that must be present.
      # @param key [Object] a static verification key. Mutually exclusive with `jwks`.
      # @param jwks [Hash, Array, #call] a JWK set or loader proc. Mutually exclusive with `key`.
      # @param allow_nil_kid [Boolean] whether a token without `kid` is allowed for JWK lookup.
      # @param key_fields [Array<Symbol>] header fields used to match JWKs.
      # @raise [JWT::PolicyError] if the configuration is incomplete or ambiguous.
      def initialize(purpose:, issuers:, algorithms:, typ:, audience:,
                     required_claims: [], key: nil, jwks: nil,
                     allow_nil_kid: false, key_fields: nil)
        @purpose         = purpose
        @issuers         = Array(issuers).map(&:to_s)
        @algorithms      = Array(algorithms).map(&:to_s)
        @types           = Array(typ).map(&:to_s)
        @audiences       = Array(audience).map(&:to_s)
        @required_claims = Array(required_claims).map(&:to_s)
        @key             = key
        @jwks            = jwks
        @allow_nil_kid   = allow_nil_kid
        @key_fields      = key_fields

        validate!
      end

      # @return [Object] the static verification key, when configured.
      attr_reader :key

      # @return [Hash, Array, #call, nil] the JWK set or loader, when configured.
      attr_reader :jwks

      # @return [Boolean] whether a JWK set/loader is used instead of a static key.
      def jwks?
        !@jwks.nil?
      end

      # @return [Hash] options consumed by {JWT::JWK::KeyFinder}.
      def jwk_options
        {
          jwks: @jwks,
          allow_nil_kid: @allow_nil_kid,
          key_fields: @key_fields
        }.compact
      end

      # Describes the constraint dimensions shared by every policy. Two policies
      # whose dimensions all intersect can each accept the same token, which is
      # the ambiguous overlap the registry must reject.
      #
      # @return [Hash{Symbol => Array<String>}] the comparable constraint sets.
      def constraint_sets
        {
          issuers: issuers,
          algorithms: algorithms,
          typ: types,
          audience: audiences
        }
      end

      # Checks whether this policy and another one can accept the same token.
      # Overlap means every discriminator dimension intersects; a single
      # distinct dimension is enough to keep the purposes apart.
      #
      # @param other [VerificationPolicy] the policy to compare with.
      # @return [Boolean] true when the two policies can accept the same token.
      def overlaps?(other)
        CONSTRAINT_DIMENSIONS.all? do |dimension|
          (constraint_sets[dimension] & other.constraint_sets[dimension]).any?
        end
      end

      # Rejects header parameters that would let an unverified token dictate the
      # key source. Called before any external key lookup happens.
      #
      # @param header [Hash] the decoded JWT header.
      # @raise [JWT::VerificationKeyError] if an external key-location header is present.
      def reject_remote_key_headers!(header)
        present = UNSAFE_KEY_LOCATION_HEADERS.select { |name| header.key?(name) }
        return if present.empty?

        raise JWT::VerificationKeyError,
              "Token header(s) #{present.join(', ')} name an external key source; the server policy selects the key"
      end

      private

      def validate!
        require_non_empty!(:issuers, issuers)
        require_non_empty!(:algorithms, algorithms)
        require_non_empty!(:typ, types)
        require_non_empty!(:audience, audiences)

        return unless @key.nil? && @jwks.nil?

        raise JWT::PolicyError, "Policy #{purpose.inspect} must configure either a static :key or a :jwks source"
      end

      def require_non_empty!(name, values)
        raise JWT::PolicyError, "Policy #{purpose.inspect} requires at least one #{name}" if values.empty?
      end
    end
  end
end
