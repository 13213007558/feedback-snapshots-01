# frozen_string_literal: true

module JWT
  module JWK
    # Holds the caller's algorithm and key usage constraints and decides which
    # JWKs may be considered as verification candidates.
    #
    # @api private
    class KeyConstraints
      # Algorithm name prefixes owned by each built-in key type. Custom
      # algorithms use names outside of these prefixes and are trusted to
      # declare their own key compatibility.
      KEY_TYPE_ALGORITHM_PREFIXES = {
        'RSA' => %w[RS PS].freeze,
        'EC'  => %w[ES].freeze,
        'oct' => %w[HS].freeze,
        'OKP' => %w[EdDSA].freeze
      }.freeze

      def initialize(algorithms)
        @algorithms = algorithms
      end

      # Checks that the JWK's algorithm and advertised usage fit the caller's
      # constraints.
      def allowed?(jwk)
        (@algorithms.empty? || key_algorithms(jwk).any?) && usage_allowed?(jwk)
      end

      # A key with an explicit alg is tried with its own declared algorithm.
      # Otherwise the algorithm comes from the token header and has to fit the
      # key type and the caller's algorithm constraints.
      def verification_algorithm_name(jwk, token)
        return jwk[:alg] if jwk[:alg]
        return unless key_algorithms(jwk).any? { |candidate| candidate.valid_alg?(token.header['alg']) }

        token.header['alg']
      end

      def algorithm(name)
        @algorithms.find { |candidate| candidate.respond_to?(:alg) && candidate.valid_alg?(name) } ||
          JWA.resolve(name)
      end

      private

      def key_algorithms(jwk)
        if jwk[:alg]
          # Match the caller-provided algorithms so custom algorithm objects
          # work without resolving the JWK's alg name through the registry.
          return @algorithms.select { |candidate| candidate.respond_to?(:alg) && candidate.valid_alg?(jwk[:alg]) }
        end

        @algorithms.select { |candidate| key_type_matches?(candidate, jwk) }
      end

      def key_type_matches?(candidate, jwk)
        return false unless candidate.respond_to?(:alg)

        prefixes = KEY_TYPE_ALGORITHM_PREFIXES[jwk[:kty]]
        return true if prefixes.nil?
        return true unless KEY_TYPE_ALGORITHM_PREFIXES.values.flatten.any? { |prefix| candidate.alg.start_with?(prefix) }

        prefixes.any? { |prefix| candidate.alg.start_with?(prefix) }
      end

      def usage_allowed?(jwk)
        return false if jwk[:use] && jwk[:use] != 'sig'

        key_ops = Array(jwk[:key_ops])
        key_ops.empty? || key_ops.include?('verify')
      end
    end
  end
end
