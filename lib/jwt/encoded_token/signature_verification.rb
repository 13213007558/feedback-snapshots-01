# frozen_string_literal: true

module JWT
  class EncodedToken
    # Signature verification for an encoded token.
    #
    # Verification is bound to the token contents that exist when it starts. A
    # key finder can inspect the token, but it cannot change what is being
    # verified behind the caller's back.
    #
    # @private
    module SignatureVerification
      # Verifies the signature of the JWT token.
      #
      # @param algorithm [String, Array<String>, Object, Array<Object>] the algorithm(s) to use for verification.
      # @param key [String, Array<String>] the key(s) to use for verification.
      # @param key_finder [#call] an object responding to `call` to find the key for verification.
      # @return [nil]
      # @raise [JWT::VerificationError] if the signature verification fails.
      # @raise [JWT::MalformedTokenError] if the token is structurally invalid.
      # @raise [ArgumentError] if neither key nor key_finder is provided, or if both are provided.
      def verify_signature!(algorithm:, key: nil, key_finder: nil)
        return if valid_signature?(algorithm: algorithm, key: key, key_finder: key_finder)

        raise JWT::VerificationError, 'Signature verification failed'
      end

      # Checks if the signature of the JWT token is valid.
      #
      # @param algorithm [String, Array<String>, Object, Array<Object>] the algorithm(s) to use for verification.
      # @param key [String, Array<String>, JWT::JWK::KeyBase, Array<JWT::JWK::KeyBase>] the key(s) to use for verification.
      # @param key_finder [#call] an object responding to `call` to find the key for verification.
      #   Not called if the token's algorithm is not among the given algorithms, in which case the
      #   signature is not valid. The token's alg header is not compared when a key is given directly.
      # @return [Boolean] true if the signature is valid, false otherwise.
      # @raise [JWT::MalformedTokenError] if the token is structurally invalid.
      def valid_signature?(algorithm: nil, key: nil, key_finder: nil)
        raise ArgumentError, 'Provide either key or key_finder, not both or neither' if key.nil? == key_finder.nil?

        @state.signature_pending!
        validate_segment_count!

        # Snapshot the contents before any hook runs. If the hook replaces the
        # payload, the revision changes and this result must be discarded.
        revision    = @state.revision
        header      = @segments.header
        input       = @segments.signing_input

        return signature_failed! if key_finder && !algorithm_allowed?(algorithm)

        keys        = Array(key || key_finder.call(self))
        encoded_sig = @segments.decoded_signature
        verifiers   = JWA.create_verifiers(algorithms: algorithm, keys: keys, preferred_algorithm: header['alg'])

        raise JWT::VerificationError, 'No algorithm provided' if verifiers.empty?

        valid = verifiers.any? do |jwa|
          jwa.verify(data: input, signature: encoded_sig)
        end

        return signature_failed! unless valid && revision == @state.revision

        @state.signature_succeeded!(revision)
        true
      rescue ArgumentError
        # Misuse of the API does not describe the token, so it cannot invalidate
        # a result that was already established for the current contents.
        raise
      rescue StandardError
        @state.signature_failed!
        raise
      end

      private

      def validate_segment_count!
        raise JWT::MalformedTokenError, 'Too many segments' if @jwt.count('.') > 2
      end

      def algorithm_allowed?(algorithms)
        algorithms = Array(algorithms).map { |algorithm| JWA.resolve(algorithm) }

        algorithms.empty? || algorithms.any? { |algorithm| algorithm == JWA::Unsupported || algorithm.valid_alg?(@segments.header['alg']) }
      end

      def signature_failed!
        @state.signature_failed!
        false
      end
    end
  end
end
