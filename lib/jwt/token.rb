# frozen_string_literal: true

module JWT
  # Represents a JWT token
  #
  # Basic token signed using the HS256 algorithm:
  #
  #   token = JWT::Token.new(payload: {pay: 'load'})
  #   token.sign!(algorithm: 'HS256', key: 'secret')
  #   token.jwt # => eyJhb....
  #
  # Custom headers will be combined with generated headers:
  #   token = JWT::Token.new(payload: {pay: 'load'}, header: {custom: "value"})
  #   token.sign!(algorithm: 'HS256', key: 'secret')
  #   token.header # => {"custom"=>"value", "alg"=>"HS256"}
  #
  # A token has two states:
  #
  # * Before {#sign!} succeeds the token is editable. {#header} and {#payload}
  #   are live hashes and every encoded value ({#encoded_header},
  #   {#encoded_payload} and {#signing_input}) is recomputed from the current
  #   content on each call. A value read before a change is a snapshot of that
  #   moment; it is never reused as the input to a later signature.
  # * After {#sign!} succeeds the token is an immutable snapshot. {#header} and
  #   {#payload} are deep-frozen copies of exactly what was signed, {#signature}
  #   and {#jwt} are fixed, and {#sign!} raises {JWT::EncodeError}.
  #
  # A failed {#sign!} leaves the token editable and unchanged, so the caller can
  # correct the key or algorithm and retry. {#detach_payload!} only affects how
  # the token is rendered; the signing input and signature are not changed.
  class Token
    # Initializes a new Token instance.
    #
    # @param header [Hash] the header of the JWT token.
    # @param payload [Hash] the payload of the JWT token.
    def initialize(payload:, header: {})
      @header  = header ? header.transform_keys(&:to_s) : {}
      @payload = payload
      @signed  = false
      @detached_payload = false
    end

    # Returns whether the token has been signed.
    #
    # @return [Boolean] true if {#sign!} has completed successfully.
    def signed?
      @signed
    end

    # Returns whether the payload is detached from the compact serialization.
    #
    # @return [Boolean] true if {#detach_payload!} has been called.
    def detached?
      @detached_payload
    end

    # Returns the decoded signature of the JWT token.
    #
    # The signature is fixed once the token is signed. A token that has not been
    # signed has no signature.
    #
    # @return [String, nil] the decoded signature, or nil if the token is not signed.
    def signature
      @signature if @signed
    end

    # Returns the encoded signature of the JWT token.
    #
    # @return [String, nil] the encoded signature, or nil if the token is not signed.
    def encoded_signature
      @encoded_signature if @signed
    end

    # Returns the decoded header of the JWT token.
    #
    # Before signing the returned hash is the editable header. After signing it
    # is a deep-frozen copy of the header that was signed.
    #
    # @return [Hash] the header of the JWT token.
    attr_reader :header

    # Returns the encoded header of the JWT token.
    #
    # While the token is editable the value is generated from the current header
    # on every call, so changes made after an earlier read are included in the
    # next read and in the signature. Once signed, the value is fixed.
    #
    # @return [String] the encoded header of the JWT token.
    def encoded_header
      return @encoded_header if @signed

      encode_segment(header)
    end

    # Returns the payload of the JWT token.
    #
    # Before signing the returned hash is the editable payload. After signing it
    # is a deep-frozen copy of the payload that was signed.
    #
    # @return [Hash] the payload of the JWT token.
    attr_reader :payload

    # Returns the encoded payload of the JWT token.
    #
    # While the token is editable the value is generated from the current
    # payload, including nested changes, on every call. Once signed, the value
    # is fixed and remains available even when the payload is detached.
    #
    # @return [String] the encoded payload of the JWT token.
    def encoded_payload
      return @encoded_payload if @signed

      encode_segment(payload)
    end

    # Returns the signing input of the JWT token.
    #
    # The signing input always contains the encoded payload, also when the
    # payload is detached from the compact serialization. While editable it is
    # recomputed from the current content on every call.
    #
    # @return [String] the signing input of the JWT token.
    def signing_input
      return @signing_input if @signed

      [encoded_header, encoded_payload].join('.')
    end

    # Returns the JWT token as a string.
    #
    # @return [String] the JWT token as a string.
    # @raise [JWT::EncodeError] if the token is not signed or other encoding issues
    def jwt
      raise ::JWT::EncodeError, 'Token is not signed' unless @signed

      @jwt ||= render.freeze
    end

    # Detaches the payload according to https://datatracker.ietf.org/doc/html/rfc7515#appendix-F
    #
    # Detaching affects only the compact serialization. Calling it before or
    # after signing leaves the signing input, the signature and the encoded
    # payload unchanged. It can be called repeatedly.
    #
    # @return [nil]
    def detach_payload!
      @detached_payload = true
      @jwt = nil

      nil
    end

    # Signs the JWT token.
    #
    # Signing is atomic. The header, payload, signing input and signature are
    # all computed before the token transitions to the signed state, so a
    # failure (an unusable key, a mismatching algorithm or an encoding problem)
    # leaves the token editable and does not leak a generated 'alg' header into
    # a later attempt.
    #
    # On success the token becomes read-only: {#header} and {#payload} are
    # deep-frozen copies of the exact JSON that was signed.
    #
    # @param key [String, JWT::JWK::KeyBase] the key to use for signing.
    # @param algorithm [String, Object] the algorithm to use for signing.
    # @return [void]
    # @raise [JWT::EncodeError] if the token is already signed or other problems when signing
    def sign!(key:, algorithm:)
      raise ::JWT::EncodeError, 'Token already signed' if @signed

      snapshot = snapshot_for(JWA.create_signer(algorithm: algorithm, key: key))

      commit!(**snapshot)

      nil
    end

    # Verifies the claims of the token.
    # @param options [Array<Symbol>, Hash] the claims to verify.
    # @raise [JWT::ClaimValidationError] if the claims are invalid.
    def verify_claims!(*options)
      Claims::Verifier.verify!(self, *options)
    end

    # Returns the errors of the claims of the token.
    # @param options [Array<Symbol>, Hash] the claims to verify.
    # @return [Array<Symbol>] the errors of the claims.
    def claim_errors(*options)
      Claims::Verifier.errors(self, *options)
    end

    # Returns whether the claims of the token are valid.
    # @param options [Array<Symbol>, Hash] the claims to verify.
    # @return [Boolean] whether the claims are valid.
    def valid_claims?(*options)
      claim_errors(*options).empty?
    end

    # Returns the JWT token as a string.
    #
    # @return [String] the JWT token as a string.
    alias to_s jwt

    private

    # Builds everything that will be exposed after signing without changing any
    # state on the token. A failure anywhere in here leaves the token editable.
    def snapshot_for(signer)
      signed_header = canonical_header(signer)
      signed_payload = canonical_copy(payload)
      encoded_header = encode_segment(signed_header)
      encoded_payload = encode_segment(signed_payload)
      signing_input = [encoded_header, encoded_payload].join('.')
      signature = signer.sign(data: signing_input)

      {
        header: deep_freeze(signed_header),
        payload: deep_freeze(signed_payload),
        encoded_header: deep_freeze(encoded_header),
        encoded_payload: deep_freeze(encoded_payload),
        signing_input: deep_freeze(signing_input),
        signature: deep_freeze(signature),
        encoded_signature: deep_freeze(::JWT::Base64.url_encode(signature))
      }
    end

    # Builds the header that will be signed without touching the editable one.
    # Header keys are normalized to strings and an explicitly given 'alg' wins
    # over the algorithm supplied by the signer.
    def canonical_header(signer)
      header_with_string_keys = header.transform_keys(&:to_s)
      canonical_copy(header_with_string_keys.merge(signer.jwa.header) { |_key, old, _new| old })
    end

    # Represents the data exactly as it appears in the token. Symbol keys and
    # other Ruby-only types are converted by the same JSON serializer used for
    # the signed segments.
    def canonical_copy(value)
      JWT::JSON.parse(JWT::JSON.generate(value))
    end

    def encode_segment(value)
      ::JWT::Base64.url_encode(JWT::JSON.generate(value))
    end

    def render
      [encoded_header, @detached_payload ? '' : encoded_payload, encoded_signature].join('.')
    end

    # The token becomes signed only after the whole snapshot is built.
    def commit!(header:, payload:, encoded_header:, encoded_payload:, signing_input:, signature:, encoded_signature:)
      @header            = header
      @payload           = payload
      @encoded_header    = encoded_header
      @encoded_payload   = encoded_payload
      @signing_input     = signing_input
      @signature         = signature
      @encoded_signature = encoded_signature
      @signed            = true
      @jwt               = nil
    end

    def deep_freeze(value)
      case value
      when Hash
        value.each do |key, element|
          deep_freeze(key)
          deep_freeze(element)
        end
      when Array
        value.each { |element| deep_freeze(element) }
      end

      value.freeze
    end
  end
end
