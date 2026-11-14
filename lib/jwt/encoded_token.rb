# frozen_string_literal: true

require_relative 'encoded_token/claim_verification'
require_relative 'encoded_token/claims_context'
require_relative 'encoded_token/segments'
require_relative 'encoded_token/signature_verification'
require_relative 'encoded_token/verification_state'

module JWT
  # Represents an encoded JWT token
  #
  # Processing an encoded and signed token:
  #
  #   token = JWT::Token.new(payload: {pay: 'load'})
  #   token.sign!(algorithm: 'HS256', key: 'secret')
  #
  #   encoded_token = JWT::EncodedToken.new(token.jwt)
  #   encoded_token.verify_signature!(algorithm: 'HS256', key: 'secret')
  #   encoded_token.verify_claims!
  #   encoded_token.payload # => {'pay' => 'load'}
  #
  # Verification results belong to the token contents that were verified.
  # Replacing the payload, or failing a later verification, discards them.
  class EncodedToken
    include SignatureVerification
    include ClaimVerification

    DEFAULT_CLAIMS = [:exp].freeze

    private_constant(:DEFAULT_CLAIMS)

    # Returns the original token provided to the class.
    #
    # The returned string is a copy. Mutating it does not change the token.
    #
    # @return [String] The JWT token.
    def jwt
      @jwt.dup
    end

    # Initializes a new EncodedToken instance.
    #
    # The token takes ownership of the given string and its segments. Later
    # changes to the caller's string are not observed by the token.
    #
    # @param jwt [String] the encoded JWT token.
    # @raise [ArgumentError] if the provided JWT is not a String.
    def initialize(jwt)
      raise ArgumentError, 'Provided JWT must be a String' unless jwt.is_a?(String)

      @jwt      = jwt.dup.freeze
      @segments = Segments.new(@jwt)
      @state    = VerificationState.new
    end

    # A token owns its mutable state. A copy cannot change the verification
    # result or the contents observed by the original.
    def initialize_copy(other)
      super
      @segments = @segments.dup
      @state    = @state.dup
    end

    # Returns the decoded signature of the JWT token.
    #
    # The returned string is a copy.
    #
    # @return [String] the decoded signature.
    def signature
      @segments.decoded_signature
    end

    # Returns the encoded signature of the JWT token.
    #
    # The returned string is a copy.
    #
    # @return [String] the encoded signature.
    def encoded_signature
      @segments.encoded_signature
    end

    # Returns the decoded header of the JWT token.
    #
    # Reading the header does not verify the token. The returned Hash is a deep
    # copy, so changes to it are not visible to the token.
    #
    # @return [Hash] the header.
    # @raise [JWT::MalformedTokenError] if the header is not a JSON object.
    def header
      @segments.header
    end

    # Returns the encoded header of the JWT token.
    #
    # The returned string is a copy.
    #
    # @return [String] the encoded header.
    def encoded_header
      @segments.encoded_header
    end

    # Returns the payload of the JWT token. Access requires the signature and claims to have been verified,
    # and both verifications must have been made against the current token contents.
    #
    # The returned Hash is a deep copy, so changes to it (including nested
    # objects) are not visible to the token and do not affect the verified state.
    #
    # @return [Hash] the payload.
    # @raise [JWT::TokenError] if the signature has not been verified.
    # @raise [JWT::TokenError] if the claims have not been verified.
    def payload
      raise JWT::TokenError, 'Verify the token signature before accessing the payload' unless @state.signature_verified?
      raise JWT::TokenError, 'Verify the token claims before accessing the payload' unless @state.claims_verified?

      @segments.payload
    end

    # Returns the payload of the JWT token without requiring the signature to have been verified.
    #
    # This is a diagnostic read. It does not verify anything and does not change
    # the verification state. The returned Hash is a deep copy, so mutating it
    # cannot make a later verification accept modified contents.
    #
    # @return [Hash] the payload.
    def unverified_payload
      @segments.payload
    end

    # Returns the encoded payload of the JWT token.
    #
    # The returned string is a copy.
    #
    # @return [String] the encoded payload.
    def encoded_payload
      @segments.encoded_payload
    end

    # Sets the encoded payload of the JWT token.
    #
    # The token keeps its own copy of the value. Replacing the payload
    # invalidates both the signature and claim verification results.
    #
    # @param encoded_payload [String] the encoded payload.
    def encoded_payload=(encoded_payload)
      @segments.replace_payload(encoded_payload)
      @state.advance!

      encoded_payload
    end

    # Returns the signing input of the JWT token.
    #
    # @return [String] the signing input.
    def signing_input
      @segments.signing_input
    end

    # Verifies the token signature and claims.
    #
    # The claims are verified only after the signature has succeeded. A failed
    # signature verification also discards any earlier claim verification, so
    # the two results always describe the same token contents.
    #
    # @example
    #  encoded_token.verify!(signature: { algorithm: 'HS256', key: 'secret' }, claims: [:exp])
    #
    # @param signature [Hash] the parameters for signature verification (see {#verify_signature!}).
    # @param claims [Array<Symbol>, Hash] the claims to verify (see {#verify_claims!}).
    # @return [nil]
    # @raise [JWT::Error] if the signature or claim verification fails.
    def verify!(signature:, claims: nil)
      verify_signature!(**signature)
      claims.is_a?(Array) ? verify_claims!(*claims) : verify_claims!(claims)
      nil
    end

    # Verifies the token signature and claims.
    #
    # @param signature [Hash] the parameters for signature verification (see {#verify_signature!}).
    # @param claims [Array<Symbol>, Hash] the claims to verify (see {#verify_claims!}).
    # @return [Boolean] true if the signature and claims are valid, false otherwise.
    # @raise [JWT::MalformedTokenError] if the token is structurally invalid.
    def valid?(signature:, claims: nil)
      valid_signature?(**signature) &&
        (claims.is_a?(Array) ? valid_claims?(*claims) : valid_claims?(claims))
    end

    alias to_s jwt
  end
end
