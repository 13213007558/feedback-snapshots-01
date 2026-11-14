# frozen_string_literal: true

module JWT
  # A key finder that guards an expensive key lookup (for example a database
  # query) with cheap pre-checks on the untrusted token data.
  #
  # The guarantees provided:
  # - the loader is called at most once per token and only after all checks pass
  # - the loader always receives a String kid (or nil when allow_nil_kid is set)
  # - tokens without a signature segment never reach the loader
  #   (unless the alg header is 'none')
  #
  # Works with both verification interfaces:
  #
  #   finder = JWT::StrictKeyFinder.new(kid_format: /\A[\w-]+\z/) do |kid|
  #     KeyStore.find_by(kid: kid)&.verification_key
  #   end
  #
  #   # Object interface (JWT::EncodedToken)
  #   JWT::EncodedToken.new(jwt).verify_signature!(algorithm: 'HS256', key_finder: finder)
  #
  #   # Legacy interface (JWT.decode)
  #   JWT.decode(jwt, nil, true, algorithm: 'HS256', &finder)
  #
  # Note: the kid and header are still unverified when the loader is called.
  # Never treat them as trusted; only use them to locate a candidate key.
  class StrictKeyFinder
    # Initializes a new StrictKeyFinder instance.
    #
    # @param allow_nil_kid [Boolean] whether tokens without a kid header are
    #   passed to the loader with a nil kid.
    # @param kid_format [Regexp, nil] an optional pattern the kid must match
    #   before the loader is called.
    # @yield [String, nil] the kid to find the verification key for.
    # @raise [ArgumentError] if no loader block is given.
    def initialize(allow_nil_kid: false, kid_format: nil, &loader)
      raise ArgumentError, 'Provide a key loader block' unless loader

      @allow_nil_kid = allow_nil_kid
      @kid_format = kid_format
      @loader = loader
    end

    # Finds the key for the given token or header.
    #
    # @param token [JWT::EncodedToken, Hash] the token (object interface) or
    #   the token header (legacy JWT.decode block interface).
    # @return the key returned by the loader.
    # @raise [JWT::MalformedTokenError] if the token has no signature segment,
    #   or the kid is not a String.
    # @raise [JWT::SignatureError] if the kid is missing or does not match
    #   the configured format.
    def call(token)
      header = token_header(token)
      kid = header['kid']

      raise ::JWT::SignatureError, 'No key id (kid) found in token header' if kid.nil? && !@allow_nil_kid
      raise ::JWT::MalformedTokenError, 'Invalid type for kid header parameter' unless kid.nil? || kid.is_a?(String)

      if kid && @kid_format && !@kid_format.match?(kid)
        raise ::JWT::SignatureError, 'Key id (kid) in token header does not match the expected format'
      end

      @loader.call(kid)
    end

    # Allows the finder to be used as the block of the legacy JWT.decode
    # interface. The legacy interface passes only the (unverified) header.
    #
    # @return [Proc] a proc accepting the token header.
    def to_proc
      method(:call).to_proc
    end

    private

    def token_header(token)
      return token unless token.is_a?(::JWT::EncodedToken)

      if token.encoded_signature.nil? && token.header['alg'] != 'none'
        raise ::JWT::MalformedTokenError, 'Token is missing a signature segment'
      end

      token.header
    end
  end
end
