# frozen_string_literal: true

require 'openssl'

require_relative '../base64'
require_relative '../security_utils'

module JWT
  module Claims
    # Verifies the OpenID Connect at_hash and c_hash bindings.
    #
    # The hash algorithm is derived from the JWA algorithm object that actually
    # verified the token signature. The unverified `alg` header value is never
    # consulted, and an algorithm without a defined mapping is rejected.
    #
    # The caller supplies the raw access token and/or authorization code and
    # lists the binding kinds that must be present. Missing values are errors,
    # not a request to skip the check.
    #
    # @example
    #   encoded_token.verify!(
    #     signature: { algorithm: 'RS256', key: key },
    #     claims: {
    #       token_binding: {
    #         access_token: access_token,
    #         code: authorization_code,
    #         required: %i[at_hash c_hash]
    #       }
    #     }
    #   )
    class TokenBinding
      # Maps a binding kind to the option holding its raw value.
      BINDING_VALUES = {
        at_hash: :access_token,
        c_hash: :code
      }.freeze

      OPTION_KEYS = %i[access_token code required].freeze

      private_constant(:BINDING_VALUES, :OPTION_KEYS)

      # @param options [Hash] the raw values and required binding kinds.
      # @option options [String] :access_token the raw access token to bind to at_hash.
      # @option options [String] :code the raw authorization code to bind to c_hash.
      # @option options [Array<Symbol>] :required the binding kinds that must be verified.
      def initialize(options:)
        raise JWT::InvalidTokenBindingError, 'Token binding options must be a Hash' unless options.is_a?(::Hash)

        @options = normalize_options(options)
        @required = normalize_required
      end

      # Verifies the configured bindings against the token.
      #
      # @param context [Object] the context containing the payload and the JWA
      #   algorithm that verified the token signature.
      # @param _args [Hash] additional arguments (not used).
      # @raise [JWT::TokenBindingError] if a binding is missing, malformed or does not match.
      # @raise [JWT::UnsupportedTokenBindingAlgorithmError] if the verified algorithm has no mapping.
      # @return [nil]
      def verify!(context:, **_args)
        digest = digest_for(verified_jwa(context))
        required.each do |kind|
          raw_value = binding_value(kind)
          claim = claim_value(context, kind)
          expected = encode_digest(digest, raw_value)

          next if JWT::SecurityUtils.secure_compare(claim, expected)

          raise JWT::InvalidTokenBindingError, "Invalid #{kind} token binding"
        end

        nil
      end

      private

      attr_reader :options, :required

      def normalize_options(options)
        normalized = options.each_with_object({}) do |(key, value), result|
          name = key.respond_to?(:to_sym) ? key.to_sym : key
          raise JWT::InvalidTokenBindingError, "Unknown token binding option(s): #{key}" unless OPTION_KEYS.include?(name)
          raise JWT::InvalidTokenBindingError, "Duplicate token binding option: #{name}" if result.key?(name)

          result[name] = value
        end
        raise JWT::InvalidTokenBindingError, 'The required token binding kinds must be given explicitly' unless normalized.key?(:required)

        normalized
      end

      def normalize_required
        kinds = options[:required]
        raise JWT::InvalidTokenBindingError, 'The required token binding kinds must be given explicitly' if kinds.nil?

        kinds = Array(kinds).map { |kind| kind.is_a?(String) ? kind.to_sym : kind }
        raise JWT::InvalidTokenBindingError, 'At least one token binding kind is required' if kinds.empty?

        unknown = kinds - BINDING_VALUES.keys
        raise JWT::InvalidTokenBindingError, "Unsupported token binding kind(s): #{unknown.join(', ')}" unless unknown.empty?

        kinds.uniq
      end

      def verified_jwa(context)
        jwa = context.respond_to?(:verified_jwa) ? context.verified_jwa : nil
        raise JWT::InvalidTokenBindingError, 'Token bindings can only be verified after a successful signature verification' if jwa.nil?

        jwa
      end

      def digest_for(jwa)
        alg = jwa.respond_to?(:alg) ? jwa.alg : nil
        digest = jwa.respond_to?(:token_binding_hash) ? jwa.token_binding_hash : nil
        raise JWT::UnsupportedTokenBindingAlgorithmError, "No token binding hash mapping for signing algorithm #{alg || '<none>'}" if digest.nil?

        OpenSSL::Digest.new(digest)
      rescue OpenSSL::Digest::DigestError
        raise JWT::UnsupportedTokenBindingAlgorithmError, "No token binding hash mapping for signing algorithm #{alg || '<none>'}"
      end

      def binding_value(kind)
        option = BINDING_VALUES.fetch(kind)
        value = options[option]
        raise JWT::InvalidTokenBindingError, "Missing raw #{option} value for #{kind} token binding" if value.nil?
        raise JWT::InvalidTokenBindingError, "The raw #{option} value for #{kind} token binding must be a String" unless value.is_a?(String)
        raise JWT::InvalidTokenBindingError, "The raw #{option} value for #{kind} token binding cannot be empty" if value.empty?

        value
      end

      def claim_value(context, kind)
        payload = context.payload
        raise JWT::InvalidTokenBindingError, "Cannot verify #{kind} without a payload object" unless payload.is_a?(Hash)

        value = payload.key?(kind.to_s) ? payload[kind.to_s] : payload[kind]
        raise JWT::InvalidTokenBindingError, "Missing #{kind} claim in the token" if value.nil?
        raise JWT::InvalidTokenBindingError, "The #{kind} claim must be a String" unless value.is_a?(String)
        raise JWT::InvalidTokenBindingError, "The #{kind} claim cannot be empty" if value.empty?

        value
      end

      def encode_digest(digest, value)
        full_digest = digest.digest(value)
        JWT::Base64.url_encode(full_digest.byteslice(0, full_digest.bytesize / 2))
      end
    end
  end
end
