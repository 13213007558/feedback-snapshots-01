# frozen_string_literal: true

require_relative '../security_utils'

module JWT
  module JWA
    # Implementation of the HMAC family of algorithms
    class Hmac
      include JWT::JWA::SigningAlgorithm

      # Minimum key lengths for HMAC algorithms based on RFC 7518 Section 3.2.
      # Keys must be at least the size of the hash output to ensure sufficient
      # entropy for the algorithm's security level.
      MIN_KEY_LENGTHS = {
        'HS256' => 32,
        'HS384' => 48,
        'HS512' => 64
      }.freeze

      def initialize(alg, digest)
        @alg = alg
        @digest = digest
      end

      def sign(data:, signing_key:)
        validate_key!(signing_key) { |message| raise_sign_error!(message) }

        OpenSSL::HMAC.digest(digest.new, signing_key, data)
      end

      def verify(data:, signature:, verification_key:)
        validate_key!(verification_key) { |message| raise_verify_error!(message) }

        SecurityUtils.secure_compare(signature, OpenSSL::HMAC.digest(digest.new, verification_key, data))
      end

      register_algorithm(new('HS256', OpenSSL::Digest::SHA256))
      register_algorithm(new('HS384', OpenSSL::Digest::SHA384))
      register_algorithm(new('HS512', OpenSSL::Digest::SHA512))

      # @api private
      def token_binding_hash
        digest.new.name
      end

      # The comparison helper moved to JWT::SecurityUtils. Keep the nested
      # constant for callers that referenced it where it used to live.
      SecurityUtils = ::JWT::SecurityUtils

      private

      attr_reader :digest

      # Yields a message for the first problem found with the key. The caller
      # raises it, so signing and verification failures keep their own error class.
      def validate_key!(key)
        yield 'HMAC key expected to be a String' unless key.is_a?(String)
        yield 'HMAC key cannot be empty' if key.empty?

        return unless JWT.configuration.decode.enforce_hmac_key_length

        min_length = MIN_KEY_LENGTHS[alg]
        yield "HMAC key must be at least #{min_length} bytes for #{alg} algorithm" if key.bytesize < min_length
      end
    end
  end
end
