# frozen_string_literal: true

require "oauth/signature"
require "oauth/helper"
require "oauth/request_proxy/base"
require "base64"
require "openssl"

module OAuth
  module Signature
    class Base
      include OAuth::Helper

      # Credential families a signature method consumes. A verifier policy
      # uses this to ensure a resolved credential matches the declared method
      # (an HMAC shared secret can never be treated as an RSA key and vice
      # versa).
      #
      # * +:shared_secret+ - a symmetric secret string (HMAC, PLAINTEXT)
      # * +:rsa_key+       - an asymmetric RSA key or X.509 certificate
      KEY_TYPES = %i[shared_secret rsa_key].freeze

      attr_accessor :options
      attr_reader :token_secret, :consumer_secret, :request

      def self.implements(signature_method = nil)
        return @implements if signature_method.nil?

        @implements = signature_method
        OAuth::Signature.available_methods[@implements] = self
      end

      # Declare (or read) the kind of credential this method requires.
      # Defaults to +:shared_secret+ so existing third-party methods built on
      # the HMAC/PLAINTEXT secret model keep working without modification.
      def self.key_type(key_type = nil)
        return @key_type || :shared_secret if key_type.nil?

        raise ArgumentError, "Unknown key type #{key_type.inspect}" unless KEY_TYPES.include?(key_type)

        @key_type = key_type
      end

      # Whether a resolved +consumer_secret+ is usable with this method.
      def self.compatible_credential?(consumer_secret)
        case key_type
        when :shared_secret
          shared_secret?(consumer_secret)
        when :rsa_key
          rsa_key?(consumer_secret)
        else
          false
        end
      end

      # A shared secret is a plain String (the token/consumer secret). RSA key
      # objects are never acceptable symmetric secrets.
      def self.shared_secret?(value)
        value.nil? || value.is_a?(String)
      end

      def self.rsa_key?(value)
        return true if value.is_a?(OpenSSL::PKey::PKey) || value.is_a?(OpenSSL::X509::Certificate)
        return false unless value.is_a?(String)

        # A PEM/DER key or certificate parses; a bare HMAC secret does not.
        OpenSSL::PKey.read(value)
        true
      rescue OpenSSL::PKey::PKeyError, ArgumentError
        begin
          OpenSSL::X509::Certificate.new(value)
          true
        rescue OpenSSL::X509::CertificateError, ArgumentError
          false
        end
      end

      def initialize(request, options = {}, &block)
        raise TypeError unless request.is_a?(OAuth::RequestProxy::Base)

        @request = request
        @options = options

        ## consumer secret was determined beforehand

        @consumer_secret = options[:consumer].secret if options[:consumer]

        # presence of :consumer_secret option will override any Consumer that's provided
        @consumer_secret = options[:consumer_secret] if options[:consumer_secret]

        ## token secret was determined beforehand

        @token_secret = options[:token].secret if options[:token]

        # presence of :token_secret option will override any Token that's provided
        @token_secret = options[:token_secret] if options[:token_secret]

        # override secrets based on the values returned from the block (if any)
        if block
          # consumer secret and token secret need to be looked up based on pieces of the request
          secrets = yield block.arity == 1 ? request : [token, consumer_key, nonce, request.timestamp]
          if secrets.is_a?(Array) && secrets.size == 2
            @token_secret = secrets[0]
            @consumer_secret = secrets[1]
          end
        end
      end

      def signature
        Base64.encode64(digest).chomp.delete("\n")
      end

      def ==(other)
        check = signature.bytesize ^ other.bytesize
        signature.bytes.zip(other.bytes) { |x, y| check |= x ^ y.to_i }
        check.zero?
      end

      def verify
        self == request.signature
      end

      def signature_base_string
        request.signature_base_string
      end

      def body_hash
        raise_instantiation_error
      end

      private

      def token
        request.token
      end

      def consumer_key
        request.consumer_key
      end

      def nonce
        request.nonce
      end

      def secret
        "#{escape(consumer_secret)}&#{escape(token_secret)}"
      end

      def digest
        raise_instantiation_error
      end

      def raise_instantiation_error
        raise NotImplementedError, "Cannot instantiate #{self.class.name} class directly."
      end
    end
  end
end
