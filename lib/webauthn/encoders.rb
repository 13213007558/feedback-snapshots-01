# frozen_string_literal: true

require "webauthn/error"

module WebAuthn
  class DecodingError < FormatError; end

  def self.standard_encoder
    @standard_encoder ||= Encoders.lookup(Encoder::STANDARD_ENCODING)
  end

  module Encoders
    class << self
      def lookup(encoding)
        case encoding
        when :base64
          Base64Encoder
        when :base64url
          Base64UrlEncoder
        when nil, false
          NullEncoder
        else
          raise ConfigurationError, "Unsupported or unknown encoding: #{encoding}"
        end
      end
    end

    class Base64Encoder
      def self.encode(data)
        [data].pack("m0") # Base64.strict_encode64(data)
      end

      def self.decode(data)
        raise DecodingError, "Input could not be decoded" unless data.is_a?(String)

        data.unpack1("m0") # Base64.strict_decode64(data)
      rescue ArgumentError
        raise DecodingError, "Input could not be decoded"
      end
    end

    class Base64UrlEncoder
      def self.encode(data)
        data = [data].pack("m0") # Base64.urlsafe_encode64(data, padding: false)
        data.chomp!("==") or data.chomp!("=")
        data.tr!("+/", "-_")
        data
      end

      def self.decode(data)
        raise DecodingError, "Input could not be decoded" unless data.is_a?(String)

        if !data.end_with?("=") && data.length % 4 != 0 #  Base64.urlsafe_decode64(data)
          data = data.ljust((data.length + 3) & ~3, "=")
        end

        data = data.tr("-_", "+/")
        data.unpack1("m0")
      rescue ArgumentError
        raise DecodingError, "Input could not be decoded"
      end
    end

    class NullEncoder
      def self.encode(data)
        data
      end

      def self.decode(data)
        data
      end
    end
  end
end
