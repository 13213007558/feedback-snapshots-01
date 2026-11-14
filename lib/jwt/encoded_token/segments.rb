# frozen_string_literal: true

module JWT
  class EncodedToken
    # Owns the encoded segments and the decoded copies derived from them.
    #
    # Nothing handed out by this class is the object it keeps internally. The
    # token can therefore verify one set of bytes and hand out copies without
    # the caller's changes reaching the verified contents.
    #
    # @private
    class Segments
      def initialize(jwt)
        @encoded_header, @encoded_payload, @encoded_signature = jwt.split('.').map { |segment| immutable(segment) }
      end

      # Copies cannot share decoded objects that the original may hand out.
      def initialize_copy(other)
        super
        @decoded_header    = duplicate_value(@decoded_header)
        @decoded_payload   = duplicate_value(@decoded_payload)
        @decoded_signature = duplicate(@decoded_signature)
      end

      def encoded_header
        duplicate(@encoded_header)
      end

      def encoded_payload
        duplicate(@encoded_payload)
      end

      def encoded_signature
        duplicate(@encoded_signature)
      end

      def header
        duplicate_value(decoded_header)
      end

      def payload
        duplicate_value(decoded_payload)
      end

      # The claim verifiers use the diagnostic read interface. An unencoded
      # payload still has to be decoded before its claims can be checked.
      def unverified_payload
        payload
      end

      def decoded_signature
        duplicate(decoded_signature_value)
      end

      def signing_input
        [@encoded_header, @encoded_payload].join('.')
      end

      def replace_payload(encoded_payload)
        @encoded_payload = immutable(encoded_payload)
        @decoded_payload = nil
      end

      private

      def decoded_signature_value
        @decoded_signature ||= immutable(::JWT::Base64.url_decode(@encoded_signature || ''))
      end

      def decoded_header
        @decoded_header ||= parse_and_decode(@encoded_header).tap do |decoded_header|
          raise JWT::MalformedTokenError, 'Token header not a JSON object' unless decoded_header.is_a?(Hash)
        end
      end

      def decoded_payload
        @decoded_payload ||= decode_payload
      end

      def decode_payload
        raise JWT::MalformedTokenError, 'Encoded payload is empty' if @encoded_payload == ''

        if unencoded_payload?
          validate_unencoded_payload!
          return parse(@encoded_payload)
        end

        parse_and_decode(@encoded_payload)
      end

      # The b64 critical header must be understood before an unencoded payload
      # can be read. This is part of decoding, not claim verification, so a
      # diagnostic read must not change the token's verification state. The
      # check only reads the header, which is already decoded at this point.
      def validate_unencoded_payload!
        Claims::Verifier.verify!(ClaimsContext.new(self), crit: ['b64'])
      end

      def unencoded_payload?
        decoded_header['b64'] == false
      end

      def parse_and_decode(segment)
        parse(::JWT::Base64.url_decode(segment || ''))
      end

      def parse(segment)
        JWT::JSON.parse(segment)
      rescue ::JSON::ParserError
        raise JWT::MalformedTokenError, 'Invalid segment encoding'
      end

      def immutable(value)
        value.is_a?(String) ? value.dup.freeze : value
      end

      def duplicate(value)
        value.is_a?(String) ? value.dup : value
      end

      def duplicate_value(value)
        case value
        when Hash
          value.each_with_object({}) { |(key, item), copy| copy[duplicate(key)] = duplicate_value(item) }
        when Array
          value.map { |item| duplicate_value(item) }
        else
          duplicate(value)
        end
      end
    end
  end
end
