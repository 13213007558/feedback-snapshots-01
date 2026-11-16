# frozen_string_literal: true

require "cose/error"
require "cose/key"
require "cose/key/ec2"
require "openssl"
require "webauthn/error"

module WebAuthn
  class PublicKey
    # Raised when a stored public key record cannot be recognized as either a
    # legacy P-256 uncompressed point or a well-formed COSE_Key credential.
    class UnrecognizedPublicKey < WebAuthn::Error
      # @return [Symbol] machine readable reason the record was rejected
      attr_reader :reason

      def initialize(message, reason: :unknown)
        @reason = reason
        super(message)
      end
    end

    # Strict, side-effect free classifier for the two on-disk public key formats
    # that have ever been emitted by this gem:
    #
    #   * +:legacy_p256_point+ - an ANSI X9.62 uncompressed P-256 point
    #     (0x04 || x || y, 65 bytes) written by webauthn-ruby <= v1.11.0.
    #   * +:cose_key+         - a CBOR encoded COSE_Key (RFC 8152) credential.
    #
    # A record is only accepted once its coordinates, curve membership and
    # algorithm have been independently verified. In particular, the leading
    # 0x04 byte alone is never treated as proof that a byte string is a point.
    module Format
      UNCOMPRESSED_FORM_INDICATOR = "\x04".b
      P256_COORDINATE_LENGTH = 32
      P256_POINT_LENGTH = 1 + (P256_COORDINATE_LENGTH * 2)
      P256_CURVE_NAME = "prime256v1"
      ES256_ALGORITHM_ID = -7

      # @return [Symbol] +:legacy_p256_point+ or +:cose_key+
      # @raise [WebAuthn::PublicKey::UnrecognizedPublicKey] when the record
      #   cannot be classified or fails structural/cryptographic validation.
      def self.detect(data)
        if data.nil? || (data.respond_to?(:empty?) && data.empty?)
          raise UnrecognizedPublicKey.new("public key is empty", reason: :empty)
        end
        unless data.is_a?(String)
          raise UnrecognizedPublicKey.new("public key is not a binary string", reason: :not_binary)
        end

        bytes = data.b

        # A record that looks structurally like a legacy point (65 bytes, 0x04
        # prefix) is always interpreted as one, never as COSE, so a corrupt or
        # off-curve point is reported specifically instead of being guessed as
        # another format.
        if point_shaped?(bytes)
          return :legacy_p256_point if valid_p256_point?(point_x(bytes), point_y(bytes))

          raise UnrecognizedPublicKey.new(
            "bytes look like a P-256 uncompressed point but the coordinates are not on the curve",
            reason: :point_not_on_curve
          )
        end

        if bytes.start_with?(UNCOMPRESSED_FORM_INDICATOR)
          raise UnrecognizedPublicKey.new(
            "data starts with the uncompressed-point indicator but has wrong length " \
            "#{bytes.bytesize} (expected #{P256_POINT_LENGTH})",
            reason: :bad_point_length
          )
        end

        if cose_key?(bytes)
          :cose_key
        else
          raise UnrecognizedPublicKey.new(
            "public key is neither a valid P-256 uncompressed point nor a COSE_Key",
            reason: :unrecognized
          )
        end
      end

      def self.point_shaped?(bytes)
        bytes.bytesize == P256_POINT_LENGTH && bytes.start_with?(UNCOMPRESSED_FORM_INDICATOR)
      end

      def self.point_x(bytes)
        bytes[1, P256_COORDINATE_LENGTH]
      end

      def self.point_y(bytes)
        bytes[1 + P256_COORDINATE_LENGTH, P256_COORDINATE_LENGTH]
      end

      def self.legacy_p256_point?(bytes)
        point_shaped?(bytes) && valid_p256_point?(point_x(bytes), point_y(bytes))
      end

      def self.cose_key?(bytes)
        # A bare point always starts with the uncompressed indicator; a COSE
        # map is CBOR and therefore cannot begin with that byte. Guard first so
        # an ambiguous length-65 byte string is never re-interpreted.
        return false if bytes.start_with?(UNCOMPRESSED_FORM_INDICATOR)

        cose_key =
          begin
            COSE::Key.deserialize(bytes)
          rescue COSE::MalformedKeyError, COSE::UnknownKeyType, COSE::KeyDeserializationError,
                 ArgumentError, TypeError => e
            raise UnrecognizedPublicKey.new("malformed COSE_Key: #{e.message}", reason: :malformed_cose)
          end

        valid_cose_ec2_key?(cose_key)
      end

      # Validates that a COSE_Key is an ES256/P-256 EC2 key whose coordinates
      # are 32 bytes each and describe a point actually on the P-256 curve.
      # Keys of any other type/algorithm are reported, never guessed.
      def self.valid_cose_ec2_key?(cose_key)
        unless cose_key.is_a?(COSE::Key::EC2)
          raise UnrecognizedPublicKey.new(
            "unsupported COSE_Key type #{cose_key.class}; only P-256 EC2 credentials are migrated",
            reason: :unsupported_key_type
          )
        end

        unless cose_key.crv == COSE::Key::Curve.by_name("P-256")&.id
          raise UnrecognizedPublicKey.new(
            "unsupported COSE curve id #{cose_key.crv.inspect}; only P-256 (crv=1) is supported",
            reason: :unsupported_curve
          )
        end

        unless cose_key.alg.nil? || cose_key.alg == ES256_ALGORITHM_ID
          raise UnrecognizedPublicKey.new(
            "unsupported COSE algorithm #{cose_key.alg.inspect}; only ES256 (#{ES256_ALGORITHM_ID}) is supported",
            reason: :unsupported_algorithm
          )
        end

        unless cose_key.x.is_a?(String) && cose_key.y.is_a?(String) &&
               cose_key.x.bytesize == P256_COORDINATE_LENGTH &&
               cose_key.y.bytesize == P256_COORDINATE_LENGTH
          raise UnrecognizedPublicKey.new(
            "COSE EC2 coordinates must each be #{P256_COORDINATE_LENGTH} bytes",
            reason: :bad_coordinate_length
          )
        end

        valid_p256_point?(cose_key.x, cose_key.y)
      end

      # Verifies that (x, y) is a real point on the P-256 curve. OpenSSL raises
      # during point construction for off-curve coordinates; on_curve? is
      # checked as well for runtimes that construct the point lazily.
      def self.valid_p256_point?(x_coordinate, y_coordinate)
        return false unless x_coordinate.bytesize == P256_COORDINATE_LENGTH
        return false unless y_coordinate.bytesize == P256_COORDINATE_LENGTH

        group = OpenSSL::PKey::EC::Group.new(P256_CURVE_NAME)
        point_bn = OpenSSL::BN.new(UNCOMPRESSED_FORM_INDICATOR + x_coordinate + y_coordinate, 2)
        point = OpenSSL::PKey::EC::Point.new(group, point_bn)

        point.on_curve? && !point.infinity?
      rescue OpenSSL::PKey::EC::Point::Error, OpenSSL::PKey::EC::Group::Error
        false
      end

      # @return [COSE::Key::EC2] a normalized ES256 P-256 COSE key
      # @raise [WebAuthn::PublicKey::UnrecognizedPublicKey]
      def self.to_cose_key(bytes)
        case detect(bytes)
        when :legacy_p256_point
          COSE::Key::EC2.new(
            alg: ES256_ALGORITHM_ID,
            crv: COSE::Key::Curve.by_name("P-256").id,
            x: bytes[1, P256_COORDINATE_LENGTH],
            y: bytes[1 + P256_COORDINATE_LENGTH, P256_COORDINATE_LENGTH]
          )
        when :cose_key
          cose_key = COSE::Key.deserialize(bytes)
          # Normalize an alg-less key (valid per RFC 8152) to the ES256 id so
          # the migrated envelope always carries an explicit algorithm.
          cose_key.alg = ES256_ALGORITHM_ID if cose_key.alg.nil?
          cose_key
        end
      end
    end
  end
end
