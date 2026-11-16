# frozen_string_literal: true

require "cose/key"
require "json"
require "webauthn/public_key/format"

module WebAuthn
  # Versioned, self-describing on-disk representation of a stored credential
  # public key.
  #
  # Before this format existed, applications persisted one of two undocumented
  # binary blobs depending on the gem version:
  #
  #   * a 65 byte P-256 uncompressed point (legacy webauthn-ruby <= v1.11.0), or
  #   * a raw COSE_Key byte string.
  #
  # Neither carried any version marker. A CredentialRecord wraps the canonical
  # COSE_Key together with the version and enough metadata to prove that the
  # key identity did not change during migration.
  class CredentialRecord
    FORMAT_VERSION = 1
    KEY_FORMAT = "cose_key"
    CURVE_NAME = "P-256"

    class CorruptRecord < WebAuthn::Error; end

    # Builds a record from an already-validated COSE key.
    def self.from_cose_key(cose_key, public_key_bytes: cose_key.serialize)
      unless cose_key.is_a?(COSE::Key::EC2)
        raise ArgumentError, "CredentialRecord only wraps P-256 EC2 COSE keys"
      end

      new(
        public_key: public_key_bytes,
        alg: cose_key.alg,
        crv: CURVE_NAME
      )
    end

    # Decodes a serialized envelope and re-validates that the embedded public
    # key is a real P-256 ES256 credential.
    def self.deserialize(serialized)
      hash =
        begin
          parsed = JSON.parse(serialized)
          parsed.is_a?(Hash) ? parsed : raise
        rescue StandardError
          raise CorruptRecord, "credential record is not a JSON object"
        end

      new(
        public_key: decode_binary(hash["public_key"]),
        alg: hash["alg"],
        crv: hash["crv"],
        format_version: hash.fetch("format_version", FORMAT_VERSION),
        key_format: hash.fetch("key_format", KEY_FORMAT)
      )
    end

    attr_reader :public_key, :alg, :crv, :format_version, :key_format

    def initialize(public_key:, alg:, crv:, format_version: FORMAT_VERSION, key_format: KEY_FORMAT)
      @format_version = format_version
      @key_format = key_format
      @alg = alg
      @crv = crv
      @public_key = public_key.is_a?(String) ? public_key.b : public_key

      validate!
    end

    def cose_key
      @cose_key ||= COSE::Key.deserialize(@public_key)
    end

    def serialize
      JSON.generate(
        "format_version" => format_version,
        "key_format" => key_format,
        "alg" => alg,
        "crv" => crv,
        "public_key" => encode_binary(public_key)
      )
    end

    def to_h
      {
        format_version: format_version,
        key_format: key_format,
        alg: alg,
        crv: crv,
        public_key: public_key
      }
    end

    # Stable identity fingerprint of the underlying key (the uncompressed
    # P-256 point). Equal fingerprints across the legacy and migrated records
    # prove that the public key itself never changed.
    def key_fingerprint
      @key_fingerprint ||= begin
        point = cose_key.to_pkey.public_key
        OpenSSL::Digest::SHA256.hexdigest(point.to_octet_string(:uncompressed))
      end
    end

    private

    def validate!
      unless public_key.is_a?(String)
        raise CorruptRecord, "record is missing a binary public_key"
      end
      unless format_version == FORMAT_VERSION
        raise CorruptRecord, "unsupported format_version #{format_version.inspect}"
      end
      unless key_format == KEY_FORMAT
        raise CorruptRecord, "unsupported key_format #{key_format.inspect}"
      end
      unless alg == WebAuthn::PublicKey::Format::ES256_ALGORITHM_ID
        raise CorruptRecord, "unsupported alg #{alg.inspect}"
      end
      unless crv == CURVE_NAME
        raise CorruptRecord, "unsupported crv #{crv.inspect}"
      end

      detected = WebAuthn::PublicKey::Format.detect(public_key)
      unless detected == :cose_key
        raise CorruptRecord, "embedded public key is not a COSE_Key (#{detected.inspect})"
      end
    end

    def encode_binary(bytes)
      [bytes].pack("m0").tr("+/", "-_").delete("=")
    end

    def self.decode_binary(value)
      raise CorruptRecord, "record is missing public_key" unless value.is_a?(String)

      padded = value.tr("-_", "+/")
      padded = padded.ljust((padded.length + 3) & ~3, "=") unless padded.length % 4 == 0
      padded.unpack1("m0")
    rescue ArgumentError
      raise CorruptRecord, "public_key is not valid base64url"
    end
  end
end
