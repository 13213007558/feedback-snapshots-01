# frozen_string_literal: true

require "webauthn/credential_record"
require "webauthn/public_key/format"

module WebAuthn
  # Migrates stored credential public keys from the two historical formats
  # (a legacy P-256 uncompressed point, or a raw COSE_Key) to the versioned
  # {WebAuthn::CredentialRecord} envelope.
  #
  # Safety properties:
  #
  #   * A record is converted only after its coordinates, curve membership and
  #     algorithm are verified (see {WebAuthn::PublicKey::Format}); the leading
  #     0x04 byte is never trusted on its own.
  #   * The original bytes are returned unchanged so callers can keep them for
  #     rollback.
  #   * Migrating an already-migrated record, or migrating the same key twice,
  #     yields byte-identical output (idempotent).
  #   * Corrupt or unclassifiable records are returned in the +:failures+
  #     array of {#migrate_many} instead of being guessed as another algorithm.
  class PublicKeyMigrator
    # Result of migrating a single record.
    Result = Struct.new(:id, :source_format, :record, :original_public_key, :fingerprint, keyword_init: true)

    # A record that could not be migrated.
    Failure = Struct.new(:id, :reason, :message, :original_public_key, keyword_init: true)

    # @param id [Object] opaque identifier echoed back on the result/failure
    # @param public_key [String] the stored legacy point or COSE_Key bytes
    # @return [WebAuthn::PublicKeyMigrator::Result]
    # @raise [WebAuthn::PublicKey::UnrecognizedPublicKey] for a bad record;
    #   use {.migrate_many} to collect those instead.
    def self.migrate(id: nil, public_key:)
      new.migrate(id: id, public_key: public_key)
    end

    def self.migrate_many(records)
      new.migrate_many(records)
    end

    def migrate(id: nil, public_key:)
      bytes = normalize(public_key)
      source_format = WebAuthn::PublicKey::Format.detect(bytes)
      cose_key = WebAuthn::PublicKey::Format.to_cose_key(bytes)
      record = WebAuthn::CredentialRecord.from_cose_key(cose_key)

      Result.new(
        id: id,
        source_format: source_format,
        record: record,
        original_public_key: bytes,
        fingerprint: record.key_fingerprint
      )
    end

    # @param records [Enumerable] entries responding to, or convertible to,
    #   +[id, public_key]+ pairs.
    # @return [Hash] +{ results:, failures: }+
    def migrate_many(records)
      results = []
      failures = []

      records.each do |entry|
        id, public_key = extract(entry)
        results << migrate(id: id, public_key: public_key)
      rescue WebAuthn::PublicKey::UnrecognizedPublicKey => e
        failures << Failure.new(
          id: id,
          reason: e.reason,
          message: e.message,
          original_public_key: safe_binary(public_key)
        )
      rescue WebAuthn::CredentialRecord::CorruptRecord => e
        failures << Failure.new(
          id: id,
          reason: :corrupt_record,
          message: e.message,
          original_public_key: safe_binary(public_key)
        )
      end

      { results: results, failures: failures }
    end

    private

    def extract(entry)
      case entry
      when Hash
        [entry[:id] || entry["id"], entry[:public_key] || entry["public_key"]]
      else
        entry
      end
    end

    def normalize(public_key)
      raise WebAuthn::PublicKey::UnrecognizedPublicKey.new(
        "public key is empty", reason: :empty
      ) if public_key.nil? || (public_key.respond_to?(:empty?) && public_key.empty?)
      unless public_key.is_a?(String)
        raise WebAuthn::PublicKey::UnrecognizedPublicKey.new(
          "public key is not a binary string", reason: :not_binary
        )
      end

      public_key.b
    end

    def safe_binary(public_key)
      public_key.is_a?(String) ? public_key.b : public_key
    end
  end
end
