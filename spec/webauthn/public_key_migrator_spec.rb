# frozen_string_literal: true

require "spec_helper"
require "cbor"
require "webauthn/public_key_migrator"

RSpec.describe WebAuthn::PublicKeyMigrator do
  let(:ec_key) { OpenSSL::PKey::EC.generate("prime256v1") }
  let(:legacy_point) { ec_key.public_key.to_octet_string(:uncompressed) }
  let(:cose_blob) do
    key = COSE::Key::EC2.from_pkey(ec_key.public_key)
    key.alg = -7
    key.serialize
  end

  describe ".migrate" do
    it "migrates a legacy point and records its source format" do
      result = described_class.migrate(id: "1", public_key: legacy_point)
      expect(result.source_format).to eq(:legacy_p256_point)
      expect(result.record).to be_a(WebAuthn::CredentialRecord)
      expect(result.original_public_key).to eq(legacy_point)
    end

    it "migrates a COSE key and records its source format" do
      result = described_class.migrate(id: "1", public_key: cose_blob)
      expect(result.source_format).to eq(:cose_key)
      expect(result.original_public_key).to eq(cose_blob)
    end

    it "produces identical envelopes for the two forms of the same key" do
      from_point = described_class.migrate(id: "1", public_key: legacy_point)
      from_cose = described_class.migrate(id: "1", public_key: cose_blob)
      expect(from_point.record.serialize).to eq(from_cose.record.serialize)
      expect(from_point.fingerprint).to eq(from_cose.fingerprint)
    end

    it "preserves the public key identity (fingerprint equals the point hash)" do
      result = described_class.migrate(id: "1", public_key: legacy_point)
      expect(result.fingerprint).to eq(OpenSSL::Digest::SHA256.hexdigest(legacy_point))
    end

    it "is idempotent: migrating again yields byte-identical output" do
      first = described_class.migrate(id: "1", public_key: legacy_point)
      embedded = WebAuthn::CredentialRecord.deserialize(first.record.serialize).public_key
      second = described_class.migrate(id: "1", public_key: embedded)
      expect(second.record.serialize).to eq(first.record.serialize)
    end

    it "raises for an off-curve point instead of guessing" do
      off_curve = legacy_point.dup
      off_curve[-1] = (off_curve[-1].ord ^ 0xFF).chr
      expect { described_class.migrate(id: "bad", public_key: off_curve) }
        .to raise_error(WebAuthn::PublicKey::UnrecognizedPublicKey) do |error|
          expect(error.reason).to eq(:point_not_on_curve)
        end
    end

    it "raises for malformed COSE input" do
      expect { described_class.migrate(id: "bad", public_key: "\xA5\x01\x02junk".b) }
        .to raise_error(WebAuthn::PublicKey::UnrecognizedPublicKey) do |error|
          expect(error.reason).to eq(:malformed_cose)
        end
    end
  end

  describe ".migrate_many" do
    let(:off_curve) do
      bytes = legacy_point.dup
      bytes[-1] = (bytes[-1].ord ^ 0xFF).chr
      bytes
    end
    let(:malformed) { "\xA5\x01\x02junk".b }

    let(:records) do
      [
        { id: "legacy", public_key: legacy_point },
        { id: "cose", public_key: cose_blob },
        { id: "off-curve", public_key: off_curve },
        { id: "malformed", public_key: malformed }
      ]
    end

    it "returns valid results and reports corrupt ones separately" do
      outcome = described_class.migrate_many(records)
      expect(outcome[:results].map(&:id)).to contain_exactly("legacy", "cose")
      expect(outcome[:failures].map(&:id)).to contain_exactly("off-curve", "malformed")
    end

    it "attaches precise failure reasons and keeps the original bytes" do
      outcome = described_class.migrate_many(records)
      failures = outcome[:failures].each_with_object({}) { |f, h| h[f.id] = f }
      expect(failures["off-curve"].reason).to eq(:point_not_on_curve)
      expect(failures["off-curve"].original_public_key).to eq(off_curve)
      expect(failures["malformed"].reason).to eq(:malformed_cose)
      expect(failures["malformed"].original_public_key).to eq(malformed)
    end

    it "does not mutate the good records' original bytes" do
      outcome = described_class.migrate_many(records)
      legacy = outcome[:results].find { |r| r.id == "legacy" }
      expect(legacy.original_public_key).to eq(legacy_point)
    end
  end

  describe "login compatibility during the transition" do
    let(:verification_data) { SecureRandom.random_bytes(64) }
    let(:signature) { ec_key.sign("SHA256", verification_data) }

    it "verifies one authenticator signature under both legacy and COSE forms" do
      expect(WebAuthn::PublicKey.deserialize(legacy_point).verify(signature, verification_data)).to be(true)
      expect(WebAuthn::PublicKey.deserialize(cose_blob).verify(signature, verification_data)).to be(true)
    end

    it "verifies the same signature under the migrated envelope key" do
      result = described_class.migrate(id: "1", public_key: legacy_point)
      migrated_bytes = WebAuthn::CredentialRecord.deserialize(result.record.serialize).public_key
      expect(WebAuthn::PublicKey.deserialize(migrated_bytes).verify(signature, verification_data)).to be(true)
    end
  end
end
