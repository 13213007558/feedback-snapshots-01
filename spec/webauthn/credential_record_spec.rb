# frozen_string_literal: true

require "spec_helper"
require "cbor"
require "webauthn/credential_record"
require "webauthn/public_key_migrator"

RSpec.describe WebAuthn::CredentialRecord do
  let(:ec_key) { OpenSSL::PKey::EC.generate("prime256v1") }
  let(:legacy_point) { ec_key.public_key.to_octet_string(:uncompressed) }
  let(:migration) { WebAuthn::PublicKeyMigrator.migrate(id: "x", public_key: legacy_point) }
  let(:record) { migration.record }

  describe ".from_cose_key" do
    it "builds a version 1 envelope" do
      expect(record.format_version).to eq(1)
      expect(record.key_format).to eq("cose_key")
      expect(record.alg).to eq(-7)
      expect(record.crv).to eq("P-256")
    end

    it "rejects a non-EC2 key" do
      rsa = COSE::Key::RSA.from_pkey(OpenSSL::PKey::RSA.new(1024))
      expect { described_class.from_cose_key(rsa) }.to raise_error(ArgumentError)
    end
  end

  describe "#serialize / .deserialize" do
    it "round-trips without changing the embedded key" do
      restored = described_class.deserialize(record.serialize)
      expect(restored.public_key).to eq(record.public_key)
      expect(restored.key_fingerprint).to eq(record.key_fingerprint)
      expect(restored.serialize).to eq(record.serialize)
    end

    it "stores the public key as base64url text" do
      parsed = JSON.parse(record.serialize)
      expect(parsed["public_key"]).not_to include("+", "/", "=")
    end

    it "rejects non-JSON input" do
      expect { described_class.deserialize("not-json") }
        .to raise_error(described_class::CorruptRecord)
    end

    it "rejects an unsupported format_version" do
      hash = JSON.parse(record.serialize).merge("format_version" => 99)
      expect { described_class.deserialize(JSON.generate(hash)) }
        .to raise_error(described_class::CorruptRecord, /format_version/)
    end

    it "rejects an unsupported alg" do
      hash = JSON.parse(record.serialize).merge("alg" => -35)
      expect { described_class.deserialize(JSON.generate(hash)) }
        .to raise_error(described_class::CorruptRecord, /alg/)
    end

    it "rejects an embedded key that is not a COSE_Key" do
      hash = JSON.parse(record.serialize)
      hash["public_key"] = WebAuthn::Encoders::Base64UrlEncoder.encode(legacy_point)
      expect { described_class.deserialize(JSON.generate(hash)) }
        .to raise_error(described_class::CorruptRecord, /COSE_Key/)
    end

    it "rejects a record missing the public key" do
      hash = JSON.parse(record.serialize)
      hash.delete("public_key")
      expect { described_class.deserialize(JSON.generate(hash)) }
        .to raise_error(described_class::CorruptRecord, /public_key/)
    end

    it "rejects a non-base64url public key" do
      hash = JSON.parse(record.serialize).merge("public_key" => "not base64!!!")
      expect { described_class.deserialize(JSON.generate(hash)) }
        .to raise_error(described_class::CorruptRecord, /base64url/)
    end

    it "rejects JSON that is not an object" do
      expect { described_class.deserialize(JSON.generate([1, 2, 3])) }
        .to raise_error(described_class::CorruptRecord, /JSON object/)
    end
  end

  describe "#key_fingerprint" do
    it "is the SHA256 of the uncompressed point" do
      expected = OpenSSL::Digest::SHA256.hexdigest(legacy_point)
      expect(record.key_fingerprint).to eq(expected)
    end
  end
end
