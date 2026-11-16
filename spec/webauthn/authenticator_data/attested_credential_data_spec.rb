# frozen_string_literal: true

require "spec_helper"

RSpec.describe WebAuthn::AuthenticatorData::AttestedCredentialData do
  let(:cose_key_data) { fake_cose_credential_key }
  let(:credential_key) { OpenSSL::PKey::EC.generate("prime256v1") }
  let(:cose_key) do
    COSE::Key::EC2.from_pkey(credential_key.public_key).tap { |key| key.alg = -7 }
  end

  def raw_attested_credential_data(options = {})
    options = {
      aaguid: SecureRandom.random_bytes(16),
      id: SecureRandom.random_bytes(16),
      public_key: cose_key_data
    }.merge(options)

    options[:aaguid] + [options[:id].length].pack("n*") + options[:id] + options[:public_key]
  end

  def deserialize(raw_data)
    described_class.deserialize(raw_data)
  end

  describe "#valid?" do
    it "returns false if public key is missing" do
      raw_data = raw_attested_credential_data(public_key: CBOR.encode(""))

      attested_credential_data = deserialize(raw_data)

      expect { attested_credential_data.valid? }.to raise_error(COSE::UnknownKeyType)
      expect { attested_credential_data.credential }.to raise_error(COSE::UnknownKeyType)
    end

    it "returns false if public key doesn't contain the alg parameter" do
      raw_data = raw_attested_credential_data(public_key: fake_cose_credential_key(algorithm: nil))

      attested_credential_data = deserialize(raw_data)

      expect(attested_credential_data.valid?).to be_falsy
      expect(attested_credential_data.credential).to eq(nil)
    end

    it "returns true if all data is present" do
      raw_data = raw_attested_credential_data(id: "this-is-a-credential-id")
      attested_credential_data = deserialize(raw_data)

      expect(attested_credential_data.valid?).to be_truthy
      expect(attested_credential_data.credential.id).to eq("this-is-a-credential-id")
      expect(attested_credential_data.credential.public_key).to eq(cose_key_data)
    end

    context "with a COSE key using non-shortest CBOR headers" do
      let(:canonical_public_key) { CborEncodingHelpers.encode_cose_key(cose_key) }
      let(:wide_public_key) { CborEncodingHelpers.encode_cose_key(cose_key, wide: true) }

      it "keeps the raw public key bytes intact" do
        raw_data = raw_attested_credential_data(public_key: wide_public_key)

        attested_credential_data = deserialize(raw_data)

        expect(wide_public_key.bytesize).to be > canonical_public_key.bytesize
        expect(attested_credential_data.valid?).to be_truthy
        expect(attested_credential_data.credential.public_key).to eq(wide_public_key)
        expect(attested_credential_data.length).to eq(raw_data.bytesize)
      end

      it "reconstructs the same public key point as the canonical encoding" do
        canonical = deserialize(raw_attested_credential_data(public_key: canonical_public_key))
        wide = deserialize(raw_attested_credential_data(public_key: wide_public_key))

        canonical_point = canonical.credential.public_key_object.public_key
        wide_point = wide.credential.public_key_object.public_key

        expect(wide_point.to_octet_string(:uncompressed)).to eq(canonical_point.to_octet_string(:uncompressed))
      end
    end

    context "with COSE map entries in a different order" do
      let(:canonical_public_key) { CborEncodingHelpers.encode_cose_key(cose_key) }
      let(:reordered_public_key) { CborEncodingHelpers.encode_cose_key(cose_key, reverse: true) }

      it "keeps the raw public key bytes intact" do
        raw_data = raw_attested_credential_data(public_key: reordered_public_key)

        attested_credential_data = deserialize(raw_data)

        expect(reordered_public_key).not_to eq(canonical_public_key)
        expect(attested_credential_data.credential.public_key).to eq(reordered_public_key)
        expect(attested_credential_data.length).to eq(raw_data.bytesize)
      end
    end

    context "with extra CBOR objects after the public key" do
      it "does not include them in the credential public key" do
        public_key = CborEncodingHelpers.encode_cose_key(cose_key)
        trailing_object = CBOR.encode("extension" => "value")
        raw_data = raw_attested_credential_data(public_key: public_key + trailing_object)

        attested_credential_data = deserialize(raw_data)

        expect(attested_credential_data.credential.public_key).to eq(public_key)
        expect(attested_credential_data.length).to eq(raw_data.bytesize - trailing_object.bytesize)
      end
    end

    context "when the public key is truncated" do
      it "raises a format error" do
        public_key = CborEncodingHelpers.encode_cose_key(cose_key)
        raw_data = raw_attested_credential_data(public_key: public_key.byteslice(0, public_key.bytesize - 1))

        attested_credential_data = deserialize(raw_data)

        expect { attested_credential_data.valid? }.to raise_error(WebAuthn::AttestedCredentialDataFormatError)
        expect { attested_credential_data.credential }.to raise_error(WebAuthn::AttestedCredentialDataFormatError)
      end
    end
  end
end
