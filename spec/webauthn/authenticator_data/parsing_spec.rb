# frozen_string_literal: true

require "spec_helper"

RSpec.describe "AuthenticatorData parsing" do
  let(:rp_id_hash) { OpenSSL::Digest.digest("SHA256", "localhost") }
  let(:credential_id) { SecureRandom.random_bytes(16) }
  let(:aaguid) { SecureRandom.random_bytes(16) }
  let(:credential_key) { OpenSSL::PKey::EC.generate("prime256v1") }
  let(:cose_key) do
    COSE::Key::EC2.from_pkey(credential_key.public_key).tap { |key| key.alg = -7 }
  end

  def authenticator_data(flags:, public_key:, extension_bytes: nil)
    attested_credential_data =
      aaguid + [credential_id.bytesize].pack("n") + credential_id + public_key

    rp_id_hash + [flags].pack("C") + [0].pack("L>") + attested_credential_data + extension_bytes.to_s
  end

  def deserialize(data)
    WebAuthn::AuthenticatorData.deserialize(data)
  end

  describe "credential public key boundary" do
    let(:canonical_key) { CborEncodingHelpers.encode_cose_key(cose_key) }
    let(:wide_key) { CborEncodingHelpers.encode_cose_key(cose_key, wide: true) }

    it "preserves the exact raw public key bytes for canonical encodings" do
      data = authenticator_data(flags: 0x41, public_key: canonical_key)

      parsed = deserialize(data)

      expect(parsed.valid?).to be_truthy
      expect(parsed.credential.public_key).to eq(canonical_key)
      expect(parsed.data).to eq(data)
    end

    it "preserves non-shortest integer encodings instead of re-encoding the key" do
      data = authenticator_data(flags: 0x41, public_key: wide_key)

      parsed = deserialize(data)

      expect(wide_key.bytesize).to be > canonical_key.bytesize
      expect(parsed.valid?).to be_truthy
      expect(parsed.credential.public_key).to eq(wide_key)
      expect(parsed.credential.public_key.bytesize).to eq(wide_key.bytesize)
      expect(parsed.data).to eq(data)
    end

    it "accepts a COSE map whose entries are in a different order" do
      reordered_key = CborEncodingHelpers.encode_cose_key(cose_key, reverse: true)
      data = authenticator_data(flags: 0x41, public_key: reordered_key)

      parsed = deserialize(data)

      expect(reordered_key).not_to eq(canonical_key)
      expect(parsed.valid?).to be_truthy
      expect(parsed.credential.public_key).to eq(reordered_key)
    end

    context "when an extension map follows a non-shortest public key" do
      let(:extensions) { { "credProtect" => 2 } }
      let(:extension_bytes) { CBOR.encode(extensions) }

      it "does not classify the tail of the public key as extension data" do
        data = authenticator_data(flags: 0xC1, public_key: wide_key, extension_bytes: extension_bytes)

        parsed = deserialize(data)

        expect(parsed.valid?).to be_truthy
        expect(parsed.credential.public_key).to eq(wide_key)
        expect(parsed.extension_data).to eq(extensions)
      end

      it "does not include extension bytes in the credential public key" do
        data = authenticator_data(flags: 0xC1, public_key: canonical_key, extension_bytes: extension_bytes)

        parsed = deserialize(data)

        expect(parsed.credential.public_key).to eq(canonical_key)
        expect(parsed.credential.public_key).not_to end_with(extension_bytes)
      end
    end

    context "when extra CBOR objects follow the public key without an extension flag" do
      it "rejects the leftover bytes" do
        data = authenticator_data(
          flags: 0x41,
          public_key: canonical_key,
          extension_bytes: CBOR.encode("unexpected" => true)
        )

        parsed = deserialize(data)

        expect(parsed.valid?).to be_falsy
        expect(parsed.credential.public_key).to eq(canonical_key)
      end
    end
  end

  describe "extension data" do
    let(:public_key) { CborEncodingHelpers.encode_cose_key(cose_key) }

    it "accepts a complete extension map" do
      extensions = { "credProtect" => 2 }
      data = authenticator_data(flags: 0xC1, public_key: public_key, extension_bytes: CBOR.encode(extensions))

      parsed = deserialize(data)

      expect(parsed.valid?).to be_truthy
      expect(parsed.extension_data).to eq(extensions)
    end

    it "accepts an empty extension map" do
      data = authenticator_data(flags: 0xC1, public_key: public_key, extension_bytes: CBOR.encode({}))

      parsed = deserialize(data)

      expect(parsed.valid?).to be_truthy
      expect(parsed.extension_data).to eq({})
    end

    it "raises a format error when the extension flag is set but no data follows" do
      data = authenticator_data(flags: 0xC1, public_key: public_key)

      parsed = deserialize(data)

      expect(parsed.valid?).to be_falsy
      expect { parsed.extension_data }.to raise_error(WebAuthn::AuthenticatorDataFormatError)
    end

    it "raises a format error when the extension map is truncated" do
      data = authenticator_data(flags: 0xC1, public_key: public_key, extension_bytes: "\xa1\x61a".b)

      parsed = deserialize(data)

      expect(parsed.valid?).to be_falsy
      expect { parsed.extension_data }.to raise_error(WebAuthn::AuthenticatorDataFormatError)
    end

    it "raises a format error when a second CBOR object follows the extension map" do
      extension_bytes = CBOR.encode("credProtect" => 2) + CBOR.encode("extra" => true)
      data = authenticator_data(flags: 0xC1, public_key: public_key, extension_bytes: extension_bytes)

      parsed = deserialize(data)

      expect(parsed.valid?).to be_falsy
      expect { parsed.extension_data }.to raise_error(WebAuthn::AuthenticatorDataFormatError)
    end

    it "raises a format error when the extension value is not a map" do
      data = authenticator_data(flags: 0xC1, public_key: public_key, extension_bytes: CBOR.encode(["not", "a", "map"]))

      parsed = deserialize(data)

      expect(parsed.valid?).to be_falsy
      expect { parsed.extension_data }.to raise_error(WebAuthn::AuthenticatorDataFormatError)
    end

    it "accepts a legal indefinite-length extension map" do
      extension_bytes = "\xbf\x6bcredProtect\x02\xff".b
      data = authenticator_data(flags: 0xC1, public_key: public_key, extension_bytes: extension_bytes)

      parsed = deserialize(data)

      expect(parsed.valid?).to be_truthy
      expect(parsed.extension_data).to eq({ "credProtect" => 2 })
    end

    it "accepts a legal indefinite-length COSE public key map" do
      canonical_key = CborEncodingHelpers.encode_cose_key(cose_key)
      indefinite_key = "\xbf".b + canonical_key.byteslice(1..-1) + "\xff".b
      extensions = { "credProtect" => 2 }
      data = authenticator_data(flags: 0xC1, public_key: indefinite_key, extension_bytes: CBOR.encode(extensions))

      parsed = deserialize(data)

      expect(parsed.valid?).to be_truthy
      expect(parsed.credential.public_key).to eq(indefinite_key)
      expect(parsed.extension_data).to eq(extensions)
    end
  end

  describe "truncated data" do
    it "rejects a credential ID that overruns the buffer" do
      data = rp_id_hash + [0x41].pack("C") + [0].pack("L>") + aaguid + [100].pack("n") + "short".b

      parsed = deserialize(data)

      expect(parsed.valid?).to be_falsy
      expect { parsed.credential }.to raise_error(WebAuthn::AuthenticatorDataFormatError)
    end

    it "raises a format error when the base fields are incomplete" do
      expect { deserialize(rp_id_hash) }.to raise_error(WebAuthn::AuthenticatorDataFormatError)
    end
  end
end
