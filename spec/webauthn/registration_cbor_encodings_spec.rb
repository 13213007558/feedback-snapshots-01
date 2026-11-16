# frozen_string_literal: true

require "spec_helper"

RSpec.describe "Registration with equivalent CBOR key encodings" do
  let(:origin) { "http://localhost" }
  let(:rp_id) { "localhost" }
  let(:challenge) { WebAuthn.standard_encoder.encode(SecureRandom.random_bytes(32)) }
  let(:client_data_json) do
    { type: "webauthn.create", challenge: challenge, origin: origin }.to_json
  end
  let(:client_data_hash) { OpenSSL::Digest::SHA256.digest(client_data_json) }
  let(:credential_id) { SecureRandom.random_bytes(16) }
  let(:credential_key) { OpenSSL::PKey::EC.generate("prime256v1") }
  let(:cose_key) do
    COSE::Key::EC2.from_pkey(credential_key.public_key).tap { |key| key.alg = -7 }
  end

  let(:canonical_public_key) { CborEncodingHelpers.encode_cose_key(cose_key) }
  let(:wide_public_key) { CborEncodingHelpers.encode_cose_key(cose_key, wide: true) }

  before do
    WebAuthn.configuration.allowed_origins = [origin]
  end

  def registration_credential(public_key, extensions: nil, extension_bytes: nil, extension_data_included: false)
    extension_bytes ||= CBOR.encode(extensions) if extensions
    flags = 0x41 # user present + attested credential data
    flags |= 0x80 if extension_bytes || extension_data_included

    attested_credential_data =
      ("\0" * 16) + [credential_id.bytesize].pack("n") + credential_id + public_key

    authenticator_data = OpenSSL::Digest::SHA256.digest(rp_id) + [flags].pack("C") + [0].pack("L>")

    if extension_bytes
      authenticator_data += attested_credential_data + extension_bytes
    else
      authenticator_data += attested_credential_data
    end

    signature = credential_key.sign("SHA256", authenticator_data + client_data_hash)

    attestation_object = CBOR.encode(
      "fmt" => "packed",
      "attStmt" => { "alg" => -7, "sig" => signature },
      "authData" => authenticator_data
    )

    {
      "type" => "public-key",
      "id" => WebAuthn.standard_encoder.encode(credential_id),
      "rawId" => WebAuthn.standard_encoder.encode(credential_id),
      "clientExtensionResults" => {},
      "response" => {
        "attestationObject" => WebAuthn.standard_encoder.encode(attestation_object),
        "clientDataJSON" => WebAuthn.standard_encoder.encode(client_data_json),
      },
    }
  end

  def assertion_credential(extensions: nil)
    flags = 0x01 # user present
    flags |= 0x80 if extensions

    authenticator_data = OpenSSL::Digest::SHA256.digest(rp_id) + [flags].pack("C") + [1].pack("L>")
    authenticator_data += CBOR.encode(extensions) if extensions

    assertion_client_data_json =
      { type: "webauthn.get", challenge: challenge, origin: origin }.to_json
    signature =
      credential_key.sign("SHA256", authenticator_data + OpenSSL::Digest::SHA256.digest(assertion_client_data_json))

    {
      "type" => "public-key",
      "id" => WebAuthn.standard_encoder.encode(credential_id),
      "rawId" => WebAuthn.standard_encoder.encode(credential_id),
      "clientExtensionResults" => {},
      "response" => {
        "authenticatorData" => WebAuthn.standard_encoder.encode(authenticator_data),
        "clientDataJSON" => WebAuthn.standard_encoder.encode(assertion_client_data_json),
        "signature" => WebAuthn.standard_encoder.encode(signature),
      },
    }
  end

  it "verifies canonically encoded and non-shortest encoded keys from the same credential key" do
    canonical = WebAuthn::Credential.from_create(registration_credential(canonical_public_key))
    wide = WebAuthn::Credential.from_create(registration_credential(wide_public_key))

    expect(canonical.verify(challenge)).to be_truthy
    expect(wide.verify(challenge)).to be_truthy

    canonical_bytes = WebAuthn.standard_encoder.decode(canonical.public_key)
    wide_bytes = WebAuthn.standard_encoder.decode(wide.public_key)

    expect(canonical_bytes).to eq(canonical_public_key)
    expect(wide_bytes).to eq(wide_public_key)
    expect(wide_bytes.bytesize).to be > canonical_bytes.bytesize

    canonical_pkey = COSE::Key.deserialize(canonical_bytes).to_pkey
    wide_pkey = COSE::Key.deserialize(wide_bytes).to_pkey

    expect(wide_pkey.public_key.to_octet_string(:uncompressed))
      .to eq(canonical_pkey.public_key.to_octet_string(:uncompressed))
  end

  it "verifies registration when extensions follow a non-shortest encoded key" do
    extensions = { "credProtect" => 2 }
    credential = WebAuthn::Credential.from_create(registration_credential(wide_public_key, extensions: extensions))

    expect(credential.verify(challenge)).to be_truthy

    parsed = credential.response.authenticator_data
    expect(parsed.credential.public_key).to eq(wide_public_key)
    expect(parsed.extension_data).to eq(extensions)
  end

  it "rejects registration when the public key is truncated" do
    truncated = wide_public_key.byteslice(0, wide_public_key.bytesize - 1)
    credential = WebAuthn::Credential.from_create(registration_credential(truncated))

    expect { credential.verify(challenge) }
      .to raise_error(WebAuthn::AuthenticatorDataVerificationError)
  end

  it "rejects registration when a complete extension map is followed by a second object" do
    extension_bytes = CBOR.encode("credProtect" => 2) + CBOR.encode("extra" => true)
    credential = WebAuthn::Credential.from_create(
      registration_credential(wide_public_key, extension_bytes: extension_bytes)
    )

    expect { credential.verify(challenge) }
      .to raise_error(WebAuthn::AuthenticatorDataVerificationError)
  end

  it "rejects registration when extension data is declared but missing" do
    credential = WebAuthn::Credential.from_create(
      registration_credential(canonical_public_key, extension_data_included: true)
    )

    expect { credential.verify(challenge) }
      .to raise_error(WebAuthn::AuthenticatorDataVerificationError)
  end

  describe "assertions" do
    let(:credential_public_key) { WebAuthn.standard_encoder.encode(canonical_public_key) }

    it "verifies an assertion whose authenticatorData is signed verbatim" do
      assertion = WebAuthn::Credential.from_get(assertion_credential)

      expect(
        assertion.verify(challenge, public_key: credential_public_key, sign_count: 0)
      ).to be_truthy
    end

    it "verifies an assertion carrying extension data without folding it into the signed bytes" do
      assertion = WebAuthn::Credential.from_get(assertion_credential(extensions: { "credProtect" => 2 }))

      expect(
        assertion.verify(challenge, public_key: credential_public_key, sign_count: 0)
      ).to be_truthy
      expect(assertion.authenticator_extension_outputs).to eq({ "credProtect" => 2 })
    end

    it "rejects an assertion whose signature covers different authData bytes" do
      assertion = WebAuthn::Credential.from_get(assertion_credential)
      tampered = assertion_credential
      tampered["response"]["signature"] = WebAuthn.standard_encoder.encode(
        credential_key.sign("SHA256", "other data")
      )
      credential = WebAuthn::Credential.from_get(tampered)

      expect { credential.verify(challenge, public_key: credential_public_key, sign_count: 0) }
        .to raise_error(WebAuthn::SignatureVerificationError)
    end
  end
end
