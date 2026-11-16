# frozen_string_literal: true

require "spec_helper"
require "json"
require "webauthn/fake_client"
require "webauthn/relying_party"

# Compatibility matrix for moving credential storage from :base64 to :base64url.
#
# Two different encodings live in this library and must not be conflated:
#
# * protocol fields (browser <-> RP): the WebAuthn spec fixes these to unpadded
#   base64url. `PublicKeyCredential#id` is verified with WebAuthn.standard_encoder
#   and client data challenges are decoded with it as well, regardless of
#   `WebAuthn.configuration.encoding` / `RelyingParty#encoding`.
# * storage fields (RP <-> database): `rawId`, `clientDataJSON`,
#   `attestationObject`, `authenticatorData`, `signature`, `userHandle` input and
#   the values exposed as `Credential#public_key` / `Credential#user_handle`
#   follow the RP encoder, which is what a Rails app would persist.
#   `allowCredentials` descriptors are protocol values even though the storage
#   column (`Credential#id`) is passed to `options_for_get(allow:)`.
RSpec.describe "encoding compatibility" do
  # Bytes chosen to exercise zero bytes, high-bit bytes and non-ASCII bytes.
  let(:credential_id) do
    [0x00, 0xFF, 0x80, 0xC3, 0xA9, 0x01, 0x00, 0xFE, 0x7F, 0x80, 0x81, 0x82, 0x00, 0xA0, 0xFF, 0x10].pack("C*")
  end
  let(:challenge_bytes) do
    ([0x00, 0xFF, 0x80, 0xC3, 0xA9, 0xFE, 0x7F] * 5)[0, 32].pack("C*")
  end
  let(:user_handle_bytes) { [0x00, 0xC3, 0xA9, 0xFF, 0x80].pack("C*") }

  # Fixed P-256 material, including 0x00 and bytes >= 0x80 in both coordinates.
  let(:credential_key) do
    OpenSSL::PKey.read(<<~PEM)
      -----BEGIN EC PRIVATE KEY-----
      MHcCAQEEICN8DSPNEiXUTkRzL8uAsBtFiBpBzUAui/2Mf/rkPdu/oAoGCCqGSM49
      AwEHoUQDQgAEsQCrHN+chdV06bXtVIYfyWP2WZP7V79GCeR2zqeuW2xmIGp2ZmQE
      9CjmMgDXSVpW0U0003Jsw01w9XhC0NVZ+A==
      -----END EC PRIVATE KEY-----
    PEM
  end

  let(:cose_public_key) do
    [
      "a503262001215820b100ab1cdf9c85d574e9b5ed54861fc963f65993fb57bf4609e476cea7ae5b6c010222582066" \
      "206a76666404f428e63200d7495a56d14d34d3726cc34d70f57842d0d559f8"
    ].pack("H*")
  end

  let(:other_cose_public_key) do
    [
      "a503262001215820e874e77b9c57579d5cce18ea7339e9692bf8ebc27773c7738b4739c3edf3c2fc0102225820" \
      "105ef0e9140a92647d4f01ea3bda72b0b8aac4fce9a005e41f766f007a04f3c6"
    ].pack("H*")
  end

  # FakeAuthenticator generates random credentials; pin them so both runs use
  # exactly the same credential ID and key material.
  let(:authenticator) do
    WebAuthn::FakeAuthenticator.new.tap do |fake|
      allow(fake).to receive(:new_credential).and_return([credential_id, credential_key, 0])
    end
  end

  def relying_party_for(encoding)
    WebAuthn::RelyingParty.new(
      allowed_origins: ["https://app.example.test"],
      id: "app.example.test",
      name: "Example",
      encoding: encoding
    )
  end

  def fake_client_for(encoding)
    WebAuthn::FakeClient.new(
      "https://app.example.test",
      authenticator: authenticator,
      encoding: encoding
    )
  end

  def creation_options_for(rp)
    rp.options_for_registration(user: { id: user_handle_bytes, name: "user" }).tap do |options|
      allow(options).to receive(:raw_challenge).and_return(challenge_bytes)
    end
  end

  def request_options_for(rp, allow_ids: [])
    rp.options_for_authentication(allow: allow_ids).tap do |options|
      allow(options).to receive(:raw_challenge).and_return(challenge_bytes)
    end
  end

  def stored_record(credential)
    {
      "id" => credential.id,
      "public_key" => credential.public_key,
      "sign_count" => credential.sign_count.to_i
    }
  end

  # Simulates the application's persistence layer. JSON is what a database
  # text column does; Marshal is the binary-column / NullEncoder path.
  def persist_and_reload(record, encoding)
    if encoding
      JSON.parse(JSON.generate(record))
    else
      Marshal.load(Marshal.dump(record))
    end
  end

  def register(encoding)
    rp = relying_party_for(encoding)
    client = fake_client_for(encoding)
    options = creation_options_for(rp)
    raw_credential = client.create(challenge: options.challenge, rp_id: rp.id)

    [rp, client, options, raw_credential, rp.verify_registration(raw_credential, options.challenge)]
  end

  def authenticate(rp:, client:, record:, sign_count:)
    options = request_options_for(rp, allow_ids: [record["id"]])
    raw_assertion = client.get(
      challenge: options.challenge,
      rp_id: rp.id,
      allow_credentials: [record["id"]],
      user_handle: user_handle_bytes,
      sign_count: sign_count
    )
    assertion = WebAuthn::Credential.from_get(raw_assertion, relying_party: rp)
    assertion.verify(options.challenge, public_key: record["public_key"], sign_count: record["sign_count"])

    assertion
  end

  shared_examples "a registration and authentication ceremony" do
    it "keeps the browser id in protocol base64url while storage follows the RP encoder" do
      rp, client, options, raw_credential, credential = register(encoding)

      expected_protocol_id = WebAuthn::Encoders::Base64UrlEncoder.encode(credential_id)
      expect(raw_credential["id"]).to eq(expected_protocol_id)
      expect(credential.id).to eq(expected_protocol_id)

      if encoding
        expect(raw_credential["rawId"]).to eq(rp.encoder.encode(credential_id))
        expect(credential.raw_id).to eq(credential_id)
        expect(credential.public_key).to eq(rp.encoder.encode(cose_public_key))
        expect(credential.public_key.encoding).not_to eq(Encoding::BINARY)
      else
        expect(raw_credential["rawId"]).to eq(credential_id)
        expect(credential.raw_id).to eq(credential_id)
        expect(credential.public_key).to eq(cose_public_key)
        expect(credential.public_key.encoding).to eq(Encoding::BINARY)
      end

      record = persist_and_reload(stored_record(credential), encoding)
      expect(record["id"]).to eq(expected_protocol_id)
      expect(record["public_key"]).to eq(credential.public_key)

      assertion = authenticate(rp: rp, client: client, record: record, sign_count: 1)
      expect(assertion.id).to eq(expected_protocol_id)
      expect(assertion.raw_id).to eq(credential_id)
      expect(assertion.sign_count).to eq(1)
    end

    it "does not decode an already-decoded stored value twice" do
      rp, _client, _options, _raw_credential, credential = register(encoding)

      stored_public_key = credential.public_key
      if encoding
        decoded_once = rp.encoder.decode(stored_public_key)
        expect(decoded_once).to eq(cose_public_key)
        # Encoding the stored string again and decoding it yields a different
        # byte string (the original encoded text), which is malformed COSE.
        double_decoded = rp.encoder.decode(rp.encoder.encode(stored_public_key))
        expect(double_decoded).not_to eq(cose_public_key)
        expect { WebAuthn::PublicKey.deserialize(double_decoded) }
          .to raise_error(COSE::MalformedKeyError)
      else
        expect(stored_public_key).to eq(cose_public_key)
      end

      # JSON serialization must not re-encode the stored string.
      record = persist_and_reload(stored_record(credential), encoding)
      expect(record["public_key"]).to eq(stored_public_key)

      # The id is already the protocol string; decoding it twice is not a
      # supported operation.
      decoded_id = WebAuthn.standard_encoder.decode(record["id"])
      expect(decoded_id).to eq(credential_id)
      expect { WebAuthn.standard_encoder.decode(decoded_id) }
        .to raise_error(ArgumentError, "invalid base64")
    end
  end

  context "with :base64url storage encoding" do
    let(:encoding) { :base64url }

    it_behaves_like "a registration and authentication ceremony"
  end

  context "with :base64 storage encoding" do
    let(:encoding) { :base64 }

    it_behaves_like "a registration and authentication ceremony"
  end

  context "with NullEncoder storage encoding" do
    let(:encoding) { false }

    it_behaves_like "a registration and authentication ceremony"

    it "rejects a JSON persistence attempt at the storage boundary" do
      _rp, _client, _options, _raw_credential, credential = register(encoding)
      record = stored_record(credential)

      expect(record["public_key"].encoding).to eq(Encoding::BINARY)
      expect { JSON.generate(record) }.to raise_error(JSON::GeneratorError)
    end
  end

  describe "protocol fields are independent of the RP encoder" do
    it "uses unpadded base64url for the id even when the RP uses :base64" do
      rp = relying_party_for(:base64)
      client = fake_client_for(:base64)
      options = creation_options_for(rp)
      raw_credential = client.create(challenge: options.challenge, rp_id: rp.id)

      protocol_id = WebAuthn::Encoders::Base64UrlEncoder.encode(credential_id)
      encoded_storage_id = WebAuthn::Encoders::Base64Encoder.encode(credential_id)

      expect(raw_credential["id"]).to eq(protocol_id)
      expect(raw_credential["id"]).not_to eq(encoded_storage_id)
      expect(raw_credential["rawId"]).to eq(encoded_storage_id)
      expect(WebAuthn.standard_encoder.decode(raw_credential["id"])).to eq(credential_id)
      expect { WebAuthn::Encoders::Base64Encoder.decode(raw_credential["id"]) }
        .to raise_error(ArgumentError, "invalid base64")

      credential = rp.verify_registration(raw_credential, options.challenge)
      expect(credential.id).to eq(protocol_id)
    end

    it "ignores the RP encoding when checking ClientData#challenge" do
      rp = relying_party_for(:base64)
      client = fake_client_for(:base64)
      options = creation_options_for(rp)
      raw_credential = client.create(challenge: options.challenge, rp_id: rp.id)
      credential = rp.verify_registration(raw_credential, options.challenge)

      client_data_json = rp.encoder.decode(raw_credential["response"]["clientDataJSON"])
      protocol_challenge = JSON.parse(client_data_json)["challenge"]
      expect(protocol_challenge).to eq(WebAuthn::Encoders::Base64UrlEncoder.encode(challenge_bytes))
      expect(protocol_challenge).not_to eq(WebAuthn::Encoders::Base64Encoder.encode(challenge_bytes))

      client_data = WebAuthn::ClientData.new(client_data_json)
      expect(client_data.challenge).to eq(challenge_bytes)
      expect(credential.sign_count.to_i).to eq(0)
    end

    it "treats allowCredentials ids as protocol values when the stored record uses :base64" do
      rp, client, _options, _raw_credential, credential = register(:base64)
      record = persist_and_reload(stored_record(credential), :base64)

      options = request_options_for(rp, allow_ids: [record["id"]])
      expect(options.allow_credentials).to eq([{ type: "public-key", id: record["id"] }])
      expect(options.allow_credentials.first[:id]).to eq(WebAuthn::Encoders::Base64UrlEncoder.encode(credential_id))

      raw_assertion = client.get(
        challenge: options.challenge,
        rp_id: rp.id,
        allow_credentials: [record["id"]],
        sign_count: 1
      )
      expect(raw_assertion["id"]).to eq(record["id"])
    end

    it "keeps the browser id meaning stable across encoders" do
      rp = relying_party_for(:base64)
      client = fake_client_for(:base64)
      options = creation_options_for(rp)
      raw_credential = client.create(challenge: options.challenge, rp_id: rp.id)

      protocol_id = raw_credential["id"]
      base64_id = WebAuthn::Encoders::Base64Encoder.encode(credential_id)

      # The protocol decoder is lenient with padding, so both spellings still
      # mean the same raw credential ID.
      expect(WebAuthn.standard_encoder.decode(protocol_id)).to eq(credential_id)
      expect(WebAuthn.standard_encoder.decode(base64_id)).to eq(credential_id)

      # The storage decoder is not lenient in this direction: a base64url id in
      # a base64 column is a storage-boundary error, not an id mismatch.
      expect { WebAuthn::Encoders::Base64Encoder.decode(protocol_id) }
        .to raise_error(ArgumentError, "invalid base64")

      credential = rp.verify_registration(raw_credential, options.challenge)
      expect(credential.id).to eq(protocol_id)
    end
  end

  describe "protocol failures are distinguishable from storage failures" do
    let(:encoding) { :base64 }
    let(:rp) { relying_party_for(encoding) }
    let(:client) { fake_client_for(encoding) }
    let(:options) { creation_options_for(rp) }
    let(:raw_credential) { client.create(challenge: options.challenge, rp_id: rp.id) }

    it "raises ChallengeVerificationError only for a wrong challenge in the expected storage encoding" do
      credential = rp.verify_registration(raw_credential, options.challenge)

      wrong_challenge = rp.encoder.encode(challenge_bytes + "x")
      expectation = WebAuthn::Credential.from_create(raw_credential, relying_party: rp)

      expect { expectation.verify(wrong_challenge) }
        .to raise_error(WebAuthn::ChallengeVerificationError)

      # A protocol-encoded challenge passed where the RP encoder is expected
      # fails at the storage boundary first, not as a challenge mismatch.
      protocol_challenge = WebAuthn::Encoders::Base64UrlEncoder.encode(challenge_bytes)
      expect { expectation.verify(protocol_challenge) }
        .to raise_error(ArgumentError, "invalid base64")
      expect(credential.id).to eq(WebAuthn::Encoders::Base64UrlEncoder.encode(credential_id))
    end

    it "raises ArgumentError when a base64url-stored public key is read with the :base64 encoder" do
      _rp, _client, _options, _raw_credential, credential = register(:base64url)
      record = stored_record(credential)

      expect do
        rp.encoder.decode(record["public_key"])
      end.to raise_error(ArgumentError, "invalid base64")
    end

    it "raises COSE::MalformedKeyError when a stored public key is decoded twice" do
      _rp, _client, _options, _raw_credential, credential = register(:base64)
      record = stored_record(credential)

      decoded_once = rp.encoder.decode(record["public_key"])
      double_decoded = rp.encoder.decode(rp.encoder.encode(record["public_key"]))

      expect(decoded_once).to eq(cose_public_key)
      expect(double_decoded).to eq(record["public_key"])
      expect { WebAuthn::PublicKey.deserialize(double_decoded) }
        .to raise_error(COSE::MalformedKeyError)
    end

    it "raises SignatureVerificationError only when the stored key is valid but belongs to another credential" do
      _rp, _client, _options, _raw_credential, credential = register(encoding)
      other_public_key = rp.encoder.encode(other_cose_public_key)
      record = persist_and_reload(
        { "id" => credential.id,
          "public_key" => other_public_key,
          "sign_count" => credential.sign_count.to_i },
        encoding
      )
      expect(rp.encoder.decode(record["public_key"])).to eq(other_cose_public_key)

      expect { authenticate(rp: rp, client: client, record: record, sign_count: 1) }
        .to raise_error(WebAuthn::SignatureVerificationError)
    end
  end

  describe "migrating existing records from :base64 to :base64url" do
    it "authenticates a record persisted before the switch" do
      old_rp = relying_party_for(:base64)
      old_client = fake_client_for(:base64)
      old_options = creation_options_for(old_rp)
      old_raw_credential = old_client.create(challenge: old_options.challenge, rp_id: old_rp.id)
      old_credential = old_rp.verify_registration(old_raw_credential, old_options.challenge)
      old_record = persist_and_reload(stored_record(old_credential), :base64)
      expect(old_record["public_key"]).to end_with("=")

      new_rp = relying_party_for(:base64url)
      new_client = fake_client_for(:base64url)
      new_record = {
        "id" => old_record["id"],
        "public_key" => WebAuthn::Encoders::Base64UrlEncoder.encode(cose_public_key),
        "sign_count" => old_record["sign_count"]
      }

      expect(old_record["id"]).to eq(WebAuthn::Encoders::Base64UrlEncoder.encode(credential_id))
      expect(old_record["public_key"]).not_to eq(new_record["public_key"])
      expect(WebAuthn::Encoders::Base64UrlEncoder.decode(new_record["public_key"])).to eq(cose_public_key)

      assertion = authenticate(rp: new_rp, client: new_client, record: new_record, sign_count: 1)
      expect(assertion.id).to eq(old_record["id"])
      expect(assertion.sign_count).to eq(1)
    end

    it "reads unrewritten :base64 stored keys through the :base64url encoder" do
      _old_rp, _old_client, _old_options, _old_raw_credential, old_credential = register(:base64)
      old_record = stored_record(old_credential)
      expect(old_record["public_key"]).to end_with("=")

      new_rp = relying_party_for(:base64url)
      new_client = fake_client_for(:base64url)

      # The base64url decoder also accepts the standard alphabet and padding,
      # so old records remain readable during a gradual migration.
      expect(WebAuthn::Encoders::Base64UrlEncoder.decode(old_record["public_key"])).to eq(cose_public_key)

      assertion = authenticate(rp: new_rp, client: new_client, record: old_record, sign_count: 1)
      expect(assertion.id).to eq(WebAuthn::Encoders::Base64UrlEncoder.encode(credential_id))
      expect(assertion.sign_count).to eq(1)
    end
  end

  describe "padding and the NullEncoder binary entry point" do
    it "accepts padded and unpadded protocol base64url for the browser id" do
      rp = relying_party_for(:base64url)
      client = fake_client_for(:base64url)
      options = creation_options_for(rp)
      raw_credential = client.create(challenge: options.challenge, rp_id: rp.id)

      unpadded_id = raw_credential["id"]
      padded_id = unpadded_id + ("=" * ((4 - unpadded_id.length % 4) % 4))

      expect(padded_id).to end_with("==")
      expect(WebAuthn.standard_encoder.decode(padded_id)).to eq(credential_id)
      expect(WebAuthn.standard_encoder.decode(padded_id)).to eq(WebAuthn.standard_encoder.decode(unpadded_id))

      credential = WebAuthn::Credential.from_create(raw_credential.merge("id" => padded_id), relying_party: rp)
      expect(credential.verify(options.challenge)).to be(true)
    end

    it "rejects unpadded base64 at the storage boundary" do
      padded = WebAuthn::Encoders::Base64Encoder.encode(credential_id)
      unpadded = padded.delete("=")

      expect(WebAuthn::Encoders::Base64Encoder.decode(padded)).to eq(credential_id)
      expect { WebAuthn::Encoders::Base64Encoder.decode(unpadded) }.to raise_error(ArgumentError, "invalid base64")
      expect(WebAuthn::Encoders::Base64UrlEncoder.decode(unpadded)).to eq(credential_id)
    end

    it "passes binary bytes through the FakeClient when encoding is false" do
      rp = relying_party_for(false)
      client = fake_client_for(false)
      options = creation_options_for(rp)
      raw_credential = client.create(challenge: options.challenge, rp_id: rp.id)

      expect(raw_credential["rawId"]).to eq(credential_id)
      expect(raw_credential["rawId"].encoding).to eq(Encoding::BINARY)

      credential = rp.verify_registration(raw_credential, options.challenge)
      record = persist_and_reload(stored_record(credential), false)

      expect(record["public_key"]).to eq(cose_public_key)
      expect(record["id"]).to eq(WebAuthn::Encoders::Base64UrlEncoder.encode(credential_id))

      # NullEncoder is a binary pass-through: no encode/decode round trip, and
      # the bytes must not be fed to a text encoder.
      expect(rp.encoder.decode(record["public_key"])).to eq(cose_public_key)
      expect(rp.encoder.encode(record["public_key"])).to eq(cose_public_key)
      expect { WebAuthn::Encoders::Base64UrlEncoder.decode(record["public_key"]) }
        .to raise_error(ArgumentError, "invalid base64")
      expect { WebAuthn::Encoders::Base64Encoder.decode(record["public_key"]) }
        .to raise_error(ArgumentError, "invalid base64")
    end
  end
end
