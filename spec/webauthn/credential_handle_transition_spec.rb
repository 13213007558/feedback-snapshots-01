# frozen_string_literal: true

require "spec_helper"

require "webauthn/fake_authenticator"
require "webauthn/fake_client"
require "webauthn/relying_party"

# Pins the credential id of an otherwise genuine in-memory authenticator.
# Key generation, attestation and assertion signing stay on the real FakeAuthenticator.
class FixedHandleAuthenticator < WebAuthn::FakeAuthenticator
  def initialize(fixed_handle)
    super()
    @fixed_handle = fixed_handle
  end

  private

  def new_credential(algorithm)
    _id, credential_key, sign_count = super
    [@fixed_handle, credential_key, sign_count]
  end
end

# Raised by the strict with-username policy when no current-encoding credential matches.
class TransitionCredentialNotFoundError < StandardError; end

RSpec.describe "Usernameless credential handle encoding transition" do
  # The relying party currently speaks the standard base64url encoding for every
  # user-facing value, including credential ids. A previous generation of the
  # directory stored credential ids with plain base64 (the "legacy" handle encoding).
  let(:current_encoding) { WebAuthn::Encoder::STANDARD_ENCODING } # :base64url
  let(:legacy_encoding) { :base64 }

  let(:current_encoder) { WebAuthn::Encoder.new(current_encoding) }
  let(:legacy_encoder) { WebAuthn::Encoder.new(legacy_encoding) }

  let(:relying_party) do
    WebAuthn::RelyingParty.new(
      allowed_origins: ["https://app.example.test"],
      id: "app.example.test",
      name: "Example App",
      encoding: current_encoding
    )
  end

  # Fixed raw credential handles chosen so that the two encodings are visibly
  # different (the bytes contain `+`, `/` and padding under plain base64).
  let(:new_handle_raw) { "\x00\x01\x02\xFE\xFF".b * 3 + "n" }
  let(:legacy_handle_raw) { "\x00\x01\x02\xFE\xFF".b * 3 + "l" }

  # Real in-memory authenticators: only the random credential id is pinned so the
  # test is deterministic; key generation, the attestation certificate path and the
  # assertion signature all run through the genuine FakeAuthenticator.
  let(:new_authenticator) { FixedHandleAuthenticator.new(new_handle_raw) }
  let(:legacy_authenticator) { FixedHandleAuthenticator.new(legacy_handle_raw) }

  let(:new_client) do
    WebAuthn::FakeClient.new(
      "https://app.example.test", authenticator: new_authenticator, encoding: current_encoding
    )
  end
  let(:legacy_client) do
    WebAuthn::FakeClient.new(
      "https://app.example.test", authenticator: legacy_authenticator, encoding: current_encoding
    )
  end

  let(:stored_credential_klass) do
    Struct.new(:webauthn_id, :public_key, :sign_count, :directory, keyword_init: true)
  end
  let(:subject_klass) do
    Struct.new(:subject_id, :name, :display_name, keyword_init: true)
  end

  # The two directories describe the same displayed person but are separate
  # accounts/subjects, so the chosen directory decides the final subject.
  let(:shared_profile) { { name: "Alex Doe", display_name: "Alex Doe" } }
  let(:new_subject) { subject_klass.new(subject_id: "subject-current", **shared_profile) }
  let(:legacy_subject) { subject_klass.new(subject_id: "subject-legacy", **shared_profile) }

  let(:new_directory) do
    {
      current_encoder.encode(new_handle_raw) => stored_credential_klass.new(
        webauthn_id: current_encoder.encode(new_handle_raw),
        public_key: current_encoder.encode(new_credential_public_key),
        sign_count: 0,
        directory: :new
      )
    }
  end
  let(:legacy_directory) do
    {
      # Historical record: its lookup key is the legacy base64 handle.
      legacy_encoder.encode(legacy_handle_raw) => stored_credential_klass.new(
        webauthn_id: legacy_encoder.encode(legacy_handle_raw),
        public_key: current_encoder.encode(legacy_credential_public_key),
        sign_count: 0,
        directory: :legacy
      )
    }
  end

  let(:new_credential_public_key) { registered_credential(new_client).first }
  let(:legacy_credential_public_key) { registered_credential(legacy_client).first }

  # Returns [public_key_binary, sign_count] produced by the genuine registration path.
  def registered_credential(client)
    create_result = client.create(rp_id: relying_party.id)

    attestation_object = relying_party.encoder.decode(create_result["response"]["attestationObject"])
    client_data_json = relying_party.encoder.decode(create_result["response"]["clientDataJSON"])

    response =
      WebAuthn::AuthenticatorAttestationResponse.new(
        attestation_object: attestation_object,
        client_data_json: client_data_json,
        relying_party: relying_party
      )

    [response.credential.public_key, response.authenticator_data.sign_count]
  end

  def authenticate(client)
    options = relying_party.options_for_authentication
    raw_credential = client.get(challenge: options.challenge, rp_id: relying_party.id, sign_count: 1)

    [options, raw_credential]
  end

  # Transition policy used by the USERNAMELESS entry point.
  #
  # Look up the requested directory in a fixed order: first the current directory with
  # the current encoding, and only on a miss fall back to the legacy directory, where the
  # same raw handle is re-encoded with the legacy codec before matching. The legacy
  # encoding is therefore accepted solely through this explicit fallback.
  def usernameless_lookup(assertion_credential)
    raw_handle = current_encoder.decode(assertion_credential.id)

    current_key = current_encoder.encode(raw_handle)
    if new_directory.key?(current_key)
      [:new, current_encoding, new_directory[current_key]]
    else
      legacy_key = legacy_encoder.encode(raw_handle)
      [:legacy, legacy_encoding, legacy_directory.fetch(legacy_key)]
    end
  end

  # Strict policy used by the WITH-USERNAME entry point.
  #
  # It never consults the legacy directory and never applies the legacy codec: only the
  # current encoding against the current directory is accepted. A historical handle is
  # therefore not selectable here even though the usernameless entry accepts it.
  def username_lookup(assertion_credential)
    raw_handle = current_encoder.decode(assertion_credential.id)

    stored = new_directory[current_encoder.encode(raw_handle)]
    if stored.nil?
      raise TransitionCredentialNotFoundError,
            "no current-encoding credential matches the presented handle"
    end

    [:new, current_encoding, stored]
  end

  def subject_for(stored_credential)
    case stored_credential.directory
    when :new then new_subject
    when :legacy then legacy_subject
    end
  end

  before do
    # Materialize both credentials and both directories before any assertion.
    new_directory
    legacy_directory
  end

  describe "handle encodings" do
    it "encodes the same raw handle differently while round-tripping through each codec" do
      legacy_url_handle = current_encoder.encode(legacy_handle_raw)
      legacy_base64_handle = legacy_encoder.encode(legacy_handle_raw)

      expect(legacy_url_handle).not_to eq(legacy_base64_handle)
      expect(legacy_base64_handle).to include("+", "/", "=")
      expect(current_encoder.decode(legacy_url_handle)).to eq(legacy_handle_raw)
      expect(legacy_encoder.decode(legacy_base64_handle)).to eq(legacy_handle_raw)
    end

    it "gives both synthetic users the same display profile but distinct subjects" do
      expect(new_subject.name).to eq(legacy_subject.name)
      expect(new_subject.display_name).to eq(legacy_subject.display_name)
      expect(new_subject.subject_id).not_to eq(legacy_subject.subject_id)
    end
  end

  describe "usernameless login" do
    context "with a current-directory credential" do
      it "looks the current directory up using the current encoding and selects the current subject" do
        options, raw_credential = authenticate(new_client)
        assertion_credential = WebAuthn::Credential.from_get(raw_credential, relying_party: relying_party)

        directory, encoding, stored = usernameless_lookup(assertion_credential)

        expect(directory).to eq(:new)
        expect(encoding).to eq(current_encoding)

        verified_credential, verified_stored =
          relying_party.verify_authentication(raw_credential, options.challenge) do |credential|
            usernameless_lookup(credential).last
          end

        expect(verified_credential.sign_count).to eq(1)
        expect(current_encoder.decode(verified_credential.id)).to eq(new_handle_raw)
        expect(verified_stored).to eq(stored)
        expect(subject_for(verified_stored).subject_id).to eq("subject-current")
      end
    end

    context "with a historical credential stored only in the legacy directory" do
      it "falls back to the legacy directory and legacy encoding and still selects the same subject" do
        options, raw_credential = authenticate(legacy_client)
        assertion_credential = WebAuthn::Credential.from_get(raw_credential, relying_party: relying_party)

        # The current directory must not contain this handle under the current encoding.
        expect(new_directory).not_to include(current_encoder.encode(legacy_handle_raw))

        directory, encoding, stored = usernameless_lookup(assertion_credential)

        expect(directory).to eq(:legacy)
        expect(encoding).to eq(legacy_encoding)
        expect(stored.webauthn_id).to eq(legacy_encoder.encode(legacy_handle_raw))

        verified_credential, verified_stored =
          relying_party.verify_authentication(raw_credential, options.challenge) do |credential|
            usernameless_lookup(credential).last
          end

        # Real signature verification passes against the stored public key.
        expect(verified_credential.sign_count).to eq(1)
        # The verified credential identity matches the stored one at the raw-handle level
        # even though the two directories encode the handle differently.
        expect(current_encoder.decode(verified_credential.id))
          .to eq(legacy_encoder.decode(verified_stored.webauthn_id))
        expect(verified_stored).to eq(stored)
        expect(subject_for(verified_stored).subject_id).to eq("subject-legacy")
      end
    end
  end

  describe "with-username login" do
    it "applies only the current encoding and rejects a historical legacy handle" do
      options, raw_credential = authenticate(legacy_client)
      assertion_credential = WebAuthn::Credential.from_get(raw_credential, relying_party: relying_party)

      # The strict entry never reaches the legacy directory or the legacy codec, so the
      # historical handle is not selectable and the ceremony is rejected outright.
      expect { username_lookup(assertion_credential) }.to raise_error(TransitionCredentialNotFoundError)

      expect do
        relying_party.verify_authentication(raw_credential, options.challenge) do |credential|
          username_lookup(credential).last
        end
      end.to raise_error(TransitionCredentialNotFoundError)
    end

    it "still accepts a current-directory credential with the strict current-encoding rule" do
      options, raw_credential = authenticate(new_client)
      assertion_credential = WebAuthn::Credential.from_get(raw_credential, relying_party: relying_party)

      directory, encoding, stored = username_lookup(assertion_credential)

      expect(directory).to eq(:new)
      expect(encoding).to eq(current_encoding)
      expect(stored).not_to be_nil

      verified_credential, verified_stored =
        relying_party.verify_authentication(raw_credential, options.challenge) do |credential|
          username_lookup(credential).last
        end

      expect(verified_credential.sign_count).to eq(1)
      expect(current_encoder.decode(verified_credential.id)).to eq(new_handle_raw)
      expect(subject_for(verified_stored).subject_id).to eq("subject-current")
    end

    it "keeps the legacy handle usable by the usernameless entry but not this one" do
      _options, raw_credential = authenticate(legacy_client)
      assertion_credential = WebAuthn::Credential.from_get(raw_credential, relying_party: relying_party)

      expect(usernameless_lookup(assertion_credential).last).not_to be_nil
      expect { username_lookup(assertion_credential) }.to raise_error(TransitionCredentialNotFoundError)
    end
  end
end
