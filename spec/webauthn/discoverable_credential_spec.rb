# frozen_string_literal: true

require "spec_helper"
require "webauthn/fake_authenticator"
require "webauthn/fake_client"
require "webauthn/relying_party"

RSpec.describe "discoverable credential (username-less) login" do
  StoredCredential = Struct.new(:public_key, :sign_count, keyword_init: true)

  let(:relying_party) do
    WebAuthn::RelyingParty.new(
      allowed_origins: ["https://example.test"],
      id: "example.test",
      name: "Example"
    )
  end
  let(:authenticator) { WebAuthn::FakeAuthenticator.new }
  let(:client) { WebAuthn::FakeClient.new("https://example.test", authenticator: authenticator) }

  let(:stored_credentials) { {} }

  def register(user_id, user_name)
    options = relying_party.options_for_registration(
      user: { id: user_id, name: user_name },
      authenticator_selection: { resident_key: "required" }
    )

    raw_credential = client.create(
      challenge: options.challenge,
      rp_id: relying_party.id,
      user_handle: WebAuthn.standard_encoder.decode(user_id),
      resident_key: "required"
    )

    verified = relying_party.verify_registration(raw_credential, options.challenge)

    stored_credentials[verified.id] = {
      public_key: verified.public_key,
      sign_count: verified.sign_count,
      user_handle: user_id
    }

    verified
  end

  def login(user_handle)
    options = relying_party.options_for_authentication

    raw_credential = client.get(
      challenge: options.challenge,
      rp_id: relying_party.id,
      user_handle: WebAuthn.standard_encoder.decode(user_handle)
    )

    relying_party.verify_authentication(raw_credential, options.challenge) do |webauthn_credential|
      stored = stored_credentials.fetch(webauthn_credential.id)

      StoredCredential.new(public_key: stored[:public_key], sign_count: stored[:sign_count])
    end
  end

  let(:alice_id) { WebAuthn.generate_user_id }
  let(:bob_id) { WebAuthn.generate_user_id }

  it "lets two accounts on the same RP log in without a username and verify each signature" do
    alice = register(alice_id, "alice")
    bob = register(bob_id, "bob")

    expect(alice.id).not_to eq(bob.id)

    alice_credential, alice_stored = login(alice_id)
    expect(alice_credential.id).to eq(alice.id)
    expect(alice_credential.user_handle).to eq(alice_id)

    bob_credential, bob_stored = login(bob_id)
    expect(bob_credential.id).to eq(bob.id)
    expect(bob_credential.user_handle).to eq(bob_id)

    expect(alice_stored.public_key).not_to eq(bob_stored.public_key)
  end

  it "rejects an assertion whose signature was tampered with" do
    register(alice_id, "alice")

    options = relying_party.options_for_authentication
    raw_credential = client.get(
      challenge: options.challenge,
      rp_id: relying_party.id,
      user_handle: WebAuthn.standard_encoder.decode(alice_id)
    )

    tampered_signature = WebAuthn.standard_encoder.decode(raw_credential["response"]["signature"])
    tampered_signature.setbyte(-1, tampered_signature.getbyte(-1) ^ 0xFF)
    raw_credential["response"]["signature"] = WebAuthn.standard_encoder.encode(tampered_signature)

    expect {
      relying_party.verify_authentication(raw_credential, options.challenge) do |webauthn_credential|
        stored = stored_credentials.fetch(webauthn_credential.id)

        StoredCredential.new(public_key: stored[:public_key], sign_count: stored[:sign_count])
      end
    }.to raise_error(WebAuthn::SignatureVerificationError)
  end

  it "cannot run a username-less ceremony against non-resident credentials" do
    options = relying_party.options_for_registration(user: { id: alice_id, name: "alice" })
    client.create(challenge: options.challenge, rp_id: relying_party.id)

    auth_options = relying_party.options_for_authentication

    expect {
      client.get(challenge: auth_options.challenge, rp_id: relying_party.id, user_handle: "anything")
    }.to raise_error(WebAuthn::FakeAuthenticator::NoDiscoverableCredentialsError)
  end

  it "rejects re-registration of an existing credential through excludeCredentials" do
    alice = register(alice_id, "alice")
    options = relying_party.options_for_registration(
      user: { id: bob_id, name: "bob" },
      exclude_credentials: [{ type: "public-key", id: alice.id }]
    )

    expect {
      client.create(
        challenge: options.challenge,
        rp_id: relying_party.id,
        exclude_credentials: options.exclude_credentials.map { |descriptor| descriptor[:id] }
      )
    }.to raise_error(WebAuthn::FakeAuthenticator::ExcludedCredentialError)
  end
end
