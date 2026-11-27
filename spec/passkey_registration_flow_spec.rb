# frozen_string_literal: true

require "spec_helper"
require "support/passkey_registry"

RSpec.describe "Passkey registration flow with a credential limit" do
  let(:origin) { fake_origin }
  let(:relying_party) { WebAuthn.configuration.relying_party }
  let(:credential_store) { PasskeyRegistry::CredentialStore.new }
  let(:credential_limit) { 2 }
  let(:user_handle) { "user-1" }

  let(:registry) do
    PasskeyRegistry.new(
      relying_party: relying_party,
      credential_limit: credential_limit,
      credential_store: credential_store
    )
  end

  let(:device_a) { WebAuthn::FakeClient.new(origin) }
  let(:device_b) { WebAuthn::FakeClient.new(origin) }

  before do
    WebAuthn.configuration.allowed_origins = [origin]

    # The user already owns one active credential, so a single slot remains.
    credential_store.insert(
      PasskeyRegistry::CredentialRecord.new(
        id: "pre-existing-credential",
        user_handle: user_handle,
        public_key: "pre-existing-public-key",
        sign_count: 0
      )
    )
  end

  def attestation_for(client, challenge)
    WebAuthn::PublicKeyCredentialWithAttestation.from_client(client.create(challenge: challenge))
  end

  def assertion_for(client, challenge)
    WebAuthn::PublicKeyCredentialWithAssertion.from_client(client.get(challenge: challenge))
  end

  def register_and_verify(client)
    session = registry.begin_registration(user_handle)
    registry.verify_registration(session.id, attestation_for(client, session.challenge))
    session
  end

  it "distinguishes pending, verified and active while surviving a failed commit" do
    session_a = registry.begin_registration(user_handle)
    session_b = registry.begin_registration(user_handle)
    expect(registry.session_state(session_a.id)).to eq(:pending)
    expect(registry.session_state(session_b.id)).to eq(:pending)

    # Both devices verify in parallel against their original sessions.
    verified_a = registry.verify_registration(session_a.id, attestation_for(device_a, session_a.challenge))
    verified_b = registry.verify_registration(session_b.id, attestation_for(device_b, session_b.challenge))
    expect(registry.session_state(session_a.id)).to eq(:verified)
    expect(registry.session_state(session_b.id)).to eq(:verified)
    expect(verified_a[:id]).not_to eq(verified_b[:id])

    # The first commit hits a database failure: nothing is persisted and
    # the session stays verified so the write can be retried.
    credential_store.fail_next_write!
    expect { registry.commit_registration(session_a.id) }
      .to raise_error(PasskeyRegistry::StorageError)
    expect(registry.session_state(session_a.id)).to eq(:verified)
    expect(registry.committed_credentials.size).to eq(1)
    expect(registry.remaining_capacity).to eq(1)

    # The second commit succeeds and takes the last slot.
    record_b = registry.commit_registration(session_b.id)
    expect(registry.session_state(session_b.id)).to eq(:active)
    expect(record_b.id).to eq(verified_b[:id])
    expect(registry.remaining_capacity).to eq(0)

    # Retrying the first commit is now rejected: capacity counts the
    # already committed records.
    expect { registry.commit_registration(session_a.id) }
      .to raise_error(PasskeyRegistry::CapacityExceededError)
    expect(registry.session_state(session_a.id)).to eq(:verified)

    # The persisted credential can authenticate.
    options = registry.begin_authentication(user_handle)
    expect(options[:allow_credentials]).to contain_exactly("pre-existing-credential", record_b.id)
    record = registry.verify_authentication(
      user_handle, options[:challenge], assertion_for(device_b, options[:challenge])
    )
    expect(record.id).to eq(record_b.id)

    # The never-persisted credential cannot build a login, even though
    # its attestation verified successfully earlier.
    options = registry.begin_authentication(user_handle)
    expect {
      registry.verify_authentication(
        user_handle, options[:challenge], assertion_for(device_a, options[:challenge])
      )
    }.to raise_error(PasskeyRegistry::UnknownCredentialError)

    expect(registry.committed_credentials.map(&:id))
      .to contain_exactly("pre-existing-credential", record_b.id)
    expect(registry.remaining_capacity).to eq(0)
  end

  it "lets a failed commit be retried while capacity remains" do
    session = register_and_verify(device_a)

    credential_store.fail_next_write!
    expect { registry.commit_registration(session.id) }
      .to raise_error(PasskeyRegistry::StorageError)

    record = registry.commit_registration(session.id)
    expect(registry.session_state(session.id)).to eq(:active)
    expect(registry.committed_credentials.map(&:id))
      .to contain_exactly("pre-existing-credential", record.id)

    options = registry.begin_authentication(user_handle)
    expect(
      registry.verify_authentication(
        user_handle, options[:challenge], assertion_for(device_a, options[:challenge])
      ).id
    ).to eq(record.id)
  end

  it "rejects authentication for a verified credential that was never committed" do
    session = register_and_verify(device_a)
    expect(registry.session_state(session.id)).to eq(:verified)
    expect(registry.remaining_capacity).to eq(1)

    options = registry.begin_authentication(user_handle)
    expect {
      registry.verify_authentication(
        user_handle, options[:challenge], assertion_for(device_a, options[:challenge])
      )
    }.to raise_error(PasskeyRegistry::UnknownCredentialError)
  end

  it "verifies the ceremony against the challenge of the original session" do
    session_a = registry.begin_registration(user_handle)
    session_b = registry.begin_registration(user_handle)

    expect {
      registry.verify_registration(session_a.id, attestation_for(device_a, session_b.challenge))
    }.to raise_error(WebAuthn::VerificationError)

    expect(registry.session_state(session_a.id)).to eq(:pending)
  end
end
