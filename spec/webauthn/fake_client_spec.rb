# frozen_string_literal: true

require "spec_helper"

RSpec.describe "FakeClient" do
  let(:client) { WebAuthn::FakeClient.new }

  context "#create" do
    it "stores non-resident credentials by default" do
      client.create

      expect { client.get }.to raise_error(
        WebAuthn::FakeAuthenticator::NoDiscoverableCredentialsError,
        /No resident \(discoverable\) credentials found/
      )
    end

    it "stores a resident credential together with its binary user handle" do
      user_handle = SecureRandom.random_bytes(64)

      credential = client.create(resident_key: "required", user_handle: user_handle)

      expect(credential["id"]).to be_truthy

      assertion = client.get(user_handle: user_handle)

      expect(assertion["id"]).to eq(credential["id"])
      expect(WebAuthn.standard_encoder.decode(assertion["response"]["userHandle"])).to eq(user_handle)
    end

    it "treats the legacy requireResidentKey flag as a resident credential" do
      user_handle = SecureRandom.random_bytes(32)

      credential = client.create(
        authenticator_selection: { "requireResidentKey" => true },
        user_handle: user_handle
      )

      assertion = client.get(user_handle: user_handle)

      expect(assertion["id"]).to eq(credential["id"])
    end

    it "accepts the legacy require_resident_key keyword argument" do
      user_handle = SecureRandom.random_bytes(32)

      credential = client.create(require_resident_key: true, user_handle: user_handle)

      expect(client.get(user_handle: user_handle)["id"]).to eq(credential["id"])
    end

    it "lets residentKey take precedence over requireResidentKey when it is discouraged" do
      user_handle = SecureRandom.random_bytes(32)

      client.create(
        authenticator_selection: { "residentKey" => "discouraged", "requireResidentKey" => true },
        user_handle: user_handle
      )

      expect { client.get(user_handle: user_handle) }.to raise_error(
        WebAuthn::FakeAuthenticator::NoDiscoverableCredentialsError
      )
    end

    it "refuses a resident credential without a user handle" do
      expect { client.create(resident_key: "required") }.to raise_error(
        ArgumentError, /resident \(discoverable\) credential requires a non-empty user handle/
      )
    end

    it "refuses to register a credential listed in excludeCredentials" do
      existing = client.create

      expect {
        client.create(exclude_credentials: [existing["id"]])
      }.to raise_error(
        WebAuthn::FakeAuthenticator::ExcludedCredentialError,
        /one of the excludeCredentials is already registered/
      )
    end

    it "accepts public key credential descriptors for excludeCredentials" do
      existing = client.create

      expect {
        client.create(exclude_credentials: [{ type: "public-key", id: existing["id"] }])
      }.to raise_error(WebAuthn::FakeAuthenticator::ExcludedCredentialError)
    end

    it "allows a registration when excludeCredentials does not match anything" do
      client.create
      other_id = WebAuthn.standard_encoder.encode(SecureRandom.random_bytes(16))

      expect { client.create(exclude_credentials: [other_id]) }.not_to raise_error
    end
  end

  context "#get" do
    let!(:first_credential) { client.create }
    let!(:second_credential) { client.create }

    it "raises an error when no matching allow_credential can be found" do
      allow_credentials = ["YWJj"]

      expect { client.get(allow_credentials: allow_credentials) }.to raise_error(
        WebAuthn::FakeAuthenticator::NoMatchingCredentialsError,
        /No matching credentials \(allowed=\["abc"\]\) found for RP/
      )
    end

    it "constrains the assertion to the provided allowCredentials list" do
      assertion = client.get(allow_credentials: [second_credential["id"]])

      expect(assertion["id"]).to eq(second_credential["id"])
    end

    it "raises an explicit error instead of picking a credential when allowCredentials is omitted" do
      expect { client.get }.to raise_error(
        WebAuthn::FakeAuthenticator::NoDiscoverableCredentialsError
      )
    end

    context "with several resident accounts for the same RP" do
      let(:first_user_handle) { SecureRandom.random_bytes(64) }
      let(:second_user_handle) { SecureRandom.random_bytes(64) }

      let!(:first_resident_credential) do
        client.create(resident_key: "required", user_handle: first_user_handle)
      end
      let!(:second_resident_credential) do
        client.create(resident_key: "required", user_handle: second_user_handle)
      end

      it "requires an explicit test user selection instead of defaulting to the first key" do
        expect { client.get }.to raise_error(
          WebAuthn::FakeAuthenticator::UserSelectionRequiredError,
          /explicit user selection is required/
        )
      end

      it "returns the credential of the explicitly selected user" do
        expect(client.get(user_handle: first_user_handle)["id"]).to eq(first_resident_credential["id"])
        expect(client.get(user_handle: second_user_handle)["id"]).to eq(second_resident_credential["id"])
      end

      it "fails clearly when the selected user has no resident credential" do
        expect { client.get(user_handle: SecureRandom.random_bytes(64)) }.to raise_error(
          WebAuthn::FakeAuthenticator::NoMatchingCredentialsError,
          /No resident credential for the selected user handle/
        )
      end

      it "still honors allowCredentials when both selection inputs are provided" do
        assertion = client.get(
          user_handle: first_user_handle,
          allow_credentials: [second_resident_credential["id"]]
        )

        expect(assertion["id"]).to eq(second_resident_credential["id"])
      end
    end
  end
end
