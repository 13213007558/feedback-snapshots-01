# frozen_string_literal: true

require "spec_helper"

RSpec.describe "FakeClient" do
  let(:client) { WebAuthn::FakeClient.new }

  context "#get" do
    let!(:credential_1) { client.create }
    let!(:credential_2) { client.create }

    it "returns the first matching credential when allow_credentials is nil" do
      assertion = client.get
      expect(assertion["id"]).to eq(credential_1["id"])
    end

    it "returns the matching credential when allow_credentials is passed" do
      allow_credentials = [credential_2["id"]]
      assertion = client.get(allow_credentials: allow_credentials)
      expect(assertion["id"]).to eq(credential_2["id"])
    end

    it "raises an error when no matching allow_credential can be found" do
      # base64(abc) is surely not a valid credential id (too short)
      allow_credentials = ["YWJj"]
      expect { client.get(allow_credentials: allow_credentials) }.to \
        raise_error(RuntimeError, /No matching credentials \(allowed=\["abc"\]\) found for RP/)
    end

    context "when the storage encoding is :base64" do
      let(:credential_id) do
        [0x00, 0xFF, 0x80, 0xC3, 0xA9, 0x01, 0x00, 0xFE, 0x7F, 0x80, 0x81, 0x82, 0x00, 0xA0, 0xFF, 0x10].pack("C*")
      end
      let(:authenticator) do
        WebAuthn::FakeAuthenticator.new.tap do |fake|
          allow(fake).to receive(:new_credential).and_return(
            [credential_id, OpenSSL::PKey::EC.generate("prime256v1"), 0]
          )
        end
      end
      let(:client) { WebAuthn::FakeClient.new(authenticator: authenticator, encoding: :base64) }
      let!(:credential) { client.create }

      it "decodes allow_credentials as browser protocol base64url ids" do
        protocol_id = WebAuthn::Encoders::Base64UrlEncoder.encode(credential_id)
        storage_id = WebAuthn::Encoders::Base64Encoder.encode(credential_id)

        expect(credential["id"]).to eq(protocol_id)
        expect(client.get(allow_credentials: [protocol_id])["id"]).to eq(protocol_id)

        # The storage spelling is a different string even though the lenient
        # protocol decoder can still read it. FakeClient must accept the
        # protocol spelling, not the storage one.
        expect(storage_id).not_to eq(protocol_id)
        expect(WebAuthn.standard_encoder.decode(storage_id)).to eq(credential_id)
      end
    end
  end
end
