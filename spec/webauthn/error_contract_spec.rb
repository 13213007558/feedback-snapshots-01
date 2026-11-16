# frozen_string_literal: true

require "spec_helper"

RSpec.describe "public verification error contract" do
  let(:origin) { fake_origin }
  let(:challenge) { fake_challenge }

  let(:relying_party) { WebAuthn.configuration.relying_party }

  before do
    WebAuthn.configuration.allowed_origins = [origin]
  end

  shared_examples "an untrusted-input rejection" do |expected_error|
    it "raises the classified error on verify" do
      expect { response.verify(challenge) }.to raise_error(expected_error)
    end

    it "returns false on valid?" do
      expect(response.valid?(challenge)).to be_falsy
    end

    it "is classified as a verification error" do
      expect { response.verify(challenge) }.to raise_error(WebAuthn::VerificationError)
    end
  end

  shared_examples "a server-side failure" do |expected_error|
    it "raises on verify" do
      expect { response.verify(challenge) }.to raise_error(expected_error)
    end

    it "does not turn into an ordinary login failure on valid?" do
      expect { response.valid?(challenge) }.to raise_error(expected_error)
    end

    it "is not classified as a verification error" do
      expect { response.verify(challenge) }.to raise_error { |error|
        expect(error).not_to be_a(WebAuthn::VerificationError)
      }
    end
  end

  describe "error taxonomy" do
    it "classifies malformed untrusted input as verification errors" do
      expect(WebAuthn::FormatError).to be < WebAuthn::VerificationError
      expect(WebAuthn::AttestationObjectFormatError).to be < WebAuthn::FormatError
      expect(WebAuthn::AuthenticatorDataFormatError).to be < WebAuthn::FormatError
      expect(WebAuthn::AttestedCredentialDataFormatError).to be < WebAuthn::FormatError
      expect(WebAuthn::AttestationStatement::FormatNotSupportedError).to be < WebAuthn::FormatError
      expect(WebAuthn::AttestationStatement::InvalidCertificateError).to be < WebAuthn::FormatError
      expect(WebAuthn::ClientDataFormatError).to be < WebAuthn::FormatError
      expect(WebAuthn::DecodingError).to be < WebAuthn::FormatError
    end

    it "keeps configuration errors outside the verification error hierarchy" do
      expect(WebAuthn::ConfigurationError).to be < WebAuthn::Error
      expect(WebAuthn::ConfigurationError).not_to be < WebAuthn::VerificationError
      expect(WebAuthn::RootCertificateFinderNotSupportedError).to be < WebAuthn::ConfigurationError
    end
  end

  describe "registration entry" do
    let(:client) { WebAuthn::FakeClient.new(origin, encoding: false) }
    let(:credential) { client.create(challenge: challenge) }
    let(:attestation_object_bytes) { credential["response"]["attestationObject"] }
    let(:client_data_json) { credential["response"]["clientDataJSON"] }

    let(:response) do
      WebAuthn::AuthenticatorAttestationResponse.new(
        attestation_object: attestation_object,
        client_data_json: client_data_json
      )
    end

    context "with a truncated CBOR attestation object" do
      let(:attestation_object) { attestation_object_bytes.byteslice(0, 20) }

      it_behaves_like "an untrusted-input rejection", WebAuthn::AttestationObjectFormatError

      it "keeps the parser exception as cause" do
        expect { response.verify(challenge) }.to raise_error { |error|
          expect(error.cause).to be_a(EOFError)
        }
      end

      it "does not leak the challenge in the message" do
        expect { response.verify(challenge) }.to raise_error { |error|
          expect(error.message).not_to include(challenge)
        }
      end
    end

    context "with a non-CBOR attestation object" do
      let(:attestation_object) { "\xff\xff\xff\xff".b }

      it_behaves_like "an untrusted-input rejection", WebAuthn::AttestationObjectFormatError

      it "keeps the parser exception as cause" do
        expect { response.verify(challenge) }.to raise_error { |error|
          expect(error.cause).to be_a(CBOR::MalformedFormatError)
        }
      end
    end

    context "with an attestation object that is not a map" do
      let(:attestation_object) { CBOR.encode("just-a-string") }

      it_behaves_like "an untrusted-input rejection", WebAuthn::AttestationObjectFormatError
    end

    context "with truncated authenticator data" do
      let(:attestation_object) do
        map = CBOR.decode(attestation_object_bytes)
        map["authData"] = map["authData"].byteslice(0, 10)
        CBOR.encode(map)
      end

      it_behaves_like "an untrusted-input rejection", WebAuthn::AuthenticatorDataVerificationError
    end

    context "with truncated attested credential data" do
      let(:attestation_object) do
        map = CBOR.decode(attestation_object_bytes)
        map["authData"] = map["authData"].byteslice(0, 40)
        CBOR.encode(map)
      end

      it_behaves_like "an untrusted-input rejection", WebAuthn::AuthenticatorDataVerificationError
    end

    context "with incomplete credential public key parameters" do
      let(:attestation_object) do
        map = CBOR.decode(attestation_object_bytes)
        auth_data = map["authData"]
        attested_credential_data = WebAuthn::AuthenticatorData.deserialize(auth_data).attested_credential_data

        incomplete_ec2_key = CBOR.encode(
          1 => 2, # kty: EC2
          3 => -7, # alg: ES256
          -1 => 1, # crv: P-256
          -2 => SecureRandom.random_bytes(32) # x, without y
        )

        map["authData"] =
          auth_data.byteslice(0, 37) +
          attested_credential_data.raw_aaguid +
          [attested_credential_data.id.length].pack("n*") +
          attested_credential_data.id +
          incomplete_ec2_key

        CBOR.encode(map)
      end

      it_behaves_like "an untrusted-input rejection", WebAuthn::AttestedCredentialDataFormatError

      it "keeps the parser exception as cause" do
        expect { response.verify(challenge) }.to raise_error { |error|
          expect(error.cause).to be_a(ArgumentError)
        }
      end
    end

    context "with an unknown attestation format" do
      let(:attestation_object) do
        map = CBOR.decode(attestation_object_bytes)
        map["fmt"] = "unknown-format"
        CBOR.encode(map)
      end

      it_behaves_like "an untrusted-input rejection", WebAuthn::AttestationStatement::FormatNotSupportedError
    end

    context "with an invalid attestation certificate" do
      let(:attestation_object) do
        map = CBOR.decode(attestation_object_bytes)
        map["fmt"] = "packed"
        map["attStmt"] = { "alg" => -7, "sig" => "signature".b, "x5c" => ["not-a-certificate"] }
        CBOR.encode(map)
      end

      it_behaves_like "an untrusted-input rejection", WebAuthn::AttestationStatement::InvalidCertificateError

      it "keeps the parser exception as cause" do
        expect { response.verify(challenge) }.to raise_error { |error|
          expect(error.cause).to be_a(OpenSSL::X509::CertificateError)
        }
      end

      it "does not leak the certificate bytes in the message" do
        expect { response.verify(challenge) }.to raise_error { |error|
          expect(error.message).not_to include("not-a-certificate")
        }
      end
    end

    context "with malformed client data JSON" do
      let(:attestation_object) { attestation_object_bytes }
      let(:client_data_json) { "this is not json" }

      it_behaves_like "an untrusted-input rejection", WebAuthn::ClientDataFormatError

      it "keeps the parser exception as cause" do
        expect { response.verify(challenge) }.to raise_error { |error|
          expect(error.cause).to be_a(JSON::ParserError)
        }
      end
    end

    context "when expected origins are not configured" do
      let(:attestation_object) { attestation_object_bytes }

      before do
        WebAuthn.configuration.allowed_origins = nil
      end

      it_behaves_like "a server-side failure", WebAuthn::ConfigurationError
    end

    context "at the RelyingParty#verify_registration entry" do
      let(:encoded_client) { WebAuthn::FakeClient.new(origin) }
      let(:encoded_challenge) { relying_party.encoder.encode(challenge) }
      let(:raw_credential) { encoded_client.create(challenge: encoded_challenge) }

      it "raises a classified error for a truncated attestation object" do
        raw_credential["response"]["attestationObject"] =
          relying_party.encoder.encode(relying_party.encoder.decode(
            raw_credential["response"]["attestationObject"]
          ).byteslice(0, 20))

        expect {
          relying_party.verify_registration(raw_credential, encoded_challenge)
        }.to raise_error(WebAuthn::AttestationObjectFormatError)
      end

      it "raises a classified error for undecodable input" do
        raw_credential["response"]["attestationObject"] = "!!! not base64 !!!"

        expect {
          relying_party.verify_registration(raw_credential, encoded_challenge)
        }.to raise_error(WebAuthn::DecodingError)
      end

      it "does not leak the undecodable input in the message" do
        raw_credential["response"]["attestationObject"] = "!!! not base64 !!!"

        expect {
          relying_party.verify_registration(raw_credential, encoded_challenge)
        }.to raise_error { |error| expect(error.message).not_to include("not base64") }
      end
    end

    context "with a packed attestation and root certificate finders" do
      let(:credential_key) { create_ec_key }
      let(:attestation_key) { create_ec_key }
      let(:root_key) { create_ec_key }
      let(:root_certificate) { create_root_certificate(root_key) }

      let(:attestation_certificate) do
        issue_certificate(
          root_certificate,
          root_key,
          attestation_key,
          name: "/C=UY/O=ACME/OU=Authenticator Attestation/CN=CN",
          extensions: [OpenSSL::X509::Extension.new("basicConstraints", "CA:FALSE", true)]
        )
      end

      let(:auth_data) do
        WebAuthn::FakeAuthenticator::AuthenticatorData.new(
          rp_id_hash: OpenSSL::Digest::SHA256.digest("localhost"),
          credential: { id: SecureRandom.random_bytes(16), public_key: credential_key.public_key }
        ).serialize
      end

      let(:client_data_json) do
        {
          type: "webauthn.create",
          challenge: WebAuthn.standard_encoder.encode(challenge),
          origin: origin
        }.to_json
      end

      let(:attestation_object) do
        CBOR.encode(
          "fmt" => "packed",
          "attStmt" => {
            "alg" => -7,
            "sig" => attestation_key.sign("SHA256", auth_data + OpenSSL::Digest::SHA256.digest(client_data_json)),
            "x5c" => [attestation_certificate.to_der]
          },
          "authData" => auth_data
        )
      end

      context "when the trusted finder itself fails" do
        let(:finder) do
          Object.new.tap do |finder|
            def finder.find(*)
              raise "attestation metadata backend unavailable"
            end
          end
        end

        before do
          WebAuthn.configuration.attestation_root_certificates_finders = finder
        end

        it "propagates the original finder error from verify" do
          expect { response.verify(challenge) }.to raise_error("attestation metadata backend unavailable")
        end

        it "does not turn into an ordinary login failure on valid?" do
          expect { response.valid?(challenge) }.to raise_error("attestation metadata backend unavailable")
        end
      end

      context "when the finder returns something that is not a certificate" do
        let(:finder) do
          Object.new.tap do |finder|
            def finder.find(*)
              ["not-a-certificate"]
            end
          end
        end

        before do
          WebAuthn.configuration.attestation_root_certificates_finders = finder
        end

        it_behaves_like "a server-side failure", WebAuthn::ConfigurationError
      end

      context "when the finder does not implement find" do
        it "raises a configuration error" do
          expect {
            WebAuthn.configuration.attestation_root_certificates_finders = Object.new
          }.to raise_error(WebAuthn::RootCertificateFinderNotSupportedError)
        end
      end
    end
  end

  describe "authentication entry" do
    let(:client) { WebAuthn::FakeClient.new(origin, encoding: false) }
    let!(:stored_public_key) { create_credential(client: client)[1] }
    let(:assertion) { client.get(challenge: challenge) }

    let(:authenticator_data_bytes) { assertion["response"]["authenticatorData"] }
    let(:client_data_json) { assertion["response"]["clientDataJSON"] }
    let(:public_key) { stored_public_key }

    let(:response) do
      WebAuthn::AuthenticatorAssertionResponse.new(
        authenticator_data: authenticator_data_bytes,
        client_data_json: client_data_json,
        signature: assertion["response"]["signature"]
      )
    end

    def verify_response
      response.verify(challenge, public_key: public_key, sign_count: 0)
    end

    def valid_response?
      response.valid?(challenge, public_key: public_key, sign_count: 0)
    end

    context "with truncated authenticator data" do
      let(:authenticator_data_bytes) { assertion["response"]["authenticatorData"].byteslice(0, 10) }

      it "raises the classified error on verify" do
        expect { verify_response }.to raise_error(WebAuthn::AuthenticatorDataVerificationError)
      end

      it "returns false on valid?" do
        expect(valid_response?).to be_falsy
      end
    end

    context "with malformed client data JSON" do
      let(:client_data_json) { "this is not json" }

      it "raises the classified error on verify" do
        expect { verify_response }.to raise_error(WebAuthn::ClientDataFormatError)
      end

      it "returns false on valid?" do
        expect(valid_response?).to be_falsy
      end
    end

    context "with an undecodable stored public key" do
      let(:public_key) { "not-a-cose-key" }

      it "raises on verify" do
        expect { verify_response }.to raise_error(WebAuthn::PublicKey::DeserializationError)
      end

      it "does not turn into an ordinary login failure on valid?" do
        expect { valid_response? }.to raise_error(WebAuthn::PublicKey::DeserializationError)
      end

      it "is not classified as a verification error" do
        expect { verify_response }.to raise_error { |error|
          expect(error).not_to be_a(WebAuthn::VerificationError)
        }
      end
    end

    context "when expected origins are not configured" do
      before do
        WebAuthn.configuration.allowed_origins = nil
      end

      it "raises on verify" do
        expect { verify_response }.to raise_error(WebAuthn::ConfigurationError)
      end

      it "does not turn into an ordinary login failure on valid?" do
        expect { valid_response? }.to raise_error(WebAuthn::ConfigurationError)
      end
    end

    context "at the RelyingParty#verify_authentication entry" do
      let(:encoded_client) { WebAuthn::FakeClient.new(origin) }
      let(:encoded_challenge) { relying_party.encoder.encode(challenge) }
      let!(:stored_credential_public_key) do
        relying_party.encoder.encode(create_credential(client: encoded_client)[1])
      end
      let(:raw_credential) { encoded_client.get(challenge: encoded_challenge) }

      it "raises a classified error for undecodable input" do
        raw_credential["response"]["clientDataJSON"] = "!!! not base64 !!!"

        expect {
          relying_party.verify_authentication(
            raw_credential,
            encoded_challenge,
            public_key: stored_credential_public_key,
            sign_count: 0
          )
        }.to raise_error(WebAuthn::DecodingError)
      end

      it "raises a configuration error when the legacy U2F AppID is missing" do
        raw_credential["clientExtensionResults"] = { "appid" => true }

        expect {
          relying_party.verify_authentication(
            raw_credential,
            encoded_challenge,
            public_key: stored_credential_public_key,
            sign_count: 0
          )
        }.to raise_error(WebAuthn::ConfigurationError)
      end
    end
  end
end
