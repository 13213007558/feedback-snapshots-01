# frozen_string_literal: true

require "spec_helper"

require "json"
require "openssl"
require "webauthn/attestation_statement/packed"
require "webauthn/relying_party"

RSpec.describe WebAuthn::AttestationRootCertificatesFinder do
  AttestationRootFinderStub = Struct.new(:result, :calls) do
    def initialize(result)
      super(result, [])
    end

    def find(**arguments)
      calls << arguments
      result.respond_to?(:call) ? result.call(**arguments) : result
    end
  end

  let(:internal_finder) { AttestationRootFinderStub.new(internal_result) }
  let(:public_finder) { AttestationRootFinderStub.new(public_result) }
  let(:unavailable_policy) { :fail }
  let(:relying_party) do
    WebAuthn::RelyingParty.new(
      attestation_root_certificates_finders: [internal_finder, public_finder],
      attestation_root_certificates_finder_unavailable_policy: unavailable_policy
    )
  end
  let(:resolver) do
    described_class::Resolver.new(
      relying_party.attestation_root_certificates_finders,
      relying_party: relying_party
    )
  end

  let(:root_key) { create_ec_key }
  let(:root_certificate) { create_root_certificate(root_key) }
  let(:attestation_key) { create_ec_key }
  let(:credential_key) { create_ec_key }
  let(:client_data_hash) { OpenSSL::Digest::SHA256.digest({}.to_json) }
  let(:authenticator_data_bytes) do
    WebAuthn::FakeAuthenticator::AuthenticatorData.new(
      rp_id_hash: OpenSSL::Digest.digest("SHA256", "RP"),
      credential: { id: "0".b * 16, public_key: credential_key.public_key }
    ).serialize
  end
  let(:authenticator_data) { WebAuthn::AuthenticatorData.deserialize(authenticator_data_bytes) }
  let(:signature) { attestation_key.sign("SHA256", authenticator_data.data + client_data_hash) }
  let(:attestation_certificate) do
    extension_factory = OpenSSL::X509::ExtensionFactory.new

    issue_certificate(
      root_certificate,
      root_key,
      attestation_key,
      name: "/C=UY/O=ACME/OU=Authenticator Attestation/CN=CN",
      extensions: [
        extension_factory.create_extension("basicConstraints", "CA:FALSE", true)
      ]
    )
  end
  let(:statement) do
    WebAuthn::AttestationStatement::Packed.new(
      {
        "alg" => -7,
        "sig" => signature,
        "x5c" => [attestation_certificate.to_der]
      },
      relying_party
    )
  end

  describe "resolution outcomes" do
    subject(:result) { resolver.resolve(attestation_format: "packed", aaguid: "aaguid") }

    context "when the first source has a matching root" do
      let(:internal_result) { described_class::Found.new(certificates: [root_certificate]) }
      let(:public_result) { ->(**) { raise "the public source must not be consulted after a hit" } }

      it "returns a found result and retains the deciding source" do
        expect(result).to be_found
        expect(result.certificates).to eq([root_certificate])
        expect(result.source).to be(internal_finder)
        expect(public_finder.calls).to be_empty
      end
    end

    context "when the first source has no match and the public source has the root" do
      let(:internal_result) { [] }
      let(:public_result) { described_class::Found.new(certificates: [root_certificate]) }

      it "continues and reports the public source as the decision source" do
        expect(result).to be_found
        expect(result.certificates).to eq([root_certificate])
        expect(result.source).to be(public_finder)
        expect(internal_finder.calls.length).to eq(1)
        expect(public_finder.calls.length).to eq(1)
      end
    end

    context "when the first source denies explicitly" do
      let(:internal_result) do
        described_class::Denied.new(source: :internal_allowlist, reason: "revoked in internal directory")
      end
      let(:public_result) { described_class::Found.new(certificates: [root_certificate]) }

      it "stops at the denial and never falls back to the public source" do
        expect(result).to be_denied
        expect(result.source).to eq(:internal_allowlist)
        expect(result.reason).to eq("revoked in internal directory")
        expect(public_finder.calls).to be_empty
      end
    end

    context "when the first source returns an explicit unavailable result" do
      let(:internal_result) do
        described_class::Result.unavailable(source: :internal_allowlist, reason: "metadata refresh failed")
      end
      let(:public_result) { described_class::Result.found([root_certificate]) }

      it "fails closed by default and preserves the reported reason" do
        expect(result).to be_unavailable
        expect(result.source).to eq(:internal_allowlist)
        expect(result.reason).to eq("metadata refresh failed")
        expect(public_finder.calls).to be_empty
      end

      context "and the trusted configuration allows continuing" do
        let(:unavailable_policy) { :continue }

        it "continues to the public source" do
          expect(result).to be_found
          expect(result.source).to be(public_finder)
        end
      end
    end

    context "when the first source raises a denial error" do
      let(:internal_result) do
        ->(**) { raise described_class::DeniedError, "blocked by internal policy" }
      end
      let(:public_result) { described_class::Result.found([root_certificate]) }

      it "treats it as a terminal denial and does not fall back" do
        expect(result).to be_denied
        expect(result.source).to be(internal_finder)
        expect(result.reason).to eq("blocked by internal policy")
        expect(public_finder.calls).to be_empty
      end
    end

    context "when a legacy finder is temporarily unavailable" do
      let(:internal_result) { ->(**) { raise IOError, "metadata service down" } }
      let(:public_result) { described_class::Found.new(certificates: [root_certificate]) }

      it "fails closed by default and reports the failing source" do
        expect(result).to be_unavailable
        expect(result.source).to be(internal_finder)
        expect(result.reason).to be_a(IOError)
        expect(public_finder.calls).to be_empty
      end

      context "and the trusted configuration allows continuing" do
        let(:unavailable_policy) { :continue }

        it "continues to the public source" do
          expect(result).to be_found
          expect(result.source).to be(public_finder)
        end

        context "and no later source has a root" do
          let(:public_result) { [] }

          it "still reports unavailability rather than a definitive no-match" do
            expect(result).to be_unavailable
            expect(result.source).to be(internal_finder)
            expect(result.reason).to be_a(IOError)
          end
        end
      end
    end
  end

  describe "result construction" do
    it "exposes the four statuses without collapsing them into a certificate array" do
      found = described_class::Result.found([root_certificate], source: :internal)
      not_found = described_class::Result.not_found(source: :internal)
      denied = described_class::Result.denied(source: :internal, reason: "revoked")
      unavailable = described_class::Result.unavailable(source: :internal, reason: "timeout")

      expect(found.status).to eq(:found)
      expect(found.certificates).to eq([root_certificate])
      expect(found.source).to eq(:internal)
      expect(not_found.status).to eq(:not_found)
      expect(denied.status).to eq(:denied)
      expect(denied.reason).to eq("revoked")
      expect(unavailable.status).to eq(:unavailable)
      expect(unavailable.reason).to eq("timeout")
    end

    it "rejects a found result without certificates" do
      expect {
        described_class::Result.found([], source: :internal)
      }.to raise_error(described_class::InvalidResultError)
    end

    it "rejects a non-certificate value" do
      expect {
        described_class::Result.found(["not a certificate"], source: :internal)
      }.to raise_error(described_class::InvalidResultError)
    end

    it "rejects unknown statuses" do
      expect {
        described_class::Result.build(:something_else, source: :internal)
      }.to raise_error(described_class::InvalidResultError)
    end

    it "rejects unknown unavailable policies" do
      resolver = described_class::Resolver.new(
        [AttestationRootFinderStub.new(->(**) { raise IOError, "down" })],
        unavailable_policy: :whatever
      )

      expect {
        resolver.resolve(attestation_format: "packed")
      }.to raise_error(described_class::InvalidUnavailablePolicyError)
    end
  end

  describe "legacy finder return values" do
    subject(:result) { resolver.resolve(attestation_format: "packed") }

    context "when a finder returns nil" do
      let(:internal_result) { nil }
      let(:public_result) { [root_certificate] }

      it "treats it as no match and keeps looking" do
        expect(result).to be_found
        expect(result.source).to be(public_finder)
      end
    end

    context "when a finder returns an array of roots" do
      let(:internal_result) { [root_certificate] }
      let(:public_result) { ->(**) { raise "the public source must not be consulted" } }

      it "treats it as a hit from that finder" do
        expect(result).to be_found
        expect(result.certificates).to eq([root_certificate])
        expect(result.source).to be(internal_finder)
      end
    end

    context "when a finder returns an empty array" do
      let(:internal_result) { [] }
      let(:public_result) { [] }

      it "treats it as no match from both sources" do
        expect(result).to be_not_found
        expect(result.certificates).to be_empty
      end
    end

    context "when a finder returns a malformed value" do
      let(:internal_result) { ["not a certificate"] }
      let(:public_result) { described_class::Found.new(certificates: [root_certificate]) }

      it "treats it as unavailable under the trusted policy" do
        expect(result).to be_unavailable
        expect(result.source).to be(internal_finder)
        expect(result.reason).to be_a(described_class::InvalidResultError)
        expect(public_finder.calls).to be_empty
      end
    end
  end

  describe "attestation verification using the resolved roots" do
    let(:unavailable_policy) { :fail }

    context "when the internal source has the matching root" do
      let(:internal_result) { described_class::Found.new(certificates: [root_certificate]) }
      let(:public_result) { ->(**) { raise "the public source must not be consulted after a hit" } }

      it "verifies the chain and reports the internal source" do
        expect(statement.valid?(authenticator_data, client_data_hash)).to be_truthy

        result = statement.attestation_root_certificates_result

        expect(result).to be_found
        expect(result.source).to be(internal_finder)
        expect(result.certificates).to eq([root_certificate])
        expect(public_finder.calls).to be_empty
      end
    end

    context "when the internal source denies even though the public source has the root" do
      let(:internal_result) { described_class::Denied.new(source: :internal_allowlist) }
      let(:public_result) { described_class::Found.new(certificates: [root_certificate]) }

      it "terminates verification before consulting the public source" do
        expect { statement.valid?(authenticator_data, client_data_hash) }
          .to raise_error(described_class::DeniedError, /internal_allowlist/)

        expect(public_finder.calls).to be_empty
      end
    end

    context "when the internal source is unavailable" do
      let(:internal_result) { ->(**) { raise IOError, "metadata service down" } }
      let(:public_result) { described_class::Found.new(certificates: [root_certificate]) }

      it "fails verification under the default trusted policy" do
        expect { statement.valid?(authenticator_data, client_data_hash) }
          .to raise_error(described_class::UnavailableError)

        expect(public_finder.calls).to be_empty
      end

      context "and the relying party policy allows continuing" do
        let(:unavailable_policy) { :continue }

        it "verifies the chain with the next source's root" do
          expect(statement.valid?(authenticator_data, client_data_hash)).to be_truthy
          expect(public_finder.calls.length).to eq(1)
        end
      end
    end

    context "when the previous source has no match and the public source has the root" do
      let(:internal_result) { [] }
      let(:public_result) { described_class::Found.new(certificates: [root_certificate]) }

      it "verifies the chain normally and exposes the public source" do
        expect(statement.valid?(authenticator_data, client_data_hash)).to be_truthy

        result = statement.attestation_root_certificates_result

        expect(result).to be_found
        expect(result.source).to be(public_finder)
        expect(result.certificates).to eq([root_certificate])
      end
    end

    context "when the source claims a hit based on the client's AAGUID" do
      let(:unrelated_root) { create_root_certificate(create_ec_key) }
      let(:internal_result) { described_class::Found.new(certificates: [unrelated_root]) }
      let(:public_result) { described_class::Found.new(certificates: [root_certificate]) }

      it "still requires the attestation certificate chain to verify" do
        expect(statement.valid?(authenticator_data, client_data_hash)).to be_falsy

        result = statement.attestation_root_certificates_result

        expect(result).to be_found
        expect(result.source).to be(internal_finder)
        expect(result.certificates).not_to eq([root_certificate])
      end
    end
  end
end

RSpec.describe "Attestation root source policy during registration" do
  let(:origin) { "https://example.test" }
  let(:rp_id) { "example.test" }
  let(:challenge) { WebAuthn::Encoders::Base64UrlEncoder.encode(SecureRandom.random_bytes(32)) }
  let(:internal_finder) { AttestationRootFinderStub.new(internal_result) }
  let(:public_finder) { AttestationRootFinderStub.new(public_result) }
  let(:relying_party) do
    WebAuthn::RelyingParty.new(
      allowed_origins: [origin],
      id: rp_id,
      name: "Example",
      attestation_root_certificates_finders: [internal_finder, public_finder]
    )
  end

  let(:root_key) { create_ec_key }
  let(:root_certificate) { create_root_certificate(root_key) }
  let(:attestation_key) { create_ec_key }
  let(:credential_key) { create_ec_key }
  let(:client_data_json) do
    {
      "type" => "webauthn.create",
      "challenge" => challenge,
      "origin" => origin
    }.to_json
  end
  let(:client_data_hash) { OpenSSL::Digest::SHA256.digest(client_data_json) }
  let(:credential_id) { SecureRandom.random_bytes(32) }
  let(:authenticator_data_bytes) do
    WebAuthn::FakeAuthenticator::AuthenticatorData.new(
      rp_id_hash: OpenSSL::Digest.digest("SHA256", rp_id),
      credential: { id: credential_id, public_key: credential_key.public_key }
    ).serialize
  end
  let(:signature) { attestation_key.sign("SHA256", authenticator_data_bytes + client_data_hash) }
  let(:attestation_certificate) do
    extension_factory = OpenSSL::X509::ExtensionFactory.new

    issue_certificate(
      root_certificate,
      root_key,
      attestation_key,
      name: "/C=UY/O=ACME/OU=Authenticator Attestation/CN=CN",
      extensions: [
        extension_factory.create_extension("basicConstraints", "CA:FALSE", true)
      ]
    )
  end
  let(:raw_credential) do
    attestation_object = CBOR.encode(
      "fmt" => "packed",
      "attStmt" => {
        "alg" => -7,
        "sig" => signature,
        "x5c" => [attestation_certificate.to_der]
      },
      "authData" => authenticator_data_bytes
    )

    {
      "type" => "public-key",
      "id" => WebAuthn::Encoders::Base64UrlEncoder.encode(credential_id),
      "rawId" => WebAuthn::Encoders::Base64UrlEncoder.encode(credential_id),
      "response" => {
        "attestationObject" => WebAuthn::Encoders::Base64UrlEncoder.encode(attestation_object),
        "clientDataJSON" => WebAuthn::Encoders::Base64UrlEncoder.encode(client_data_json)
      }
    }
  end

  context "when the internal source denies and the public source has the root" do
    let(:internal_result) { WebAuthn::AttestationRootCertificatesFinder::Result.denied(source: :internal_allowlist) }
    let(:public_result) { WebAuthn::AttestationRootCertificatesFinder::Result.found([root_certificate]) }

    it "does not admit the credential" do
      expect {
        relying_party.verify_registration(raw_credential, challenge)
      }.to raise_error(WebAuthn::AttestationRootCertificatesFinder::DeniedError)

      expect(public_finder.calls).to be_empty
    end
  end

  context "when the internal source is unavailable and the trusted policy keeps failing closed" do
    let(:internal_result) { ->(**) { raise IOError, "metadata service down" } }
    let(:public_result) { WebAuthn::AttestationRootCertificatesFinder::Result.found([root_certificate]) }

    it "does not admit the credential" do
      expect {
        relying_party.verify_registration(raw_credential, challenge)
      }.to raise_error(WebAuthn::AttestationRootCertificatesFinder::UnavailableError)

      expect(public_finder.calls).to be_empty
    end
  end

  context "when the previous source has no match and the public source has the root" do
    let(:internal_result) { [] }
    let(:public_result) { WebAuthn::AttestationRootCertificatesFinder::Result.found([root_certificate]) }

    it "admits the credential and reports the public source" do
      credential = relying_party.verify_registration(raw_credential, challenge)

      result = credential.response.attestation_root_certificates_result

      expect(result).to be_found
      expect(result.source).to be(public_finder)
      expect(result.certificates).to eq([root_certificate])
    end
  end

  context "when the internal source reports a hit that does not validate the chain" do
    let(:internal_result) do
      WebAuthn::AttestationRootCertificatesFinder::Result.found([create_root_certificate(create_ec_key)])
    end
    let(:public_result) { WebAuthn::AttestationRootCertificatesFinder::Result.found([root_certificate]) }

    it "does not admit the credential based on the stated AAGUID or finder hit alone" do
      expect {
        relying_party.verify_registration(raw_credential, challenge)
      }.to raise_error(WebAuthn::AttestationStatementVerificationError)

      expect(public_finder.calls).to be_empty
    end
  end
end
