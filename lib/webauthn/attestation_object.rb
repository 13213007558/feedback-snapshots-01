# frozen_string_literal: true

require "cbor"
require "forwardable"
require "openssl"
require "webauthn/attestation_statement"
require "webauthn/authenticator_data"
require "webauthn/error"

module WebAuthn
  class AttestationObjectFormatError < FormatError; end

  class AttestationObject
    extend Forwardable

    def self.deserialize(attestation_object, relying_party)
      map =
        begin
          CBOR.decode(attestation_object)
        rescue CBOR::UnpackError, EOFError
          raise AttestationObjectFormatError, "Attestation object could not be deserialized"
        end

      unless map.is_a?(Hash)
        raise AttestationObjectFormatError, "Attestation object could not be deserialized"
      end

      from_map(map, relying_party)
    end

    def self.from_map(map, relying_party)
      new(
        authenticator_data: WebAuthn::AuthenticatorData.deserialize(map["authData"]),
        attestation_statement: WebAuthn::AttestationStatement.from(
          map["fmt"],
          map["attStmt"],
          relying_party: relying_party
        )
      )
    end

    attr_reader :authenticator_data, :attestation_statement, :relying_party

    def initialize(authenticator_data:, attestation_statement:)
      @authenticator_data = authenticator_data
      @attestation_statement = attestation_statement
    end

    def valid_attested_credential?
      authenticator_data.attested_credential_data_included? &&
        authenticator_data.attested_credential_data.valid?
    end

    def valid_attestation_statement?(client_data_hash)
      attestation_statement.valid?(authenticator_data, client_data_hash)
    end

    def_delegators :authenticator_data, :credential, :aaguid
    def_delegators :attestation_statement, :attestation_certificate_key_id
  end
end
