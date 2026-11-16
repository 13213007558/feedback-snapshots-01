# frozen_string_literal: true

require "openssl"
require "securerandom"
require "webauthn/authenticator_data"
require "webauthn/encoder"
require "webauthn/fake_authenticator"

module WebAuthn
  class FakeClient
    TYPES = { create: "webauthn.create", get: "webauthn.get" }.freeze

    attr_reader :origin, :cross_origin, :top_origin, :encoding

    def initialize(
      origin = fake_origin,
      cross_origin: nil,
      top_origin: nil,
      authenticator: WebAuthn::FakeAuthenticator.new,
      encoding: WebAuthn.configuration.encoding
    )
      @origin = origin
      @cross_origin = cross_origin
      @top_origin = top_origin
      @authenticator = authenticator
      @encoding = encoding
    end

    def create(
      challenge: fake_challenge,
      rp_id: nil,
      user_present: true,
      user_verified: false,
      backup_eligibility: false,
      backup_state: false,
      attested_credential_data: true,
      credential_algorithm: nil,
      extensions: nil,
      user_handle: nil,
      resident_key: nil,
      require_resident_key: nil,
      authenticator_selection: nil,
      exclude_credentials: nil
    )
      rp_id ||= URI.parse(origin).host

      client_data_json = data_json_for(:create, encoder.decode(challenge))
      client_data_hash = hashed(client_data_json)

      attestation_object = authenticator.make_credential(
        rp_id: rp_id,
        client_data_hash: client_data_hash,
        user_present: user_present,
        user_verified: user_verified,
        backup_eligibility: backup_eligibility,
        backup_state: backup_state,
        attested_credential_data: attested_credential_data,
        algorithm: credential_algorithm,
        extensions: extensions,
        resident: resident_credential?(resident_key, require_resident_key, authenticator_selection),
        user_handle: user_handle,
        exclude_credentials: normalize_credential_ids(exclude_credentials)
      )

      id =
        if attested_credential_data
          WebAuthn::AuthenticatorData
            .deserialize(CBOR.decode(attestation_object)["authData"])
            .attested_credential_data
            .id
        else
          "id-for-pk-without-attested-credential-data"
        end

      {
        "type" => "public-key",
        "id" => internal_encoder.encode(id),
        "rawId" => encoder.encode(id),
        "authenticatorAttachment" => 'platform',
        "clientExtensionResults" => extensions,
        "response" => {
          "attestationObject" => encoder.encode(attestation_object),
          "clientDataJSON" => encoder.encode(client_data_json),
          "transports" => ["internal"],
        }
      }
    end

    def get(challenge: fake_challenge,
            rp_id: nil,
            user_present: true,
            user_verified: false,
            backup_eligibility: false,
            backup_state: false,
            sign_count: nil,
            extensions: nil,
            user_handle: nil,
            allow_credentials: nil)
      rp_id ||= URI.parse(origin).host

      client_data_json = data_json_for(:get, encoder.decode(challenge))
      client_data_hash = hashed(client_data_json)

      if allow_credentials
        allow_credentials = allow_credentials.map { |credential| encoder.decode(credential) }
      end

      assertion = authenticator.get_assertion(
        rp_id: rp_id,
        client_data_hash: client_data_hash,
        user_present: user_present,
        user_verified: user_verified,
        backup_eligibility: backup_eligibility,
        backup_state: backup_state,
        sign_count: sign_count,
        extensions: extensions,
        allow_credentials: allow_credentials,
        user_handle: user_handle
      )

      {
        "type" => "public-key",
        "id" => internal_encoder.encode(assertion[:credential_id]),
        "rawId" => encoder.encode(assertion[:credential_id]),
        "clientExtensionResults" => extensions,
        "authenticatorAttachment" => 'platform',
        "response" => {
          "clientDataJSON" => encoder.encode(client_data_json),
          "authenticatorData" => encoder.encode(assertion[:authenticator_data]),
          "signature" => encoder.encode(assertion[:signature]),
          "userHandle" => assertion[:user_handle] ? encoder.encode(assertion[:user_handle]) : nil
        }
      }
    end

    private

    attr_reader :authenticator

    # Mirrors the WebAuthn L2/L3 effective resident key requirement:
    # https://www.w3.org/TR/webauthn-3/#dictdef-authenticatorselectioncriteria
    # `residentKey` takes precedence and the legacy `requireResidentKey` boolean is
    # retained for backwards compatibility, defaulting to "discouraged" when neither is set.
    def resident_credential?(resident_key, require_resident_key, authenticator_selection)
      selection = authenticator_selection || {}

      effective_resident_key =
        resident_key ||
        selection[:resident_key] ||
        selection["residentKey"] ||
        legacy_require_resident_key(selection, require_resident_key)

      effective_resident_key == "required"
    end

    def legacy_require_resident_key(selection, require_resident_key)
      legacy_flag =
        require_resident_key ||
        selection[:require_resident_key] ||
        selection["requireResidentKey"]

      legacy_flag ? "required" : nil
    end

    def normalize_credential_ids(credentials)
      return nil if credentials.nil?

      credentials.map do |credential|
        id = credential.is_a?(Hash) ? (credential[:id] || credential["id"]) : credential
        encoder.decode(id)
      end
    end

    def data_json_for(method, challenge)
      data = {
        type: type_for(method),
        challenge: internal_encoder.encode(challenge),
        origin: origin
      }

      if cross_origin
        data[:crossOrigin] = cross_origin
      end

      if top_origin
        data[:topOrigin] = top_origin
      end

      data.to_json
    end

    def encoder
      @encoder ||= WebAuthn::Encoder.new(encoding)
    end

    def internal_encoder
      WebAuthn.standard_encoder
    end

    def hashed(data)
      OpenSSL::Digest::SHA256.digest(data)
    end

    def fake_challenge
      encoder.encode(SecureRandom.random_bytes(32))
    end

    def fake_origin
      "http://localhost#{rand(1000)}.test"
    end

    def type_for(method)
      TYPES[method]
    end
  end
end
