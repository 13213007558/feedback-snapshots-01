# frozen_string_literal: true

require "cbor"
require "openssl"
require "securerandom"
require "webauthn/fake_authenticator/attestation_object"
require "webauthn/fake_authenticator/authenticator_data"

module WebAuthn
  class FakeAuthenticator
    class Error < StandardError; end
    class ExcludedCredentialError < Error; end
    class UserSelectionRequiredError < Error; end
    class NoMatchingCredentialsError < Error; end
    class NoDiscoverableCredentialsError < Error; end

    def initialize
      @credentials = {}
    end

    def make_credential(
      rp_id:,
      client_data_hash:,
      user_present: true,
      user_verified: false,
      backup_eligibility: false,
      backup_state: false,
      attested_credential_data: true,
      algorithm: nil,
      sign_count: nil,
      extensions: nil,
      resident: false,
      user_handle: nil,
      exclude_credentials: nil
    )
      if exclude_credentials && (exclude_credentials & credentials_for(rp_id).keys).any?
        raise ExcludedCredentialError,
              "Refusing to create a credential for RP #{rp_id}: one of the excludeCredentials " \
              "is already registered on this authenticator"
      end

      if resident && (user_handle.nil? || user_handle.empty?)
        raise ArgumentError, "A resident (discoverable) credential requires a non-empty user handle"
      end

      credential_id, credential_key, credential_sign_count = new_credential(algorithm)
      sign_count ||= credential_sign_count

      credentials[rp_id] ||= {}
      credentials[rp_id][credential_id] = {
        credential_key: credential_key,
        sign_count: sign_count + 1,
        resident: resident,
        user_handle: resident ? user_handle : nil
      }

      AttestationObject.new(
        client_data_hash: client_data_hash,
        rp_id_hash: hashed(rp_id),
        credential_id: credential_id,
        credential_key: credential_key,
        user_present: user_present,
        user_verified: user_verified,
        backup_eligibility: backup_eligibility,
        backup_state: backup_state,
        attested_credential_data: attested_credential_data,
        sign_count: sign_count,
        extensions: extensions
      ).serialize
    end

    def get_assertion(
      rp_id:,
      client_data_hash:,
      user_present: true,
      user_verified: false,
      backup_eligibility: false,
      backup_state: false,
      aaguid: AuthenticatorData::AAGUID,
      sign_count: nil,
      extensions: nil,
      allow_credentials: nil,
      user_handle: nil
    )
      rp_credentials = credentials_for(rp_id)

      if rp_credentials.empty?
        raise NoMatchingCredentialsError, "No credentials found for RP #{rp_id}"
      end

      if allow_credentials
        candidate_ids = rp_credentials.keys & allow_credentials

        if candidate_ids.empty?
          raise NoMatchingCredentialsError,
                "No matching credentials (allowed=#{allow_credentials}) found for RP #{rp_id} " \
                "among credentials=#{rp_credentials.keys}"
        end
      else
        candidate_ids = rp_credentials.keys.select { |id| rp_credentials.dig(id, :resident) }

        if candidate_ids.empty?
          raise NoDiscoverableCredentialsError,
                "No resident (discoverable) credentials found for RP #{rp_id}; " \
                "a username-less ceremony cannot be answered"
        end

        if user_handle.nil?
          raise UserSelectionRequiredError,
                "An explicit user selection is required for a username-less ceremony on RP #{rp_id}: " \
                "#{candidate_ids.length} resident credential(s) are available and silently picking the " \
                "first one is not an acceptable default"
        end

        candidate_ids = candidate_ids.select { |id| rp_credentials.dig(id, :user_handle) == user_handle }

        if candidate_ids.empty?
          raise NoMatchingCredentialsError,
                "No resident credential for the selected user handle found for RP #{rp_id}"
        end
      end

      credential_id = candidate_ids.first
      credential = rp_credentials[credential_id]
      credential_key = credential[:credential_key]
      credential_sign_count = credential[:sign_count]

      authenticator_data = AuthenticatorData.new(
        rp_id_hash: hashed(rp_id),
        user_present: user_present,
        user_verified: user_verified,
        backup_eligibility: backup_eligibility,
        backup_state: backup_state,
        aaguid: aaguid,
        credential: nil,
        sign_count: sign_count || credential_sign_count,
        extensions: extensions
      ).serialize

      signature_digest_algorithm =
        case credential_key
        when OpenSSL::PKey::RSA, OpenSSL::PKey::EC
          'SHA256'
        when OpenSSL::PKey::PKey
          nil
        end
      signature = credential_key.sign(signature_digest_algorithm, authenticator_data + client_data_hash)
      credential[:sign_count] += 1

      {
        credential_id: credential_id,
        authenticator_data: authenticator_data,
        signature: signature,
        user_handle: credential[:user_handle]
      }
    end

    private

    attr_reader :credentials

    def credentials_for(rp_id)
      credentials[rp_id] || {}
    end

    def new_credential(algorithm)
      algorithm ||= 'ES256'
      credential_key =
        case algorithm
        when 'ES256'
          OpenSSL::PKey::EC.generate('prime256v1')
        when 'RS256'
          OpenSSL::PKey::RSA.new(2048)
        when 'EdDSA'
          OpenSSL::PKey.generate_key("ED25519")
        else
          raise "Unsupported algorithm #{algorithm}"
        end

      [SecureRandom.random_bytes(16), credential_key, 0]
    end

    def hashed(target)
      OpenSSL::Digest::SHA256.digest(target)
    end
  end
end
