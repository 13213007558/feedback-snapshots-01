# frozen_string_literal: true

require "digest"
require "json"
require "openssl"
require "securerandom"
require "time"

# Minimal example of turning a verified WebAuthn registration into a
# privacy-preserving audit record. It deliberately does not receive or copy
# the raw attestation object into the returned record.
module RegistrationAudit
  ZERO_AAGUID = ("\0" * 16).b

  class Redactor
    SCHEMA = "webauthn.registration.audit/v1"

    def initialize(hmac_key:, policy:, root_anchor_sha256: nil, verifier_version: nil,
                   reference_key_id: "audit-ref-v1", retain_certificate_identifiers: false,
                   clock: -> { Time.now.utc })
      raise ArgumentError, "hmac_key must be at least 32 bytes" if hmac_key.to_s.bytesize < 32

      @hmac_key = hmac_key
      @policy = policy.freeze
      @root_anchor_sha256 = root_anchor_sha256
      @verifier_version =
        verifier_version || (defined?(WebAuthn::VERSION) ? "webauthn-ruby/#{WebAuthn::VERSION}" : "unknown")
      @reference_key_id = reference_key_id
      @retain_certificate_identifiers = retain_certificate_identifiers
      @clock = clock
    end

    # `credential` is a WebAuthn::PublicKeyCredentialWithAttestation that has
    # already been verified with the full raw attestation object. `error` is the
    # rescued WebAuthn::Error, if any. The full raw object is only used to
    # compute a commitment and is not retained.
    def build(credential, raw_attestation_object:, statement_verified:, user_handle: nil, error: nil)
      statement_policy = @policy.fetch(:verify_attestation_statement, false)
      response = credential.response
      auth_data = safe { response.authenticator_data }
      client_data = safe { response.client_data }
      trust_path = Array(safe { response.attestation_trust_path })
      certificate = trust_path.first
      attestation_type = safe { response.attestation_type }
      attestation_type = nil if attestation_type == false
      recorded_statement_verified = statement_policy && error.nil? && statement_verified
      recorded_trust_path_verified = statement_policy && error.nil? && trust_path.any?

      {
        schema: SCHEMA,
        event_id: SecureRandom.uuid,
        occurred_at: @clock.call.iso8601,
        ceremony: "webauthn.create",
        result: {
          verified: error.nil?,
          error: error && error.class.name
        },
        policy: policy_summary,
        verifier: {
          implementation: @verifier_version,
          policy_version: @policy[:version]
        },
        reference: {
          algorithm: "HMAC-SHA256",
          key_id: @reference_key_id
        },
        rp: {
          id_hash: auth_data && auth_data.rp_id_hash.unpack1("H*"),
          origin: client_data&.origin,
          cross_origin: client_data&.cross_origin,
          top_origin: client_data&.top_origin
        },
        credential: {
          ref: reference("credential", credential.raw_id),
          id_bytes: credential.raw_id&.bytesize,
          algorithm: auth_data&.credential&.algorithm
        },
        user: user_handle ? { ref: reference("user", user_handle) } : nil,
        authenticator: {
          aaguid: safe { response.aaguid },
          aaguid_zero: safe { auth_data.attested_credential_data.raw_aaguid == ZERO_AAGUID },
          flags: {
            up: safe { auth_data.user_present? },
            uv: safe { auth_data.user_verified? },
            be: safe { auth_data.credential_backup_eligible? },
            bs: safe { auth_data.credential_backed_up? }
          },
          sign_count: auth_data && auth_data.sign_count.to_i,
          attachment: credential.authenticator_attachment,
          transports: transports_for(response)
        },
        attestation: {
          format: safe { response.attestation_statement.format },
          type: attestation_type,
          certificate: certificate && certificate_summary(certificate),
          trust_path_length: trust_path.length,
          root_anchor_sha256: @root_anchor_sha256,
          proof: {
            kind: proof_kind(attestation_type, trust_path),
            statement_signature_verified: !!recorded_statement_verified,
            trust_path_verified: !!recorded_trust_path_verified
          }
        },
        client_data: {
          hash_sha256: safe { client_data.hash.unpack1("H*") },
          type: client_data&.type,
          challenge_ref: safe { reference("challenge", client_data.challenge) },
          origin: client_data&.origin,
          cross_origin: client_data&.cross_origin,
          top_origin: client_data&.top_origin
        },
        evidence: {
          raw_attestation_sha256: Digest::SHA256.hexdigest(raw_attestation_object),
          raw_attestation_retained: false,
          raw_client_data_retained: false
        }
      }
    end

    private

    def policy_summary
      {
        version: @policy[:version],
        sha256: Digest::SHA256.hexdigest(JSON.generate(canonicalize(@policy))),
        acceptable_attestation_types: @policy[:acceptable_attestation_types],
        require_user_presence: @policy[:require_user_presence],
        require_user_verification: @policy[:require_user_verification],
        verify_attestation_statement: @policy[:verify_attestation_statement]
      }.compact
    end

    def canonicalize(value)
      case value
      when Hash
        value.keys.sort_by(&:to_s).to_h { |key| [key.to_s, canonicalize(value[key])] }
      when Array
        value.map { |item| canonicalize(item) }
      else
        value
      end
    end

    def reference(kind, value)
      return nil if value.nil?

      message = kind.to_s.b + "\0".b + value.to_s.b
      "hmac-sha256:#{OpenSSL::HMAC.hexdigest('SHA256', @hmac_key, message)}"
    end

    def transports_for(response)
      transports = safe { response.transports }
      return nil if transports.nil? || transports.empty?

      Array(transports).sort
    end

    def proof_kind(attestation_type, trust_path)
      return "none" if attestation_type == "None"
      return "self" if attestation_type == "Self"
      return "certificate-chain" if trust_path.any?

      "unknown"
    end

    # Deliberately omits the full subject/SAN. Those fields can contain
    # device serials, batch identifiers, or model strings; parse only the
    # specific attributes your policy actually uses. Serial and SKI are
    # opt-in because they can link registrations to a batch or device.
    def certificate_summary(cert)
      summary = {
        leaf_sha256: Digest::SHA256.hexdigest(cert.to_der),
        issuer_cn: cert.issuer.to_a.find { |entry| entry[0] == "CN" }&.at(1),
        not_before: cert.not_before.utc.iso8601,
        not_after: cert.not_after.utc.iso8601
      }
      if @retain_certificate_identifiers
        summary[:serial_hex] = cert.serial.to_s(16)
        summary[:subject_key_identifier] = cert.subject_key_identifier&.unpack1("H*")
      end
      summary
    end

    def safe
      yield
    rescue StandardError
      nil
    end
  end
end
