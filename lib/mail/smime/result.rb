# encoding: utf-8
# frozen_string_literal: true

module Mail
  module SMIME
    # Outcome of verifying one CMS SignerInfo inside a multipart/signed
    # message. Each signer is reported independently so callers can decide
    # whether any, all, or a specific signer is acceptable.
    class SignerResult
      # valid            => signature verifies and the chain is trusted
      # digest_mismatch  => the signed bytes do not match messageDigest
      # invalid          => signature verifies against the wrong bytes or fails
      # untrusted        => signature is good but the chain is not trusted
      # unsupported      => signature or digest algorithm is not supported
      # signer_not_found => no certificate in the CMS object matches the signer
      STATUSES = %i[valid invalid digest_mismatch untrusted unsupported signer_not_found].freeze

      attr_reader :status, :reason, :certificate, :signed_time, :digest_algorithm,
                  :signature_algorithm, :error

      def initialize(status:, reason: nil, certificate: nil, signed_time: nil,
                     digest_algorithm: nil, signature_algorithm: nil, error: nil)
        unless STATUSES.include?(status)
          raise ArgumentError, "unknown signer status: #{status.inspect}"
        end

        @status = status
        @reason = reason
        @certificate = certificate
        @signed_time = signed_time
        @digest_algorithm = digest_algorithm
        @signature_algorithm = signature_algorithm
        @error = error
      end

      def valid?
        status == :valid
      end

      def invalid?
        !valid?
      end

      # Addresses guaranteed to be covered by this signer's signature. The
      # value comes from the signing certificate, never from the unprotected
      # outer message header.
      def email_addresses
        return [] unless certificate

        addresses = []

        san = certificate.extensions.find { |extension| extension.oid == 'subjectAltName' }
        if san
          san.value.to_s.split(/,\s*/).each do |entry|
            addresses << Regexp.last_match(1) if entry =~ /\Aemail:([^,\s]+)\z/i
          end
        end

        subject = certificate.subject.to_a
        email = subject.assoc('emailAddress')
        addresses << email[1] if email && email[1]

        addresses.map(&:downcase).uniq
      end

      def to_h
        {
          status: status,
          reason: reason,
          valid: valid?,
          digest_algorithm: digest_algorithm,
          signature_algorithm: signature_algorithm,
          signed_time: signed_time,
          certificate: certificate,
          email_addresses: email_addresses,
          error: error
        }
      end

      def inspect
        "#<#{self.class} status=#{status} reason=#{reason.inspect} " \
          "subject=#{certificate && certificate.subject}>"
      end
    end

    # Result of Mail::SMIME.verify.
    #
    # signed_content is the exact MIME entity byte string that the CMS
    # signature covers. It is a BINARY-encoded String copied from the
    # received message and is never passed through Mail::Message#encoded.
    class VerificationResult
      REASONS = %i[
        not_multipart_signed
        missing_boundary
        missing_signature
        unexpected_part_count
        unsupported_protocol
        invalid_signature_part
        invalid_cms
        no_signers
        no_trusted_signer
      ].freeze

      attr_reader :signed_content, :signers, :reason, :protocol, :micalg,
                  :signature_part_body, :error

      def initialize(signed_content:, signers:, reason: nil, protocol: nil,
                     micalg: nil, signature_part_body: nil, error: nil)
        @signed_content = signed_content
        @signers = signers.freeze
        @reason = reason
        @protocol = protocol
        @micalg = micalg
        @signature_part_body = signature_part_body
        @error = error
      end

      # True only when the detachment/protocol checks passed and every signer
      # verified against a trusted chain. A single valid signer, however
      # trusted, is not enough to call the whole message verified.
      def valid?
        reason.nil? && !signers.empty? && signers.all?(&:valid?)
      end

      def invalid?
        !valid?
      end

      # True when the protocol parameter and part layout were acceptable even
      # if no signature verified. Useful to distinguish a malformed message
      # from a cryptographically untrusted one.
      def structure_valid?
        !%i[not_multipart_signed missing_boundary missing_signature
            unexpected_part_count unsupported_protocol invalid_signature_part
            invalid_cms].include?(reason)
      end

      def trusted_signer
        signers.find(&:valid?)
      end

      # True when at least one signer's signature is cryptographically valid
      # and its chain is trusted. Use this only when the caller accepts
      # per-signer semantics; #valid? remains the strict "all signers" answer.
      def any_trusted_signer?
        !trusted_signer.nil?
      end

      # Subject addresses from valid signers only. Never derived from the
      # unprotected outer From header.
      def signer_email_addresses
        signers.select(&:valid?).flat_map(&:email_addresses).uniq
      end

      def to_h
        {
          valid: valid?,
          structure_valid: structure_valid?,
          reason: reason,
          protocol: protocol,
          micalg: micalg,
          signed_content: signed_content,
          signers: signers.map(&:to_h),
          error: error
        }
      end

      def inspect
        "#<#{self.class} valid=#{valid?} reason=#{reason.inspect} signers=#{signers.size}>"
      end
    end
  end
end
