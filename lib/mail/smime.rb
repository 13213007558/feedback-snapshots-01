# encoding: utf-8
# frozen_string_literal: true

require 'mail/smime/result'
require 'mail/smime/verifier'

module Mail
  # Detached S/MIME (multipart/signed) verification.
  #
  #   trust = {
  #     certificates: [ca_certificate],       # OpenSSL::X509::Certificate objects
  #     certificate_files: ['ca.pem'],        # files loaded into the store
  #     certificate_directories: ['/etc/ssl'],# hashed certificate directories
  #     default_paths: false,                 # load OpenSSL's default trust store
  #     crls: [crl],                          # OpenSSL::X509::CRL objects
  #     flags: 0                              # OpenSSL::X509::Store flags
  #   }
  #
  #   result = Mail::SMIME.verify(raw_email, trust: trust)
  #   result.valid?                  # every signer verified against the trust store
  #   result.signed_content          # exact MIME entity bytes that were signed
  #   result.signers.first.status    # :valid, :untrusted, :digest_mismatch, ...
  #
  # The verifier works on the bytes it is given. It does not call
  # Mail::Message#encoded, so folded headers, transfer encodings and boundary
  # framing stay exactly as received.
  module SMIME
    class << self
      # raw_source may be the exact message bytes, a Mail::Message or a
      # Mail::Part. In every case the received octets are used as-is.
      def verify(raw_source, trust: {})
        Verifier.new(trust: trust).verify(raw_source)
      end

      # Verifies a Mail::Message without the caller having to pass
      # message.raw_source explicitly.
      def verify_message(message, trust: {})
        verify(message, trust: trust)
      end
    end
  end

  class Message
    # Verifies the detached S/MIME signature of this message using the
    # supplied trust configuration. Uses the message's raw bytes, not
    # re-encoded output. Returns Mail::SMIME::VerificationResult.
    def verify_smime(trust: {})
      Mail::SMIME.verify(raw_source, trust: trust)
    end
    alias verify_smime_signature verify_smime

    def smime_signed?
      has_content_type? && sub_type.to_s.casecmp('signed').zero? &&
        main_type.to_s.casecmp('multipart').zero?
    end
  end

  class Part
    # Parts can carry a nested multipart/signed entity. Verification still
    # starts from this part's raw bytes.
    def verify_smime(trust: {})
      Mail::SMIME.verify(raw_source, trust: trust)
    end
    alias verify_smime_signature verify_smime
  end
end
