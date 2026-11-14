# frozen_string_literal: true

module JWT
  class X5cKeyFinder
    # Classifies OpenSSL verification errors into JWT error classes so callers
    # can distinguish missing, expired and invalid revocation evidence from an
    # explicitly revoked certificate or an untrusted chain.
    module ErrorBuilder
      REVOCATION_DATA_INVALID_ERRORS = [
        OpenSSL::X509::V_ERR_CRL_SIGNATURE_FAILURE,
        OpenSSL::X509::V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE,
        OpenSSL::X509::V_ERR_UNABLE_TO_GET_CRL_ISSUER,
        OpenSSL::X509::V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD,
        OpenSSL::X509::V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD,
        OpenSSL::X509::V_ERR_DIFFERENT_CRL_SCOPE,
        OpenSSL::X509::V_ERR_KEYUSAGE_NO_CRL_SIGN,
        OpenSSL::X509::V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION,
        OpenSSL::X509::V_ERR_CRL_PATH_VALIDATION_ERROR
      ].freeze

      module_function

      def build(store_context, certificate_chain)
        openssl_error = store_context.error
        reason = reason_for(openssl_error)
        current_certificate = store_context.current_cert

        message = "Certificate verification failed: #{store_context.error_string}."
        message = "#{message} Certificate subject: #{current_certificate.subject}." if current_certificate

        error_class_for(reason).new(
          message,
          reason: reason,
          current_certificate: current_certificate,
          certificate_chain: certificate_chain,
          openssl_error: openssl_error
        )
      end

      def reason_for(error)
        return :certificate_revoked if error == OpenSSL::X509::V_ERR_CERT_REVOKED
        return :revocation_data_missing if error == OpenSSL::X509::V_ERR_UNABLE_TO_GET_CRL
        return :revocation_data_expired if error == OpenSSL::X509::V_ERR_CRL_HAS_EXPIRED
        return :revocation_data_not_yet_valid if error == OpenSSL::X509::V_ERR_CRL_NOT_YET_VALID
        return :revocation_data_invalid if REVOCATION_DATA_INVALID_ERRORS.include?(error)
        return :unsuitable_certificate_purpose if error == OpenSSL::X509::V_ERR_INVALID_PURPOSE
        return :certificate_expired if error == OpenSSL::X509::V_ERR_CERT_HAS_EXPIRED
        return :certificate_not_yet_valid if error == OpenSSL::X509::V_ERR_CERT_NOT_YET_VALID

        :untrusted_chain
      end

      def error_class_for(reason)
        case reason
        when :certificate_revoked
          JWT::CertificateRevokedError
        when :revocation_data_missing
          JWT::CertificateRevocationDataMissingError
        when :revocation_data_expired, :revocation_data_not_yet_valid
          JWT::CertificateRevocationDataExpiredError
        when :revocation_data_invalid
          JWT::CertificateRevocationDataInvalidError
        when :unsuitable_certificate_purpose
          JWT::CertificatePurposeError
        when :certificate_expired, :certificate_not_yet_valid
          JWT::CertificateTimeError
        else
          JWT::CertificateChainError
        end
      end
    end
  end
end
