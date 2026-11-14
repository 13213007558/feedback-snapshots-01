# frozen_string_literal: true

module JWT
  # The base error class for all JWT errors.
  class Error < StandardError; end

  # The EncodeError class is raised when there is an error encoding a JWT.
  class EncodeError < Error; end

  # The historical grouping of every error that is not an encoding error. Every
  # error class below is a descendant, so `rescue JWT::DecodeError` keeps its
  # original meaning.
  #
  # @deprecated Use {JWT::Error}, {JWT::TokenError} or a more specific error class instead.
  class DecodeError < Error; end

  # The TokenError class is the base class for all errors related to token processing.
  class TokenError < DecodeError; end

  # The MalformedTokenError class is raised when the token is structurally invalid.
  class MalformedTokenError < TokenError; end

  # The Base64DecodeError class is raised when there is an error decoding a Base64-encoded string.
  class Base64DecodeError < MalformedTokenError; end

  # The SignatureError class is the base class for signature and algorithm related errors.
  class SignatureError < TokenError; end

  # The VerificationError class is raised when the signature of a token does not
  # match the one calculated from the signing input.
  class VerificationError < SignatureError; end

  # The VerificationKeyError class is raised when the key or algorithm given for
  # verification cannot be used, as opposed to a signature that does not match.
  class VerificationKeyError < VerificationError; end

  # The CertificateVerificationError class is raised when an x5c certificate
  # chain cannot be accepted as the source of a JWT verification key.
  #
  # The +reason+ attribute gives a stable classification of the failure so that
  # callers do not have to parse OpenSSL error strings.
  class CertificateVerificationError < VerificationKeyError
    attr_reader :reason, :current_certificate, :certificate_chain, :openssl_error

    def initialize(message = nil, reason: nil, current_certificate: nil, certificate_chain: nil, openssl_error: nil)
      super(message)
      @reason = reason
      @current_certificate = current_certificate
      @certificate_chain = certificate_chain
      @openssl_error = openssl_error
    end
  end

  # The CertificateChainError class is raised when the header certificates do
  # not form a valid path to a server-provided trusted root.
  class CertificateChainError < CertificateVerificationError; end

  # The CertificatePurposeError class is raised when a trusted certificate is
  # not permitted by the requested purpose (for example its extended key usage
  # does not allow the operation).
  class CertificatePurposeError < CertificateVerificationError; end

  # The CertificateTimeError class is raised when a certificate is expired or
  # not yet valid at the requested verification time.
  class CertificateTimeError < CertificateVerificationError; end

  # The CertificateRevocationError class is the base class for failures caused
  # by revocation evidence.
  class CertificateRevocationError < CertificateVerificationError; end

  # The CertificateRevokedError class is raised when the certificate is
  # explicitly listed as revoked.
  class CertificateRevokedError < CertificateRevocationError; end

  # The CertificateRevocationDataMissingError class is raised when the applied
  # policy requires revocation evidence but no usable CRL was supplied. This is
  # deliberately distinct from "not revoked": missing evidence must not pass.
  class CertificateRevocationDataMissingError < CertificateRevocationError; end

  # The CertificateRevocationDataExpiredError class is raised when the supplied
  # CRL is outside its last_update/next_update window at the verification time.
  # This does not imply that the certificate is revoked.
  class CertificateRevocationDataExpiredError < CertificateRevocationError; end

  # The CertificateRevocationDataInvalidError class is raised when a CRL is
  # present but cannot be trusted (for example a bad signature or a malformed
  # update field).
  class CertificateRevocationDataInvalidError < CertificateRevocationError; end

  # The IncorrectAlgorithm class is raised when the JWT algorithm is incorrect.
  class IncorrectAlgorithm < SignatureError; end

  # The UnsupportedEcdsaCurve class is raised when the ECDSA curve is unsupported.
  class UnsupportedEcdsaCurve < IncorrectAlgorithm; end

  # The ClaimValidationError class is the base class for all claim validation errors.
  class ClaimValidationError < TokenError; end

  # The ExpiredSignature class is raised when the JWT token has expired.
  class ExpiredSignature < ClaimValidationError; end

  # The ImmatureSignature class is raised when the JWT token is not yet valid (nbf).
  class ImmatureSignature < ClaimValidationError; end

  # The InvalidIssuerError class is raised when the JWT issuer is invalid.
  class InvalidIssuerError < ClaimValidationError; end

  # The InvalidIatError class is raised when the JWT issued at (iat) claim is invalid.
  class InvalidIatError < ClaimValidationError; end

  # The InvalidAudError class is raised when the JWT audience (aud) claim is invalid.
  class InvalidAudError < ClaimValidationError; end

  # The InvalidSubError class is raised when the JWT subject (sub) claim is invalid.
  class InvalidSubError < ClaimValidationError; end

  # The InvalidCritError class is raised when the JWT crit header is invalid.
  class InvalidCritError < ClaimValidationError; end

  # The InvalidJtiError class is raised when the JWT ID (jti) claim is invalid.
  class InvalidJtiError < ClaimValidationError; end

  # The InvalidPayload class is raised when the JWT payload is invalid.
  class InvalidPayload < ClaimValidationError; end

  # The MissingRequiredClaim class is raised when a required claim is missing from the JWT.
  class MissingRequiredClaim < ClaimValidationError; end

  # The JWKError class is raised when there is an error with the JSON Web Key (JWK).
  class JWKError < DecodeError; end

  # Raised when a JWK uses a key type (kty) that this library does not support.
  class UnsupportedKeyType < JWKError; end
end
