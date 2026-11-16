# frozen_string_literal: true

module WebAuthn
  class Error < StandardError; end

  # Raised when an authenticator response cannot be accepted. Both semantic
  # verification failures and malformed authenticator data fall in this
  # category, so `valid?` can treat them uniformly as rejection.
  class VerificationError < Error; end

  # Raised when untrusted input cannot be parsed at all. Messages never
  # echo back client-controlled data; the original parser exception is
  # preserved as the exception cause.
  class FormatError < VerificationError; end

  # Raised when the Relying Party itself is misconfigured or a trusted
  # server-side component (e.g. an attestation root certificates finder)
  # fails. Never raised for untrusted input and never swallowed by `valid?`.
  class ConfigurationError < Error; end
end
