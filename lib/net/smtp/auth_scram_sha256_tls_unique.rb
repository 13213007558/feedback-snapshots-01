# frozen_string_literal: true

require_relative 'scram_authenticator'

class Net::SMTP
  # SCRAM-SHA-256-PLUS SASL mechanism (RFC 7677) bound to the current
  # connection with the tls-unique channel binding (RFC 5929).  tls-unique
  # is defined only for TLS 1.2 and earlier and requires the extended
  # master secret extension (RFC 7627); it is rejected otherwise rather
  # than downgraded.
  class AuthSCRAMSHA256TlsUnique < AuthSCRAM
    auth_type :scram_sha_256_tls_unique

    MECHANISM = 'SCRAM-SHA-256-PLUS'
    DIGEST_NAME = 'SHA256'
    CHANNEL_BINDING = 'tls-unique'
  end
end
