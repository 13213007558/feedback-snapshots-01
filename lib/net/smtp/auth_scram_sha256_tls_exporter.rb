# frozen_string_literal: true

require_relative 'scram_authenticator'

class Net::SMTP
  # SCRAM-SHA-256-PLUS SASL mechanism (RFC 7677) bound to the current
  # connection with the tls-exporter channel binding (RFC 9266).
  # tls-exporter is the mandatory default channel binding over TLS 1.3 and
  # later.
  class AuthSCRAMSHA256TlsExporter < AuthSCRAM
    auth_type :scram_sha_256_tls_exporter

    MECHANISM = 'SCRAM-SHA-256-PLUS'
    DIGEST_NAME = 'SHA256'
    CHANNEL_BINDING = 'tls-exporter'
  end
end
