# frozen_string_literal: true

require_relative 'scram_authenticator'

class Net::SMTP
  # SCRAM-SHA-256-PLUS SASL mechanism (RFC 7677) bound to the current
  # connection with the tls-server-end-point channel binding (RFC 5929),
  # which hashes the server certificate as presented in the handshake.
  class AuthSCRAMSHA256TlsServerEndPoint < AuthSCRAM
    auth_type :scram_sha_256_tls_server_end_point

    MECHANISM = 'SCRAM-SHA-256-PLUS'
    DIGEST_NAME = 'SHA256'
    CHANNEL_BINDING = 'tls-server-end-point'
  end
end
