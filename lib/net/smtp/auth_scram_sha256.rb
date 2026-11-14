# frozen_string_literal: true

require_relative 'scram_authenticator'

class Net::SMTP
  # SCRAM-SHA-256 SASL mechanism (RFC 7677), the bare mechanism without
  # channel binding.
  class AuthSCRAMSHA256 < AuthSCRAM
    auth_type :scram_sha_256

    MECHANISM = 'SCRAM-SHA-256'
    DIGEST_NAME = 'SHA256'
    CHANNEL_BINDING = nil
  end
end
