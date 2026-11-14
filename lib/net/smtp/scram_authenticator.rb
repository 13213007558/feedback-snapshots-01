# frozen_string_literal: true

require 'securerandom'

class Net::SMTP
  # Common implementation of the SCRAM SASL family (RFC 5802) and its
  # channel-binding "-PLUS" variants (RFC 5802 section 6, RFC 7677).
  #
  # Subclasses set DIGEST_NAME (and CHANNEL_BINDING for the -PLUS
  # mechanisms) and register themselves through Authenticator.auth_type.
  #
  # The password, the salted password and every derived key are kept in
  # local variables only; they are never written to the SMTP debug log and
  # never appear in an exception message.
  class AuthSCRAM < Authenticator
    # RFC 5802 / RFC 7677 recommend at least 4096 iterations for
    # SCRAM-SHA-256.  A hostile server can cause a denial of service by
    # advertising a huge iteration count, so an upper bound is enforced.
    MIN_ITERATIONS = 4096
    MAX_ITERATIONS = (2 ** 31) - 1

    # The channel binding type required by a "-PLUS" mechanism, or nil for
    # the bare mechanism (which never uses channel binding).
    CHANNEL_BINDING = nil

    def self.check_args(user_arg = nil, secret_arg = nil, *, **)
      super
      raise '"openssl" library is required for SCRAM authentication' unless defined?(OpenSSL::Digest)
    end

    def auth(user, secret)
      raise Net::SCRAMError, 'SCRAM password must use ASCII characters' unless secret.ascii_only?
      raise Net::SCRAMError, 'SCRAM user name must use ASCII characters' unless user.ascii_only?

      cnonce = SecureRandom.base64(32)
      gs2_header = "#{gs2_cbind_flag},,"
      client_first_bare = "n=#{sasl_name(user)},r=#{cnonce}"
      client_first = "#{gs2_header}#{client_first_bare}"

      server_first = recv_challenge("AUTH #{mechanism} #{base64_encode(client_first)}")
      params = parse_message(server_first)

      reject_extension(params)
      server_nonce = require_attribute(params, 'r')
      unless server_nonce.start_with?(cnonce) && server_nonce.length > cnonce.length
        raise Net::SCRAMError, 'SCRAM server nonce does not extend the client nonce'
      end
      salt = decode_base64_attribute(params, 's')
      iterations = parse_iterations(require_attribute(params, 'i'))

      cbind_input = "#{gs2_header}#{channel_binding_data}"
      client_final_without_proof =
        "c=#{base64_encode(cbind_input)},r=#{server_nonce}"
      auth_message =
        "#{client_first_bare},#{server_first},#{client_final_without_proof}"

      # Derive every key from the (locally held) password in one PBKDF2
      # pass.  salted_password stays in this local variable; it is neither
      # stored on the object nor logged.
      salted_password = hi(secret, salt, iterations)
      proof = client_proof(salted_password, auth_message)
      client_final = "#{client_final_without_proof},p=#{base64_encode(proof)}"

      # The server-final-message (carrying the v= server proof) must arrive
      # as a 334 continuation.  SMTP cannot attach data to the final 235
      # success reply (RFC 4954), so a success reply here means the server
      # proof was never provided and the exchange cannot be trusted.
      server_final = recv_challenge(base64_encode(client_final)).b
      final_params = parse_message(server_final)
      reject_extension(final_params)
      if final_params.key?('e')
        raise Net::SMTPAuthenticationError.new(
          Net::SMTP::Response.parse("535 5.7.8 SCRAM server error: #{final_params['e']}")
        )
      end

      verifier = decode_base64_attribute(final_params, 'v')
      expected = server_signature(salted_password, auth_message)
      unless secure_compare(verifier, expected)
        raise Net::SCRAMError, 'SCRAM server proof verification failed'
      end

      # The mutual authentication proof has now been verified against an
      # independent computation; only at this point is the empty SASL
      # response sent and the exchange reported as successful.
      finish('')
    end

    private

    # Sends a SCRAM message and returns the decoded Base64 payload of the
    # server's 334 continuation.  A non-continuation reply (including a
    # premature 235 success) aborts the exchange because no usable
    # server-final-message was received.
    def recv_challenge(message)
      response = smtp.get_response(message)
      unless response.continue?
        if response.success?
          raise Net::SCRAMError, 'SCRAM authentication ended without a server proof'
        end
        raise response.exception_class.new(response)
      end
      token = response.string.split[1]
      raise Net::SCRAMError, 'SCRAM server sent an empty challenge' if token.nil? || token.empty?
      token.unpack1('m0')
    end

    def mechanism
      self.class::MECHANISM
    end

    def digest
      OpenSSL::Digest.new(self.class::DIGEST_NAME)
    end

    def channel_binding?
      !self.class::CHANNEL_BINDING.nil?
    end

    # GS2 channel-binding flag.  -PLUS mechanisms always require binding
    # ("p="); the bare mechanism never binds ("n").  The "y" flag is never
    # emitted because this client supports mechanism negotiation.
    def gs2_cbind_flag
      if channel_binding?
        "p=#{self.class::CHANNEL_BINDING}"
      else
        'n'
      end
    end

    # Channel binding data from the current TLS connection.  For the bare
    # mechanism there is no binding data (RFC 5802 cbind-input rules).
    def channel_binding_data
      return ''.b unless channel_binding?
      smtp.tls_channel_binding_data(self.class::CHANNEL_BINDING)
    end

    def hi(password, salt, iterations)
      OpenSSL::KDF.pbkdf2_hmac(
        password,
        salt: salt,
        iterations: iterations,
        length: digest.digest_length,
        hash: digest,
      )
    end

    def hmac(key, data)
      OpenSSL::HMAC.digest(digest, key, data)
    end

    def client_proof(salted_password, auth_message)
      client_key = hmac(salted_password, 'Client Key')
      stored_key = digest.digest(client_key)
      client_signature = hmac(stored_key, auth_message)
      xor(client_key, client_signature)
    end

    def server_signature(salted_password, auth_message)
      hmac(hmac(salted_password, 'Server Key'), auth_message)
    end

    def xor(left, right)
      left.bytes.zip(right.bytes).map { |a, b| a ^ b }.pack('C*')
    end

    # Constant-time comparison so the server proof check does not leak its
    # expected value through timing.
    def secure_compare(left, right)
      return false unless left.bytesize == right.bytesize
      left.bytes.zip(right.bytes).inject(0) { |acc, (a, b)| acc | (a ^ b) } == 0
    end

    def parse_iterations(value)
      raise Net::SCRAMError, 'SCRAM iteration count must be a positive integer' unless /\A[1-9][0-9]*\z/.match?(value)
      iterations = Integer(value)
      if iterations < MIN_ITERATIONS
        raise Net::SCRAMError, "SCRAM iteration count #{iterations} is below the minimum #{MIN_ITERATIONS}"
      end
      if iterations > MAX_ITERATIONS
        raise Net::SCRAMError, "SCRAM iteration count #{iterations} exceeds the maximum #{MAX_ITERATIONS}"
      end
      iterations
    end

    # Parses a comma separated attribute list.  Repeated attributes, empty
    # values, malformed pairs and reserved attributes are all rejected.
    def parse_message(message)
      attributes = {}
      message.split(',', -1).each do |pair|
        name, value = pair.split('=', 2)
        if value.nil? || name.nil? || name.empty? || value.empty?
          raise Net::SCRAMError, 'malformed SCRAM message'
        end
        if name.bytesize != 1 || !name.match?(/[A-Za-z]/)
          raise Net::SCRAMError, "unexpected SCRAM attribute #{name.inspect}"
        end
        if attributes.key?(name)
          raise Net::SCRAMError, "duplicate SCRAM attribute #{name}"
        end
        attributes[name] = value
      end
      attributes
    end

    def reject_extension(attributes)
      raise Net::SCRAMError, 'SCRAM mandatory extension is not supported' if attributes.key?('m')
    end

    def require_attribute(attributes, name)
      attributes.fetch(name) { raise Net::SCRAMError, "SCRAM message is missing attribute #{name}" }
    end

    def decode_base64_attribute(attributes, name)
      value = require_attribute(attributes, name)
      raise Net::SCRAMError, "SCRAM attribute #{name} is not valid base64" unless valid_base64?(value)
      value.unpack1('m0')
    end

    # Rejects empty values and any padding ('=') that does not form a valid
    # terminal pad, per the strict BASE64 requirements of RFC 4954.
    def valid_base64?(value)
      return false if value.empty? || (value.bytesize % 4).nonzero?
      value.match?(/\A[A-Za-z0-9+\/]+={0,2}\z/) &&
        !value.match?(/=[A-Za-z0-9+\/]/) &&
        !value.match?(/={3}/)
    end

    # Encodes a SASL name, escaping "," and "=" per RFC 5802 section 5.1.
    def sasl_name(name)
      name.gsub('=', '=3D').gsub(',', '=2C')
    end
  end
end
