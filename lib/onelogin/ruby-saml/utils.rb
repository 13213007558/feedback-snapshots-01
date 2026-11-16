if RUBY_VERSION < '1.9'
  require 'uuid'
else
  require 'securerandom'
end
require "openssl"
require "strscan"
require "rexml/document"

module OneLogin
  module RubySaml

    # SAML2 Auxiliary class
    #
    class Utils
      @@uuid_generator = UUID.new if RUBY_VERSION < '1.9'

      BINDINGS = { :post => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".freeze,
                   :redirect => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect".freeze }.freeze
      DSIG = "http://www.w3.org/2000/09/xmldsig#".freeze
      XENC = "http://www.w3.org/2001/04/xmlenc#".freeze
      XENC11 = "http://www.w3.org/2009/xmlenc11#".freeze

      # Key transport algorithms (used to wrap the symmetric content key).
      RSA_15        = "http://www.w3.org/2001/04/xmlenc#rsa-1_5".freeze
      RSA_OAEP_MGF1P = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p".freeze
      RSA_OAEP      = "http://www.w3.org/2009/xmlenc11#rsa-oaep".freeze
      KEY_TRANSPORT_ALGORITHMS = [RSA_15, RSA_OAEP_MGF1P, RSA_OAEP].freeze

      # Content encryption algorithms (used to encrypt the actual XML payload).
      TRIPLEDES_CBC = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc".freeze
      AES128_CBC    = "http://www.w3.org/2001/04/xmlenc#aes128-cbc".freeze
      AES192_CBC    = "http://www.w3.org/2001/04/xmlenc#aes192-cbc".freeze
      AES256_CBC    = "http://www.w3.org/2001/04/xmlenc#aes256-cbc".freeze
      AES128_GCM    = "http://www.w3.org/2009/xmlenc11#aes128-gcm".freeze
      AES192_GCM    = "http://www.w3.org/2009/xmlenc11#aes192-gcm".freeze
      AES256_GCM    = "http://www.w3.org/2009/xmlenc11#aes256-gcm".freeze
      CONTENT_ENCRYPTION_ALGORITHMS = [
        TRIPLEDES_CBC, AES128_CBC, AES192_CBC, AES256_CBC,
        AES128_GCM, AES192_GCM, AES256_GCM
      ].freeze

      # XML Encryption 1.1 mandates a 128 bit (16 byte) GCM authentication tag.
      GCM_TAG_LENGTH = 16

      # Digest algorithms allowed as the RSA-OAEP digest and MGF1 hash.
      OAEP_DIGEST_ALGORITHMS = {
        "http://www.w3.org/2000/09/xmldsig#sha1" => "SHA1",
        "http://www.w3.org/2001/04/xmlenc#sha256" => "SHA256",
        "http://www.w3.org/2001/04/xmldsig-more#sha384" => "SHA384",
        "http://www.w3.org/2001/04/xmlenc#sha512" => "SHA512"
      }.freeze

      # Raised when an encrypted element cannot be processed because its
      # declared algorithms, parameters or ciphertext do not satisfy the
      # XML Encryption requirements. Messages must never contain private
      # key material or decrypted plaintext.
      class DecryptionError < StandardError; end
      DURATION_FORMAT = %r(^
        (-?)P                       # 1: Duration sign
        (?:
          (?:(\d+)Y)?               # 2: Years
          (?:(\d+)M)?               # 3: Months
          (?:(\d+)D)?               # 4: Days
          (?:T
            (?:(\d+)H)?             # 5: Hours
            (?:(\d+)M)?             # 6: Minutes
            (?:(\d+(?:[.,]\d+)?)S)? # 7: Seconds
          )?
          |
          (\d+)W                    # 8: Weeks
        )
      $)x.freeze

      UUID_PREFIX = '_'
      @@prefix = '_'

      # Checks if the x509 cert provided is expired.
      #
      # @param cert [OpenSSL::X509::Certificate|String] The x509 certificate.
      # @return [true|false] Whether the certificate is expired.
      def self.is_cert_expired(cert)
        cert = OpenSSL::X509::Certificate.new(cert) if cert.is_a?(String)

        cert.not_after < Time.now
      end

      # Checks if the x509 cert provided has both started and has not expired.
      #
      # @param cert [OpenSSL::X509::Certificate|String] The x509 certificate.
      # @return [true|false] Whether the certificate is currently active.
      def self.is_cert_active(cert)
        cert = OpenSSL::X509::Certificate.new(cert) if cert.is_a?(String)
        now = Time.now
        cert.not_before <= now && cert.not_after >= now
      end

      # Interprets a ISO8601 duration value relative to a given timestamp.
      #
      # @param duration [String] The duration, as a string.
      # @param timestamp [Integer] The unix timestamp we should apply the
      #                            duration to. Optional, default to the
      #                            current time.
      #
      # @return [Integer] The new timestamp, after the duration is applied.
      #
      def self.parse_duration(duration, timestamp=Time.now.utc)
        return nil if RUBY_VERSION < '1.9'  # 1.8.7 not supported

        matches = duration.match(DURATION_FORMAT)

        if matches.nil?
          raise StandardError.new("Invalid ISO 8601 duration")
        end

        sign = matches[1] == '-' ? -1 : 1

        durYears, durMonths, durDays, durHours, durMinutes, durSeconds, durWeeks =
          matches[2..8].map do |match|
            if match
              match = match.tr(',', '.').gsub(/\.0*\z/, '')
              sign * (match.include?('.') ? match.to_f : match.to_i)
            else
              0
            end
          end

        datetime = Time.at(timestamp).utc.to_datetime
        datetime = datetime.next_year(durYears)
        datetime = datetime.next_month(durMonths)
        datetime = datetime.next_day((7*durWeeks) + durDays)
        datetime.to_time.utc.to_i + (durHours * 3600) + (durMinutes * 60) + durSeconds
      end

      # Return a properly formatted x509 certificate
      #
      # @param cert [String] The original certificate
      # @return [String] The formatted certificate
      #
      def self.format_cert(cert)
        # don't try to format an encoded certificate or if is empty or nil
        if cert.respond_to?(:ascii_only?)
          return cert if cert.nil? || cert.empty? || !cert.ascii_only?
        else
          return cert if cert.nil? || cert.empty? || cert.match(/\x0d/)
        end

        if cert.scan(/BEGIN CERTIFICATE/).length > 1
          formatted_cert = []
          cert.scan(/-{5}BEGIN CERTIFICATE-{5}[\n\r]?.*?-{5}END CERTIFICATE-{5}[\n\r]?/m) {|c|
            formatted_cert << format_cert(c)
          }
          formatted_cert.join("\n")
        else
          cert = cert.gsub(/\-{5}\s?(BEGIN|END) CERTIFICATE\s?\-{5}/, "")
          cert = cert.gsub(/\r/, "")
          cert = cert.gsub(/\n/, "")
          cert = cert.gsub(/\s/, "")
          cert = cert.scan(/.{1,64}/)
          cert = cert.join("\n")
          "-----BEGIN CERTIFICATE-----\n#{cert}\n-----END CERTIFICATE-----"
        end
      end

      # Return a properly formatted private key
      #
      # @param key [String] The original private key
      # @return [String] The formatted private key
      #
      def self.format_private_key(key)
        # don't try to format an encoded private key or if is empty
        return key if key.nil? || key.empty? || key.match(/\x0d/)

        # is this an rsa key?
        rsa_key = key.match("RSA PRIVATE KEY")
        key = key.gsub(/\-{5}\s?(BEGIN|END)( RSA)? PRIVATE KEY\s?\-{5}/, "")
        key = key.gsub(/\n/, "")
        key = key.gsub(/\r/, "")
        key = key.gsub(/\s/, "")
        key = key.scan(/.{1,64}/)
        key = key.join("\n")
        key_label = rsa_key ? "RSA PRIVATE KEY" : "PRIVATE KEY"
        "-----BEGIN #{key_label}-----\n#{key}\n-----END #{key_label}-----"
      end

      # Given a certificate string, return an OpenSSL::X509::Certificate object.
      #
      # @param cert [String] The original certificate
      # @return [OpenSSL::X509::Certificate] The certificate object
      #
      def self.build_cert_object(cert)
        return nil if cert.nil? || cert.empty?

        OpenSSL::X509::Certificate.new(format_cert(cert))
      end

      # Given a private key string, return an OpenSSL::PKey::RSA object.
      #
      # @param cert [String] The original private key
      # @return [OpenSSL::PKey::RSA] The private key object
      #
      def self.build_private_key_object(private_key)
        return nil if private_key.nil? || private_key.empty?

        OpenSSL::PKey::RSA.new(format_private_key(private_key))
      end

      # Build the Query String signature that will be used in the HTTP-Redirect binding
      # to generate the Signature
      # @param params [Hash] Parameters to build the Query String
      # @option params [String] :type 'SAMLRequest' or 'SAMLResponse'
      # @option params [String] :data Base64 encoded SAMLRequest or SAMLResponse
      # @option params [String] :relay_state The RelayState parameter
      # @option params [String] :sig_alg The SigAlg parameter
      # @return [String] The Query String
      #
      def self.build_query(params)
        type, data, relay_state, sig_alg = [:type, :data, :relay_state, :sig_alg].map { |k| params[k]}

        url_string = "#{type}=#{CGI.escape(data)}"
        url_string << "&RelayState=#{CGI.escape(relay_state)}" if relay_state
        url_string << "&SigAlg=#{CGI.escape(sig_alg)}"
      end

      # Reconstruct a canonical query string from raw URI-encoded parts, to be used in verifying a signature
      #
      # @param params [Hash] Parameters to build the Query String
      # @option params [String] :type 'SAMLRequest' or 'SAMLResponse'
      # @option params [String] :raw_data URI-encoded, base64 encoded SAMLRequest or SAMLResponse, as sent by IDP
      # @option params [String] :raw_relay_state URI-encoded RelayState parameter, as sent by IDP
      # @option params [String] :raw_sig_alg URI-encoded SigAlg parameter, as sent by IDP
      # @return [String] The Query String
      #
      def self.build_query_from_raw_parts(params)
        type, raw_data, raw_relay_state, raw_sig_alg = [:type, :raw_data, :raw_relay_state, :raw_sig_alg].map { |k| params[k]}

        url_string = "#{type}=#{raw_data}"
        url_string << "&RelayState=#{raw_relay_state}" if raw_relay_state
        url_string << "&SigAlg=#{raw_sig_alg}"
      end

      # Prepare raw GET parameters (build them from normal parameters
      # if not provided).
      #
      # @param rawparams [Hash] Raw GET Parameters
      # @param params [Hash] GET Parameters
      # @param lowercase_url_encoding [bool] Lowercase URL Encoding  (For ADFS urlencode compatibility)
      # @return [Hash] New raw parameters
      #
      def self.prepare_raw_get_params(rawparams, params, lowercase_url_encoding=false)
        rawparams ||= {}

        if rawparams['SAMLRequest'].nil? && !params['SAMLRequest'].nil?
          rawparams['SAMLRequest'] = escape_request_param(params['SAMLRequest'], lowercase_url_encoding)
        end
        if rawparams['SAMLResponse'].nil? && !params['SAMLResponse'].nil?
          rawparams['SAMLResponse'] = escape_request_param(params['SAMLResponse'], lowercase_url_encoding)
        end
        if rawparams['RelayState'].nil? && !params['RelayState'].nil?
          rawparams['RelayState'] = escape_request_param(params['RelayState'], lowercase_url_encoding)
        end
        if rawparams['SigAlg'].nil? && !params['SigAlg'].nil?
          rawparams['SigAlg'] = escape_request_param(params['SigAlg'], lowercase_url_encoding)
        end

        rawparams
      end

      def self.escape_request_param(param, lowercase_url_encoding)
        CGI.escape(param).tap do |escaped|
          next unless lowercase_url_encoding

          escaped.gsub!(/%[A-Fa-f0-9]{2}/) { |match| match.downcase }
        end
      end

      # Validate the Signature parameter sent on the HTTP-Redirect binding
      # @param params [Hash] Parameters to be used in the validation process
      # @option params [OpenSSL::X509::Certificate] cert The IDP public certificate
      # @option params [String] sig_alg The SigAlg parameter
      # @option params [String] signature The Signature parameter (base64 encoded)
      # @option params [String] query_string The full GET Query String to be compared
      # @return [Boolean] True if the Signature is valid, False otherwise
      #
      def self.verify_signature(params)
        cert, sig_alg, signature, query_string = [:cert, :sig_alg, :signature, :query_string].map { |k| params[k]}
        signature_algorithm = XMLSecurity::BaseDocument.new.algorithm(sig_alg)
        return cert.public_key.verify(signature_algorithm.new, Base64.decode64(signature), query_string)
      end

      # Build the status error message
      # @param status_code [String] StatusCode value
      # @param status_message [String] StatusMessage value
      # @return [String] The status error message
      def self.status_error_msg(error_msg, raw_status_code = nil, status_message = nil)
        error_msg = error_msg.dup

        unless raw_status_code.nil?
          if raw_status_code.include? "|"
            status_codes = raw_status_code.split(' | ')
            values = status_codes.collect do |status_code|
              status_code.split(':').last
            end
            printable_code = values.join(" => ")
          else
            printable_code = raw_status_code.split(':').last
          end
          error_msg << ', was ' + printable_code
        end

        unless status_message.nil?
          error_msg << ' -> ' + status_message
        end

        error_msg
      end

      # Obtains the decrypted string from an Encrypted node element in XML,
      # given multiple private keys to try.
      # @param encrypted_node [REXML::Element] The Encrypted element
      # @param private_keys [Array<OpenSSL::PKey::RSA>] The Service provider private key
      # @return [String] The decrypted data
      # @raise [ArgumentError] If no private keys are provided
      # @raise [DecryptionError] If none of the keys can decrypt the element
      def self.decrypt_multi(encrypted_node, private_keys)
        raise ArgumentError.new('private_keys must be specified') if !private_keys || private_keys.empty?

        error = nil
        private_keys.each do |key|
          begin
            return decrypt_data(encrypted_node, key)
          rescue DecryptionError => e
            error ||= e
          rescue OpenSSL::PKey::PKeyError, OpenSSL::Cipher::CipherError => e
            error ||= DecryptionError.new("Unable to decrypt the encrypted element: #{e.class}")
          end
        end

        raise(error || DecryptionError.new('Unable to decrypt the encrypted element'))
      end

      # Obtains the decrypted string from an Encrypted node element in XML
      # @param encrypted_node [REXML::Element] The Encrypted element
      # @param private_key [OpenSSL::PKey::RSA] The Service provider private key
      # @return [String] The decrypted data
      # @raise [DecryptionError] If the element or its algorithms are not valid
      def self.decrypt_data(encrypted_node, private_key)
        encrypt_data = REXML::XPath.first(
          encrypted_node,
          "./xenc:EncryptedData",
          { 'xenc' => XENC }
        )
        raise DecryptionError.new('EncryptedData element not found') if encrypt_data.nil?

        symmetric_key = retrieve_symmetric_key(encrypt_data, private_key)

        cipher_value = REXML::XPath.first(
          encrypt_data,
          "./xenc:CipherData/xenc:CipherValue",
          { 'xenc' => XENC }
        )
        raise DecryptionError.new('EncryptedData CipherValue element not found') if cipher_value.nil?

        node = Base64.decode64(element_text(cipher_value).to_s)
        algorithm = encryption_algorithm(encrypt_data)
        unless CONTENT_ENCRYPTION_ALGORITHMS.include?(algorithm)
          raise DecryptionError.new("Unsupported content encryption algorithm: #{algorithm}")
        end

        retrieve_content_plaintext(node, symmetric_key, algorithm)
      end

      # Obtains the symmetric key from the EncryptedData element
      # @param encrypt_data [REXML::Element]     The EncryptedData element
      # @param private_key [OpenSSL::PKey::RSA] The Service provider private key
      # @return [String] The symmetric key
      # @raise [DecryptionError] If the key transport material is not valid
      def self.retrieve_symmetric_key(encrypt_data, private_key)
        encrypted_key = REXML::XPath.first(
          encrypt_data,
          "./ds:KeyInfo/xenc:EncryptedKey | ./KeyInfo/xenc:EncryptedKey | //xenc:EncryptedKey[@Id=$id]",
          { "ds" => DSIG, "xenc" => XENC },
          { "id" => self.retrieve_symetric_key_reference(encrypt_data) }
        )
        raise DecryptionError.new('EncryptedKey element not found') if encrypted_key.nil?

        encrypted_symmetric_key_element = REXML::XPath.first(
          encrypted_key,
          "./xenc:CipherData/xenc:CipherValue",
          "xenc" => XENC
        )
        raise DecryptionError.new('EncryptedKey CipherValue element not found') if encrypted_symmetric_key_element.nil?

        cipher_text = Base64.decode64(element_text(encrypted_symmetric_key_element).to_s)

        algorithm = encryption_algorithm(encrypted_key)
        unless KEY_TRANSPORT_ALGORITHMS.include?(algorithm)
          raise DecryptionError.new("Unsupported key transport algorithm: #{algorithm}")
        end

        retrieve_wrapped_key(cipher_text, private_key, algorithm, encrypted_key)
      end

      def self.retrieve_symetric_key_reference(encrypt_data)
        REXML::XPath.first(
          encrypt_data,
          "substring-after(./ds:KeyInfo/ds:RetrievalMethod/@URI, '#')",
          { "ds" => DSIG }
        )
      end

      # Reads the mandatory Algorithm attribute of an EncryptionMethod element.
      # @param encrypted_element [REXML::Element] An EncryptedData or EncryptedKey element
      # @return [String] The declared algorithm URI
      # @raise [DecryptionError] If the attribute is missing or empty
      def self.encryption_algorithm(encrypted_element)
        encrypt_method = REXML::XPath.first(
          encrypted_element,
          "./xenc:EncryptionMethod",
          { 'xenc' => XENC }
        )
        raise DecryptionError.new('EncryptionMethod element not found') if encrypt_method.nil?

        algorithm = encrypt_method.attributes['Algorithm']
        if algorithm.nil? || algorithm.to_s.strip.empty?
          raise DecryptionError.new('EncryptionMethod Algorithm attribute is missing')
        end
        algorithm.to_s
      end

      # Decrypts the symmetric content key using a key transport algorithm.
      # Key transport and content encryption are intentionally handled by
      # separate methods so an algorithm URI can never be interpreted in the
      # wrong context.
      # @param cipher_text [String]              The wrapped key bytes
      # @param private_key [OpenSSL::PKey::RSA]  The Service provider private key
      # @param algorithm [String]                The key transport algorithm URI
      # @param encrypted_key [REXML::Element]    The EncryptedKey element (OAEP parameters)
      # @return [String] The symmetric key
      # @raise [DecryptionError] If the algorithm parameters are unsupported
      def self.retrieve_wrapped_key(cipher_text, private_key, algorithm, encrypted_key)
        case algorithm
        when RSA_15
          rsa_decrypt(private_key, cipher_text, OpenSSL::PKey::RSA::PKCS1_PADDING)
        when RSA_OAEP_MGF1P
          # The xmlenc#rsa-oaep-mgf1p identifier pins SHA-1 for both the
          # digest and MGF1; explicit parameters must not be honored here.
          oaep_decrypt(private_key, cipher_text, 'SHA1', 'SHA1')
        when RSA_OAEP
          oaep_digest, mgf1_digest = oaep_parameters(encrypted_key)
          oaep_decrypt(private_key, cipher_text, oaep_digest, mgf1_digest)
        else
          raise DecryptionError.new("Unsupported key transport algorithm: #{algorithm}")
        end
      rescue OpenSSL::PKey::PKeyError => e
        raise DecryptionError.new("Unable to decrypt the encrypted key: #{e.class}")
      end

      # Validates the DigestMethod and MGF1 parameters of an XML Encryption 1.1
      # RSA-OAEP EncryptionMethod. Only MGF1 with digest algorithms supported by
      # the toolkit are accepted; anything else is rejected instead of being
      # silently downgraded to the SHA-1 default.
      # @return [Array(String, String)] The OpenSSL digest names for OAEP and MGF1
      def self.oaep_parameters(encrypted_key)
        encrypt_method = REXML::XPath.first(
          encrypted_key,
          "./xenc:EncryptionMethod",
          { 'xenc' => XENC, 'xenc11' => XENC11, 'ds' => DSIG }
        )

        digest_node = REXML::XPath.first(
          encrypt_method,
          "./ds:DigestMethod",
          { 'ds' => DSIG }
        )
        digest_uri = digest_node && digest_node.attributes['Algorithm']
        oaep_digest = OAEP_DIGEST_ALGORITHMS[digest_uri] if digest_uri
        raise DecryptionError.new("Unsupported RSA-OAEP DigestMethod algorithm: #{digest_uri}") unless oaep_digest

        mgf_node = REXML::XPath.first(
          encrypt_method,
          "./xenc11:MGF1",
          { 'xenc11' => XENC11 }
        )

        if mgf_node.nil?
          # Absent MGF1 means MGF1 with the same digest as the OAEP hash.
          [oaep_digest, oaep_digest]
        else
          mgf_digest_node = REXML::XPath.first(mgf_node, "./ds:DigestMethod", { 'ds' => DSIG })
          mgf_digest_uri = mgf_digest_node && mgf_digest_node.attributes['Algorithm']
          mgf1_digest = OAEP_DIGEST_ALGORITHMS[mgf_digest_uri] if mgf_digest_uri
          unless mgf1_digest
            raise DecryptionError.new("Unsupported RSA-OAEP MGF1 DigestMethod algorithm: #{mgf_digest_uri}")
          end
          [oaep_digest, mgf1_digest]
        end
      end

      # Performs RSA-OAEP decryption, using the EVP based API when available
      # (the only option for non-SHA-1 digests) and falling back to the legacy
      # padding constant API for older openssl gem versions.
      def self.oaep_decrypt(private_key, cipher_text, oaep_digest, mgf1_digest)
        options = {
          "rsa_padding_mode" => "oaep",
          "rsa_oaep_md" => oaep_digest,
          "rsa_mgf1_md" => mgf1_digest
        }
        if private_key.respond_to?(:decrypt) && evp_oaep_supported?
          private_key.decrypt(cipher_text, options)
        elsif oaep_digest == 'SHA1' && mgf1_digest == 'SHA1'
          private_key.private_decrypt(cipher_text, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
        else
          raise DecryptionError.new('RSA-OAEP with non-SHA-1 parameters is not supported by this OpenSSL')
        end
      end

      def self.evp_oaep_supported?
        return @evp_oaep_supported unless @evp_oaep_supported.nil?

        probe_key = OpenSSL::PKey::RSA.new(2048)
        probe = probe_key.encrypt("\x00" * 8, {
          "rsa_padding_mode" => "oaep",
          "rsa_oaep_md" => "SHA256",
          "rsa_mgf1_md" => "SHA256"
        })
        probe_key.decrypt(probe, {
          "rsa_padding_mode" => "oaep",
          "rsa_oaep_md" => "SHA256",
          "rsa_mgf1_md" => "SHA256"
        })
        @evp_oaep_supported = true
      rescue StandardError
        @evp_oaep_supported = false
      end

      def self.rsa_decrypt(private_key, cipher_text, padding)
        private_key.private_decrypt(cipher_text, padding)
      end

      # Decrypts the XML payload using a block cipher content encryption
      # algorithm and validates every declared length. This never returns raw
      # ciphertext for an unknown algorithm: unsupported URIs are rejected.
      # @param cipher_text [String]  The encrypted payload (IV + data [+ GCM tag])
      # @param symmetric_key [String] The symmetric key
      # @param algorithm [String]    The content encryption algorithm URI
      # @return [String] The deciphered text
      # @raise [DecryptionError] If a length or authentication check fails
      def self.retrieve_content_plaintext(cipher_text, symmetric_key, algorithm)
        raise DecryptionError.new('Encrypted payload is empty') if cipher_text.nil? || cipher_text.empty?

        case algorithm
        when TRIPLEDES_CBC
          cbc_decrypt(cipher_text, symmetric_key, OpenSSL::Cipher.new('DES-EDE3-CBC').decrypt, 24)
        when AES128_CBC
          cbc_decrypt(cipher_text, symmetric_key, OpenSSL::Cipher.new('AES-128-CBC').decrypt, 16)
        when AES192_CBC
          cbc_decrypt(cipher_text, symmetric_key, OpenSSL::Cipher.new('AES-192-CBC').decrypt, 24)
        when AES256_CBC
          cbc_decrypt(cipher_text, symmetric_key, OpenSSL::Cipher.new('AES-256-CBC').decrypt, 32)
        when AES128_GCM
          gcm_decrypt(cipher_text, symmetric_key, 128)
        when AES192_GCM
          gcm_decrypt(cipher_text, symmetric_key, 192)
        when AES256_GCM
          gcm_decrypt(cipher_text, symmetric_key, 256)
        else
          raise DecryptionError.new("Unsupported content encryption algorithm: #{algorithm}")
        end
      rescue OpenSSL::Cipher::CipherError => e
        raise DecryptionError.new("Unable to decrypt the encrypted data: #{e.class}")
      end

      # Decrypts an XML Encryption CBC payload.
      #
      # RFC 5652 / XML Encryption block encryption uses PKCS#5/#7 padding, so
      # the cipher is first run with padding enabled and +final+ must validate
      # it. Some historical SAML deployments encrypted without padding (the
      # payload length was a block multiple on its own); those are accepted
      # only when the unpadded plaintext carries no padding at all. A payload
      # that decrypts to data which is neither valid PKCS padding nor a full,
      # unpadded block multiple is rejected. Callers must still parse the whole
      # plaintext as XML rather than truncating it at an expected closing tag.
      def self.cbc_decrypt(cipher_text, symmetric_key, cipher, expected_key_length)
        validate_key_length(symmetric_key, expected_key_length, cipher.name)
        iv_len = cipher.iv_len
        if cipher_text.bytesize <= iv_len
          raise DecryptionError.new('Encrypted payload is shorter than its initialization vector')
        end

        iv = cipher_text.byteslice(0, iv_len)
        data = cipher_text.byteslice(iv_len..-1)
        if data.bytesize % cipher.block_size != 0
          raise DecryptionError.new('Encrypted payload length is not a multiple of the cipher block size')
        end

        strict_cipher = OpenSSL::Cipher.new(cipher.name).decrypt
        strict_cipher.padding = 1
        strict_cipher.key = symmetric_key
        strict_cipher.iv = iv
        begin
          plaintext = strict_cipher.update(data)
          return plaintext << strict_cipher.final
        rescue OpenSSL::Cipher::CipherError
          # Fall through to the unpadded compatibility path below.
        end

        unpadded_cipher = OpenSSL::Cipher.new(cipher.name).decrypt
        unpadded_cipher.padding = 0
        unpadded_cipher.key = symmetric_key
        unpadded_cipher.iv = iv
        unpadded_cipher.update(data) << unpadded_cipher.final
      end

      # Decrypts an XML Encryption 1.1 AES-GCM payload, validating the 12 byte
      # IV, 16 byte authentication tag and declared key size. A failed
      # authentication check is reported as a decryption failure.
      def self.gcm_decrypt(cipher_text, symmetric_key, key_bits)
        auth_cipher = OpenSSL::Cipher::AES.new(key_bits, :GCM).decrypt
        validate_key_length(symmetric_key, key_bits / 8, auth_cipher.name)

        iv_len = auth_cipher.iv_len
        minimum_length = iv_len + GCM_TAG_LENGTH
        if cipher_text.bytesize < minimum_length
          raise DecryptionError.new("Encrypted payload must contain at least #{minimum_length} bytes (IV and GCM tag)")
        end

        iv = cipher_text.byteslice(0, iv_len)
        auth_tag = cipher_text.byteslice(-GCM_TAG_LENGTH, GCM_TAG_LENGTH)
        data = cipher_text.byteslice(iv_len...(cipher_text.bytesize - GCM_TAG_LENGTH))

        auth_cipher.padding = 0
        auth_cipher.key = symmetric_key
        auth_cipher.iv = iv
        auth_cipher.auth_data = ''
        auth_cipher.auth_tag = auth_tag
        plaintext = auth_cipher.update(data)
        begin
          plaintext << auth_cipher.final
        rescue OpenSSL::Cipher::CipherError
          raise DecryptionError.new('GCM authentication tag verification failed')
        end
        plaintext
      end

      def self.validate_key_length(symmetric_key, expected_key_length, cipher_name)
        if symmetric_key.nil? || symmetric_key.bytesize != expected_key_length
          raise DecryptionError.new("Invalid symmetric key length for #{cipher_name}: expected #{expected_key_length} bytes")
        end
      end

      # Parses decrypted ciphertext and enforces that it contains exactly one
      # well-formed XML element whose local name matches +element_name+.
      #
      # This replaces the legacy approach of truncating the plaintext at the
      # first expected closing tag, which silently accepted malformed padding
      # or an attacker controlled second element. Content before the root
      # element (other than whitespace, an XML declaration, processing
      # instructions or comments) and any second top level element are
      # rejected. Trailing non XML bytes, which legacy unpadded CBC ciphertexts
      # may carry, are tolerated only after the single root element has closed
      # and never become part of the returned element.
      #
      # @param plaintext [String]      The decrypted payload
      # @param element_name [String]   The required local name of the root
      # @param namespaces [Hash]       Namespace declarations for the wrapper
      # @return [REXML::Element] The parsed root element
      # @raise [DecryptionError] If the plaintext is not a single valid element
      def self.parse_decrypted_element(plaintext, element_name, namespaces)
        raise DecryptionError.new("Decrypted #{element_name} is empty") if plaintext.nil? || plaintext.empty?

        payload = plaintext.dup.force_encoding('BINARY')
        root_xml = single_root_xml(payload, element_name).dup.force_encoding('UTF-8')

        wrapper = namespaces.map { |prefix, uri| "xmlns:#{prefix}=\"#{uri}\"" }.join(' ')
        begin
          document = REXML::Document.new("<node #{wrapper}>#{root_xml}</node>")
        rescue REXML::ParseException, REXML::UndefinedNamespaceException, ArgumentError
          raise DecryptionError.new("Decrypted #{element_name} is not well formed XML")
        end

        element = document.root[0]
        if element.nil? || element.node_type != :element || element_local_name(element) != element_name
          raise DecryptionError.new("Decrypted element is not a valid #{element_name}")
        end

        element
      end

      # Returns the local (prefix independent) name of a REXML element.
      def self.element_local_name(element)
        name = element.respond_to?(:localname) ? element.localname : element.name
        name.to_s.split(':', 2).last
      end

      # Extracts the single root element from decrypted plaintext using a
      # depth counting lexical scan. The element boundary is found without
      # interpreting the trailing bytes as XML, while any extra root or
      # leading non XML content is rejected.
      def self.single_root_xml(payload, element_name)
        scanner = StringScanner.new(payload)
        skip_ignorable_head(scanner)
        raise DecryptionError.new("Decrypted #{element_name} does not contain a root element") if scanner.eos?

        opening = scanner.scan(/<((?:[A-Za-z_][\w.-]*:)?#{Regexp.escape(element_name)})(?=[\s\/>])/)
        unless opening
          raise DecryptionError.new("Decrypted #{element_name} contains content before its root element")
        end

        depth = 1
        until scanner.eos? || depth.zero?
          if (tag = scanner.scan(/<\/(?:[A-Za-z_][\w.-]*:)?[\w.-]+\s*>/))
            depth -= 1
            if depth.zero? && tag !~ /<\/((?:[A-Za-z_][\w.-]*:)?#{Regexp.escape(element_name)})\s*>\z/
              raise DecryptionError.new("Decrypted #{element_name} is not well formed XML")
            end
          elsif scanner.scan(/<!--.*?-->/m) || scanner.scan(/<\?.*?\?>/m)
            # Comments and processing instructions do not change depth.
          elsif scanner.scan(/<[A-Za-z_][\w.-]*(?::[\w.-]+)?[^>]*?\/>/m)
            # Self closing nested element.
          elsif scanner.scan(/<[A-Za-z_][\w.-]*(?::[\w.-]+)?[^>]*?>/m)
            depth += 1
          elsif scanner.scan(/[^<]+/)
            # Text content.
          else
            raise DecryptionError.new("Decrypted #{element_name} is not well formed XML")
          end
        end

        raise DecryptionError.new("Decrypted #{element_name} is not well formed XML") unless depth.zero?

        root_end = scanner.pos
        root_xml = payload.byteslice(0, root_end)

        # After the root, comments, processing instructions and whitespace are
        # ignored; a second element is rejected. Legacy CBC ciphertexts may
        # append non XML padding or garbage bytes here.
        remainder = payload.byteslice(root_end..-1).to_s
        stripped = remainder.gsub(/\s+/, '').gsub(/<!--.*?-->/m, '').gsub(/<\?.*?\?>/m, '')
        if stripped =~ /<[A-Za-z_]/
          raise DecryptionError.new("Decrypted #{element_name} contains more than one root element")
        end

        root_xml
      end

      def self.skip_ignorable_head(scanner)
        loop do
          previous = scanner.pos
          scanner.scan(/\s+/)
          scanner.scan(/<\?.*?\?>/m)
          scanner.scan(/<!--.*?-->/m)
          break if scanner.pos == previous || scanner.eos?
        end
      end

      def self.set_prefix(value)
        @@prefix = value
      end

      def self.prefix
        @@prefix
      end

      def self.uuid
        "#{prefix}" + (RUBY_VERSION < '1.9' ? "#{@@uuid_generator.generate}" : "#{SecureRandom.uuid}")
      end

      # Given two strings, attempt to match them as URIs using Rails' parse method.  If they can be parsed,
      # then the fully-qualified domain name and the host should perform a case-insensitive match, per the
      # RFC for URIs.  If Rails can not parse the string into URL pieces, return a boolean match of the
      # two strings.  This maintains the previous functionality.
      # @return [Boolean]
      def self.uri_match?(destination_url, settings_url)
        dest_uri = URI.parse(destination_url)
        acs_uri = URI.parse(settings_url)

        if dest_uri.scheme.nil? || acs_uri.scheme.nil? || dest_uri.host.nil? || acs_uri.host.nil?
          raise URI::InvalidURIError
        else
          dest_uri.scheme.downcase == acs_uri.scheme.downcase &&
            dest_uri.host.downcase == acs_uri.host.downcase &&
            dest_uri.path == acs_uri.path &&
            dest_uri.query == acs_uri.query
        end
      rescue URI::InvalidURIError
        original_uri_match?(destination_url, settings_url)
      end

      # If Rails' URI.parse can't match to valid URL, default back to the original matching service.
      # @return [Boolean]
      def self.original_uri_match?(destination_url, settings_url)
        destination_url == settings_url
      end

      # Given a REXML::Element instance, return the concatenation of all child text nodes. Assumes
      # that there all children other than text nodes can be ignored (e.g. comments). If nil is
      # passed, nil will be returned.
      def self.element_text(element)
        element.texts.map(&:value).join if element
      end
    end
  end
end
