if RUBY_VERSION < '1.9'
  require 'uuid'
else
  require 'securerandom'
end
require "openssl"

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
      ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion".freeze
      PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol".freeze
      XML_PREFIXES = {
        "saml" => ASSERTION,
        "samlp" => PROTOCOL,
        "ds" => DSIG,
        "xenc" => XENC,
        "xs" => "http://www.w3.org/2001/XMLSchema",
        "xsi" => "http://www.w3.org/2001/XMLSchema-instance"
      }.freeze
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

      # Parses a decrypted XML payload that must consist of exactly one element
      # with the expected local name and namespace. Padding and namespace
      # declarations are handled explicitly; any additional plaintext outside
      # the root element is rejected.
      #
      # @param xml [String] The decrypted payload
      # @param expected_root [String] The expected root local name
      # @param expected_namespace [String] The expected root namespace URI
      # @param available_namespaces [Hash<String, String>] Namespace declarations
      #   in scope at the encrypted element, used to resolve prefixes that the
      #   plaintext inherited from its original document
      # @return [Array(String, REXML::Element)] The repaired XML string and the root element
      # @raise [ValidationError] if the payload is not a single, expected element
      #
      def self.parse_decrypted_element(xml, expected_root, expected_namespace = ASSERTION, available_namespaces = {})
        raise ValidationError.new("Empty decrypted #{expected_root}") if xml.nil? || xml.strip.empty?

        namespaces = XML_PREFIXES.merge(available_namespaces || {})
        source = xml
        injected = []

        5.times do
          begin
            nokogiri_document = XMLSecurity::BaseDocument.safe_load_xml(source, true)
            rexml_document = REXML::Document.new(source)
            validate_decrypted_root!(nokogiri_document, rexml_document, expected_root, expected_namespace)
            return [source, rexml_document.root]
          rescue StandardError => error
            prefixes = missing_namespace_prefixes(error) - injected
            if prefixes.empty? || prefixes.any? { |prefix| !namespaces.key?(prefix) }
              raise ValidationError.new("Invalid decrypted #{expected_root}: #{error.message}")
            end

            injected.concat(prefixes)
            source = inject_namespace_declarations(source, prefixes, namespaces)
          end
        end

        raise ValidationError.new("Invalid decrypted #{expected_root}: unable to resolve XML namespace prefixes")
      end

      # Validates that a parsed document contains exactly one root element with
      # the expected name and namespace.
      #
      # @param nokogiri_document [Nokogiri::XML::Document]
      # @param rexml_document [REXML::Document]
      # @param expected_root [String]
      # @param expected_namespace [String]
      def self.validate_decrypted_root!(nokogiri_document, rexml_document, expected_root, expected_namespace)
        raise "No root element found" if nokogiri_document.root.nil? || rexml_document.root.nil?

        noko_elements = nokogiri_document.children.select(&:element?)
        rexml_elements = rexml_document.children.select { |node| node.is_a?(REXML::Element) }
        raise "Multiple root elements found" unless noko_elements.size == 1 && rexml_elements.size == 1

        unexpected_noko = nokogiri_document.children.reject do |node|
          node.element? || node.comment? || node.processing_instruction? ||
            (node.text? && node.text.strip.empty?)
        end
        raise "Unexpected content outside the root element" unless unexpected_noko.empty?

        unexpected_rexml = rexml_document.children.reject do |node|
          node.is_a?(REXML::Element) || node.is_a?(REXML::Comment) || node.is_a?(REXML::XMLDecl) ||
            (node.respond_to?(:value) && node.value.to_s.strip.empty?)
        end
        raise "Unexpected content outside the root element" unless unexpected_rexml.empty?

        local_name = nokogiri_document.root.name.split(':').last
        unless local_name == expected_root
          raise "Unexpected root element '#{local_name}', expected '#{expected_root}'"
        end

        namespace = nokogiri_document.root.namespace && nokogiri_document.root.namespace.href
        unless namespace == expected_namespace
          raise "Unexpected namespace '#{namespace}' for root element '#{local_name}'"
        end
      end
      private_class_method :validate_decrypted_root!

      # Collects namespace declarations in scope at an element, so a decrypted
      # payload that inherited prefixes from its enclosing document can still be
      # parsed without inventing bindings for unknown prefixes.
      #
      # @param element [REXML::Element]
      # @return [Hash<String, String>]
      def self.in_scope_namespaces(element)
        element.namespaces || {}
      rescue StandardError
        {}
      end

      # Extracts namespace prefixes reported as missing by Nokogiri or REXML.
      #
      # @param error [StandardError]
      # @return [Array<String>]
      def self.missing_namespace_prefixes(error)
        message = error.message.to_s
        prefixes = message.scan(/Namespace prefix ([^\s]+)/).flatten
        prefixes.concat(message.scan(/Undefined prefix ([^\s]+) found/).flatten)
        prefixes.map { |prefix| prefix.sub(/[:;,].*/, '') }.reject(&:empty?).uniq
      end
      private_class_method :missing_namespace_prefixes

      # Injects namespace declarations on the root start tag. Only prefixes
      # known to the SAML/XML Signature/XML Encryption vocabularies are used.
      #
      # @param xml [String]
      # @param prefixes [Array<String>]
      # @param namespaces [Hash<String, String>]
      # @return [String]
      def self.inject_namespace_declarations(xml, prefixes, namespaces = XML_PREFIXES)
        start_index, end_index = root_tag_bounds(xml)
        existing_tag = xml[start_index..end_index]
        desired = prefixes.map { |prefix| [prefix, namespaces[prefix]] }

        # Replace a conflicting declaration instead of duplicating it, which is
        # not well-formed XML.
        desired.each do |prefix, namespace|
          pattern = /\s+xmlns:#{Regexp.escape(prefix)}\s*=\s*("[^"]*"|'[^']*')/
          existing_tag = existing_tag.sub(pattern, %( xmlns:#{prefix}="#{namespace}"))
        end

        missing = desired.reject { |prefix, _| existing_tag.include?("xmlns:#{prefix}=") }
        insertion = missing.map { |prefix, namespace| %(xmlns:#{prefix}="#{namespace}") }.join(' ')

        updated_tag = if insertion.empty?
          existing_tag
        else
          position = existing_tag.end_with?('/>') ? existing_tag.length - 2 : existing_tag.length - 1
          existing_tag[0...position] + ' ' + insertion + existing_tag[position..]
        end

        xml[0...start_index] + updated_tag + xml[(end_index + 1)..]
      end
      private_class_method :inject_namespace_declarations

      # Finds the byte bounds of the root start tag, skipping declarations,
      # comments, processing instructions and doctypes.
      #
      # @param xml [String]
      # @return [Array(Integer, Integer)]
      def self.root_tag_bounds(xml)
        length = xml.length
        index = xml.byteslice(0, 3) == "\xEF\xBB\xBF".b ? 3 : 0

        loop do
          index += 1 while index < length && xml[index] =~ /\s/
          if xml[index, 4] == '<!--'
            index = xml.index('-->', index) + 3
          elsif xml[index, 2] == '<?'
            index = xml.index('?>', index) + 2
          elsif xml[index, 2] == '<!'
            index = xml.index('>', index) + 1
          else
            break
          end
        end

        raise "No root element found" unless xml[index] == '<'

        start_index = index
        index += 1
        quote = nil
        while index < length
          character = xml[index]
          if quote
            quote = nil if character == quote
          else
            quote = character if character == '"' || character == "'"
            break if character == '>'
          end
          index += 1
        end

        [start_index, index]
      end
      private_class_method :root_tag_bounds

      # Obtains the decrypted string from an Encrypted node element in XML,
      # given multiple private keys to try.
      # @param encrypted_node [REXML::Element] The Encrypted element
      # @param private_keys [Array<OpenSSL::PKey::RSA>] The Service provider private key
      # @return [String] The decrypted data
      def self.decrypt_multi(encrypted_node, private_keys)
        raise ArgumentError.new('private_keys must be specified') if !private_keys || private_keys.empty?

        error = nil
        private_keys.each do |key|
          begin
            return decrypt_data(encrypted_node, key)
          rescue OpenSSL::PKey::PKeyError => e
            error ||= e
          end
        end

        raise(error) if error
      end

      # Obtains the decrypted string from an Encrypted node element in XML
      # @param encrypted_node [REXML::Element] The Encrypted element
      # @param private_key [OpenSSL::PKey::RSA] The Service provider private key
      # @return [String] The decrypted data
      def self.decrypt_data(encrypted_node, private_key)
        encrypt_data = REXML::XPath.first(
          encrypted_node,
          "./xenc:EncryptedData",
          { 'xenc' => XENC }
        )
        symmetric_key = retrieve_symmetric_key(encrypt_data, private_key)
        cipher_value = REXML::XPath.first(
          encrypt_data,
          "./xenc:CipherData/xenc:CipherValue",
          { 'xenc' => XENC }
        )
        node = Base64.decode64(element_text(cipher_value))
        encrypt_method = REXML::XPath.first(
          encrypt_data,
          "./xenc:EncryptionMethod",
          { 'xenc' => XENC }
        )
        algorithm = encrypt_method.attributes['Algorithm']
        retrieve_plaintext(node, symmetric_key, algorithm)
      end

      # Obtains the symmetric key from the EncryptedData element
      # @param encrypt_data [REXML::Element]     The EncryptedData element
      # @param private_key [OpenSSL::PKey::RSA] The Service provider private key
      # @return [String] The symmetric key
      def self.retrieve_symmetric_key(encrypt_data, private_key)
        encrypted_key = REXML::XPath.first(
          encrypt_data,
          "./ds:KeyInfo/xenc:EncryptedKey | ./KeyInfo/xenc:EncryptedKey | //xenc:EncryptedKey[@Id=$id]",
          { "ds" => DSIG, "xenc" => XENC },
          { "id" => self.retrieve_symetric_key_reference(encrypt_data) }
        )

        encrypted_symmetric_key_element = REXML::XPath.first(
          encrypted_key,
          "./xenc:CipherData/xenc:CipherValue",
          "xenc" => XENC
        )

        cipher_text = Base64.decode64(element_text(encrypted_symmetric_key_element))

        encrypt_method = REXML::XPath.first(
          encrypted_key,
          "./xenc:EncryptionMethod",
          "xenc" => XENC
        )

        algorithm = encrypt_method.attributes['Algorithm']
        retrieve_plaintext(cipher_text, private_key, algorithm)
      end

      def self.retrieve_symetric_key_reference(encrypt_data)
        REXML::XPath.first(
          encrypt_data,
          "substring-after(./ds:KeyInfo/ds:RetrievalMethod/@URI, '#')",
          { "ds" => DSIG }
        )
      end

      # Obtains the deciphered text
      # @param cipher_text [String]   The ciphered text
      # @param symmetric_key [String] The symmetric key used to encrypt the text
      # @param algorithm [String]     The encrypted algorithm
      # @return [String] The deciphered text
      def self.retrieve_plaintext(cipher_text, symmetric_key, algorithm)
        case algorithm
          when 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc' then cipher = OpenSSL::Cipher.new('DES-EDE3-CBC').decrypt
          when 'http://www.w3.org/2001/04/xmlenc#aes128-cbc' then cipher = OpenSSL::Cipher.new('AES-128-CBC').decrypt
          when 'http://www.w3.org/2001/04/xmlenc#aes192-cbc' then cipher = OpenSSL::Cipher.new('AES-192-CBC').decrypt
          when 'http://www.w3.org/2001/04/xmlenc#aes256-cbc' then cipher = OpenSSL::Cipher.new('AES-256-CBC').decrypt
          when 'http://www.w3.org/2009/xmlenc11#aes128-gcm' then auth_cipher = OpenSSL::Cipher::AES.new(128, :GCM).decrypt
          when 'http://www.w3.org/2009/xmlenc11#aes192-gcm' then auth_cipher = OpenSSL::Cipher::AES.new(192, :GCM).decrypt
          when 'http://www.w3.org/2009/xmlenc11#aes256-gcm' then auth_cipher = OpenSSL::Cipher::AES.new(256, :GCM).decrypt
          when 'http://www.w3.org/2001/04/xmlenc#rsa-1_5' then rsa = symmetric_key
          when 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p' then oaep = symmetric_key
        end

        if cipher
          iv_len = cipher.iv_len
          data = cipher_text[iv_len..-1]
          cipher.padding, cipher.key, cipher.iv = 0, symmetric_key, cipher_text[0..iv_len-1]
          assertion_plaintext = cipher.update(data)
          assertion_plaintext << cipher.final
          assertion_plaintext = remove_block_padding(assertion_plaintext, cipher.block_size)
        elsif auth_cipher
          iv_len, text_len, tag_len = auth_cipher.iv_len, cipher_text.length, 16
          data = cipher_text[iv_len..text_len-1-tag_len]
          auth_cipher.padding = 0
          auth_cipher.key = symmetric_key
          auth_cipher.iv = cipher_text[0..iv_len-1]
          auth_cipher.auth_data = ''
          auth_cipher.auth_tag = cipher_text[text_len-tag_len..-1]
          assertion_plaintext = auth_cipher.update(data)
          assertion_plaintext << auth_cipher.final
        elsif rsa
          rsa.private_decrypt(cipher_text)
        elsif oaep
          oaep.private_decrypt(cipher_text, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
        else
          cipher_text
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

      # Removes the padding of a block cipher plaintext. XML Encryption permits
      # arbitrary padding bytes as long as the final block encodes the padding
      # length, so the trailing length byte is authoritative. PKCS#7 padding is
      # also accepted.
      #
      # @param plaintext [String] The decrypted text including padding
      # @param block_size [Integer] The cipher block size
      # @return [String] The plaintext with the padding removed
      def self.remove_block_padding(plaintext, block_size)
        return plaintext if plaintext.nil? || plaintext.empty?

        padding_length = plaintext.getbyte(-1)
        if padding_length && padding_length > 0 && padding_length <= block_size && padding_length <= plaintext.bytesize
          plaintext = plaintext.byteslice(0, plaintext.bytesize - padding_length)
        end

        plaintext = '' if plaintext.bytesize == 1 && plaintext.getbyte(0) == 0
        plaintext
      end
    end
  end
end
