require 'openssl'
require 'securerandom'
require 'base64'
require 'rexml/document'

# Builds XML Encryption samples for security tests. Every helper returns raw
# (non base64) XML so individual elements and algorithm attributes can be
# mutated before the document is parsed by the toolkit.
module EncryptionHelper
  extend self

  XENC = "http://www.w3.org/2001/04/xmlenc#"
  XENC11 = "http://www.w3.org/2009/xmlenc11#"
  DSIG = "http://www.w3.org/2000/09/xmldsig#"
  ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion"

  CBC = {
    "http://www.w3.org/2001/04/xmlenc#tripledes-cbc" => ["DES-EDE3-CBC", 24],
    "http://www.w3.org/2001/04/xmlenc#aes128-cbc" => ["AES-128-CBC", 16],
    "http://www.w3.org/2001/04/xmlenc#aes192-cbc" => ["AES-192-CBC", 24],
    "http://www.w3.org/2001/04/xmlenc#aes256-cbc" => ["AES-256-CBC", 32]
  }.freeze

  GCM = {
    "http://www.w3.org/2009/xmlenc11#aes128-gcm" => 128,
    "http://www.w3.org/2009/xmlenc11#aes192-gcm" => 192,
    "http://www.w3.org/2009/xmlenc11#aes256-gcm" => 256
  }.freeze

  OAEP_DIGEST_URIS = {
    "SHA1" => "http://www.w3.org/2000/09/xmldsig#sha1",
    "SHA256" => "http://www.w3.org/2001/04/xmlenc#sha256",
    "SHA384" => "http://www.w3.org/2001/04/xmldsig-more#sha384",
    "SHA512" => "http://www.w3.org/2001/04/xmlenc#sha512"
  }.freeze

  def b64(data)
    Base64.strict_encode64(data)
  end

  def wrap_rsa15(public_key, symmetric_key)
    public_key.public_encrypt(symmetric_key, OpenSSL::PKey::RSA::PKCS1_PADDING)
  end

  def wrap_oaep(public_key, symmetric_key, oaep_md = "SHA1", mgf1_md = oaep_md)
    public_key.encrypt(symmetric_key, {
      "rsa_padding_mode" => "oaep",
      "rsa_oaep_md" => oaep_md,
      "rsa_mgf1_md" => mgf1_md
    })
  end

  def encrypt_cbc(plaintext, cipher_name, key, iv, padding: 1)
    cipher = OpenSSL::Cipher.new(cipher_name).encrypt
    cipher.padding = padding
    cipher.key = key
    cipher.iv = iv
    cipher.update(plaintext) << cipher.final
  end

  def encrypt_gcm(plaintext, key_bits, key, iv)
    cipher = OpenSSL::Cipher::AES.new(key_bits, :GCM).encrypt
    cipher.iv = iv
    cipher.key = key
    cipher.auth_data = ""
    data = cipher.update(plaintext) << cipher.final
    [data, cipher.auth_tag]
  end

  def rsa_oaep_method_xml(digest_md: nil, mgf1_md: nil, include_mgf: digest_md ? true : false)
    if digest_md.nil?
      return %(<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"></xenc:EncryptionMethod>)
    end

    digest_uri = OAEP_DIGEST_URIS.fetch(digest_md)
    mgf = if include_mgf
            mgf_uri = OAEP_DIGEST_URIS.fetch(mgf1_md || digest_md)
            %(<xenc11:MGF1 Algorithm="http://www.w3.org/2009/xmlenc11#mgf1#{mgf1_md || digest_md}"><ds:DigestMethod Algorithm="#{mgf_uri}"/></xenc11:MGF1>)
          else
            ""
          end
    <<-XML.strip
<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#rsa-oaep">
  <ds:DigestMethod Algorithm="#{digest_uri}"/>
  #{mgf}
</xenc:EncryptionMethod>
XML
  end

  # Builds a full EncryptedAssertion document. Options:
  #   content_algorithm, key_algorithm, oaep_digest, oaep_mgf1, include_mgf,
  #   tamper_tag, tamper_iv, wrong_key_size, key_wrap_method_override,
  #   content_method_override, extra_payload
  def encrypted_assertion(public_key, plaintext = default_assertion, **options)
    content_algorithm = options.fetch(:content_algorithm, "http://www.w3.org/2001/04/xmlenc#aes128-cbc")
    _iv, payload_b64, symmetric_key = content_payload(public_key, plaintext, content_algorithm, options)

    key_transport_xml = encrypted_key_xml(public_key, symmetric_key, options)
    content_method = options[:content_method_override] || content_algorithm

    <<-XML.strip
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="#{ASSERTION_NS}" ID="_response1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
  <saml:EncryptedAssertion>
    <xenc:EncryptedData xmlns:xenc="#{XENC}" xmlns:xenc11="#{XENC11}" xmlns:ds="#{DSIG}" Type="http://www.w3.org/2001/04/xmlenc#Element">
      <xenc:EncryptionMethod Algorithm="#{content_method}"/>
      <ds:KeyInfo>
        #{key_transport_xml}
      </ds:KeyInfo>
      <xenc:CipherData><xenc:CipherValue>#{payload_b64}</xenc:CipherValue></xenc:CipherData>
    </xenc:EncryptedData>
  </saml:EncryptedAssertion>
</samlp:Response>
XML
  end

  def content_payload(public_key, plaintext, content_algorithm, options)
    if GCM.key?(content_algorithm)
      key_bits = GCM.fetch(content_algorithm)
      expected_size = key_bits / 8
      declared_key = options[:symmetric_key] || SecureRandom.random_bytes(expected_size)
      iv = options[:iv] || SecureRandom.random_bytes(12)
      # A wrong length key can only be exercised by encrypting with a valid
      # key and then wrapping the attacker chosen key for the SP to recover.
      encrypt_key = declared_key.bytesize == expected_size ? declared_key : SecureRandom.random_bytes(expected_size)
      data, tag = encrypt_gcm(plaintext, key_bits, encrypt_key, iv)
      tag = tamper(tag) if options[:tamper_tag]
      iv = tamper(iv) if options[:tamper_iv]
      [iv, b64(iv + data + tag), declared_key]
    else
      cipher_name, key_size = CBC.fetch(content_algorithm)
      key = options[:symmetric_key] || SecureRandom.random_bytes(key_size)
      iv = options[:iv] || SecureRandom.random_bytes(OpenSSL::Cipher.new(cipher_name).iv_len)
      if options[:cbc_padding] == 0
        block_size = OpenSSL::Cipher.new(cipher_name).block_size
        unless plaintext.bytesize % block_size == 0
          raise ArgumentError, "unpadded CBC plaintext must be a block multiple"
        end
      end
      data = encrypt_cbc(plaintext, cipher_name, key, iv, padding: options.fetch(:cbc_padding, 1))
      extra = options[:extra_payload] || ""
      [iv, b64(iv + data + extra), key]
    end
  end

  def encrypted_key_xml(public_key, symmetric_key, options)
    key_algorithm = options.fetch(:key_algorithm, "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p")
    override = options[:key_wrap_method_override]

    if override
      wrapped = wrap_oaep(public_key, symmetric_key)
      return encrypted_key_shell(override, wrapped)
    end

    case key_algorithm
    when "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
      encrypted_key_shell("http://www.w3.org/2001/04/xmlenc#rsa-1_5", wrap_rsa15(public_key, symmetric_key))
    when "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
      encrypted_key_shell("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p", wrap_oaep(public_key, symmetric_key))
    when "http://www.w3.org/2009/xmlenc11#rsa-oaep"
      oaep_md = options.fetch(:oaep_digest, "SHA256")
      mgf1_md = options.fetch(:oaep_mgf1, oaep_md)
      wrapped = wrap_oaep(public_key, symmetric_key, oaep_md, mgf1_md)
      method = rsa_oaep_method_xml(
        digest_md: oaep_md,
        mgf1_md: mgf1_md,
        include_mgf: options.fetch(:include_mgf, true)
      )
      <<-XML.strip
<xenc:EncryptedKey xmlns:xenc="#{XENC}" xmlns:xenc11="#{XENC11}" xmlns:ds="#{DSIG}">
  #{method}
  <xenc:CipherData><xenc:CipherValue>#{b64(wrapped)}</xenc:CipherValue></xenc:CipherData>
</xenc:EncryptedKey>
XML
    else
      raise ArgumentError, "unknown key algorithm #{key_algorithm}"
    end
  end

  def encrypted_key_shell(algorithm, wrapped_key)
    <<-XML.strip
<xenc:EncryptedKey xmlns:xenc="#{XENC}">
  <xenc:EncryptionMethod Algorithm="#{algorithm}"/>
  <xenc:CipherData><xenc:CipherValue>#{b64(wrapped_key)}</xenc:CipherValue></xenc:CipherData>
</xenc:EncryptedKey>
XML
  end

  def tamper(data)
    bytes = data.dup.force_encoding("BINARY").bytes
    bytes[0] = (bytes[0] ^ 0xFF)
    bytes.pack("C*")
  end

  def default_assertion
    <<-XML.strip
<saml:Assertion xmlns:saml="#{ASSERTION_NS}" ID="_assertion1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <saml:Subject><saml:NameID>alice@example.com</saml:NameID></saml:Subject>
</saml:Assertion>
XML
  end
end
