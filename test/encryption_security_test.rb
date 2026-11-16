require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

class EncryptionSecurityTest < Minitest::Test
  include EncryptionHelper

  def private_key
    @private_key ||= OpenSSL::PKey::RSA.new(2048)
  end

  def public_key
    @public_key ||= private_key.public_key
  end

  def settings
    @settings ||= begin
      config = OneLogin::RubySaml::Settings.new
      config.private_key = private_key.to_pem
      config.idp_cert = ruby_saml_cert_text
      config.security[:want_assertions_signed] = false
      config
    end
  end

  def plaintext
    @plaintext ||= EncryptionHelper.default_assertion
  end

  def response_for(xml)
    OneLogin::RubySaml::Response.new(Base64.strict_encode64(xml), settings: settings)
  end

  def encrypted_node(xml)
    doc = REXML::Document.new(xml)
    REXML::XPath.first(
      doc,
      "(/p:Response/saml:EncryptedAssertion/)|(/p:Response/a:EncryptedAssertion/)",
      "p" => "urn:oasis:names:tc:SAML:2.0:protocol",
      "saml" => "urn:oasis:names:tc:SAML:2.0:assertion",
      "a" => "urn:oasis:names:tc:SAML:2.0:assertion"
    )
  end

  def decrypt(xml, key = private_key)
    OneLogin::RubySaml::Utils.decrypt_data(encrypted_node(xml), key)
  end

  def cipher_value_node(node)
    REXML::XPath.first(node, ".//xenc:EncryptedData/xenc:CipherData/xenc:CipherValue",
                       "xenc" => EncryptionHelper::XENC)
  end

  # ---- Algorithm dispatch -------------------------------------------------

  def test_rejects_unknown_content_algorithm_even_when_payload_looks_like_xml
    xml = EncryptionHelper.encrypted_assertion(
      public_key, plaintext,
      content_algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc",
      content_method_override: "http://www.w3.org/2001/04/xmlenc#made-up-cipher"
    )
    error = assert_raises(OneLogin::RubySaml::Utils::DecryptionError) { decrypt(xml) }
    assert_match(/Unsupported content encryption algorithm/, error.message)
  end

  def test_rejects_unknown_key_transport_algorithm
    xml = EncryptionHelper.encrypted_assertion(
      public_key, plaintext,
      key_wrap_method_override: "http://www.w3.org/2001/04/xmlenc#unknown-key-wrap"
    )
    error = assert_raises(OneLogin::RubySaml::Utils::DecryptionError) { decrypt(xml) }
    assert_match(/Unsupported key transport algorithm/, error.message)
  end

  def test_rejects_content_algorithm_uri_placed_on_encrypted_key
    xml = EncryptionHelper.encrypted_assertion(
      public_key, plaintext,
      key_wrap_method_override: "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
    )
    error = assert_raises(OneLogin::RubySaml::Utils::DecryptionError) { decrypt(xml) }
    assert_match(/Unsupported key transport algorithm/, error.message)
  end

  def test_rejects_key_transport_uri_placed_on_encrypted_data
    xml = EncryptionHelper.encrypted_assertion(
      public_key, plaintext,
      content_method_override: "http://www.w3.org/2009/xmlenc11#rsa-oaep"
    )
    error = assert_raises(OneLogin::RubySaml::Utils::DecryptionError) { decrypt(xml) }
    assert_match(/Unsupported content encryption algorithm/, error.message)
  end

  def test_rejects_missing_algorithm_attribute
    xml = EncryptionHelper.encrypted_assertion(public_key, plaintext)
    xml.sub!('<xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>',
             '<xenc:EncryptionMethod/>')
    error = assert_raises(OneLogin::RubySaml::Utils::DecryptionError) { decrypt(xml) }
    assert_match(/Algorithm attribute is missing/, error.message)
  end

  def test_unknown_algorithm_never_returns_raw_ciphertext
    xml = EncryptionHelper.encrypted_assertion(
      public_key, plaintext,
      content_method_override: "http://attacker.example/raw-bytes"
    )
    node = encrypted_node(xml)
    raw = Base64.decode64(cipher_value_node(node).text)
    error = assert_raises(OneLogin::RubySaml::Utils::DecryptionError) do
      OneLogin::RubySaml::Utils.decrypt_data(node, private_key)
    end
    refute_equal raw, error.message
  end

  # ---- AES GCM parameter validation --------------------------------------

  EncryptionHelper::GCM.each do |algorithm, key_bits|
    key_size = key_bits / 8

    define_method("test_decrypts_well_formed_#{algorithm.split('#').last}") do
      xml = EncryptionHelper.encrypted_assertion(
        public_key, plaintext,
        content_algorithm: algorithm,
        key_algorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
      )
      assert_equal plaintext, decrypt(xml)
    end

    define_method("test_rejects_wrong_key_length_for_#{algorithm.split('#').last}") do
      wrong_size = key_size == 16 ? 24 : 16
      xml = EncryptionHelper.encrypted_assertion(
        public_key, plaintext,
        content_algorithm: algorithm,
        symmetric_key: SecureRandom.random_bytes(wrong_size)
      )
      error = assert_raises(OneLogin::RubySaml::Utils::DecryptionError) { decrypt(xml) }
      assert_match(/Invalid symmetric key length/, error.message)
    end
  end

  def test_rejects_gcm_payload_shorter_than_iv_plus_tag
    xml = EncryptionHelper.encrypted_assertion(
      public_key, plaintext,
      content_algorithm: "http://www.w3.org/2009/xmlenc11#aes128-gcm"
    )
    node = encrypted_node(xml)
    cipher_value_node(node).text = Base64.strict_encode64(SecureRandom.random_bytes(12 + 8))
    error = assert_raises(OneLogin::RubySaml::Utils::DecryptionError) do
      OneLogin::RubySaml::Utils.decrypt_data(node, private_key)
    end
    assert_match(/IV and GCM tag/, error.message)
  end

  def test_fails_authentication_with_wrong_gcm_tag
    xml = EncryptionHelper.encrypted_assertion(
      public_key, plaintext,
      content_algorithm: "http://www.w3.org/2009/xmlenc11#aes128-gcm",
      tamper_tag: true
    )
    error = assert_raises(OneLogin::RubySaml::Utils::DecryptionError) { decrypt(xml) }
    assert_match(/GCM authentication tag verification failed/, error.message)
  end

  def test_fails_authentication_with_tampered_gcm_iv
    xml = EncryptionHelper.encrypted_assertion(
      public_key, plaintext,
      content_algorithm: "http://www.w3.org/2009/xmlenc11#aes256-gcm",
      tamper_iv: true
    )
    assert_raises(OneLogin::RubySaml::Utils::DecryptionError) { decrypt(xml) }
  end

  # ---- RSA OAEP parameters -----------------------------------------------

  %w[SHA1 SHA256 SHA384 SHA512].each do |digest|
    define_method("test_supports_rsa_oaep_with_#{digest}_digest_and_mgf1") do
      xml = EncryptionHelper.encrypted_assertion(
        public_key, plaintext,
        key_algorithm: "http://www.w3.org/2009/xmlenc11#rsa-oaep",
        oaep_digest: digest,
        oaep_mgf1: digest
      )
      assert_equal plaintext, decrypt(xml)
    end
  end

  def test_supports_distinct_oaep_and_mgf1_digests
    xml = EncryptionHelper.encrypted_assertion(
      public_key, plaintext,
      key_algorithm: "http://www.w3.org/2009/xmlenc11#rsa-oaep",
      oaep_digest: "SHA256",
      oaep_mgf1: "SHA1"
    )
    assert_equal plaintext, decrypt(xml)
  end

  def test_rejects_unsupported_oaep_digest_method
    xml = EncryptionHelper.encrypted_assertion(
      public_key, plaintext,
      key_algorithm: "http://www.w3.org/2009/xmlenc11#rsa-oaep",
      oaep_digest: "SHA256"
    )
    xml.sub!('http://www.w3.org/2001/04/xmlenc#sha256',
             'http://www.w3.org/2001/04/xmlenc#sha3-256')
    error = assert_raises(OneLogin::RubySaml::Utils::DecryptionError) { decrypt(xml) }
    assert_match(/Unsupported RSA-OAEP DigestMethod/, error.message)
  end

  def test_rejects_unsupported_mgf1_digest_method
    xml = EncryptionHelper.encrypted_assertion(
      public_key, plaintext,
      key_algorithm: "http://www.w3.org/2009/xmlenc11#rsa-oaep",
      oaep_digest: "SHA256",
      oaep_mgf1: "SHA256"
    )
    xml.sub!('<xenc11:MGF1 Algorithm="http://www.w3.org/2009/xmlenc11#mgf1SHA256"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/></xenc11:MGF1>',
             '<xenc11:MGF1 Algorithm="http://www.w3.org/2009/xmlenc11#mgf1SHA3-256"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha3-256"/></xenc11:MGF1>')
    error = assert_raises(OneLogin::RubySaml::Utils::DecryptionError) { decrypt(xml) }
    assert_match(/Unsupported RSA-OAEP MGF1 DigestMethod/, error.message)
  end

  def test_does_not_downgrade_sha256_oaep_to_sha1_default
    xml = EncryptionHelper.encrypted_assertion(
      public_key, plaintext,
      key_algorithm: "http://www.w3.org/2009/xmlenc11#rsa-oaep",
      oaep_digest: "SHA256",
      oaep_mgf1: "SHA256"
    )
    stripped = xml.sub(%r{<ds:DigestMethod.*?</xenc11:MGF1>}m, "")
    error = assert_raises(OneLogin::RubySaml::Utils::DecryptionError) { decrypt(stripped) }
    assert_match(/Unsupported RSA-OAEP DigestMethod/, error.message)
  end

  # ---- CBC padding --------------------------------------------------------

  EncryptionHelper::CBC.each_key do |algorithm|
    define_method("test_decrypts_valid_pkcs_padded_#{algorithm.split('#').last}") do
      xml = EncryptionHelper.encrypted_assertion(public_key, plaintext, content_algorithm: algorithm)
      assert_equal plaintext, decrypt(xml)
    end
  end

  def test_rejects_cbc_payload_not_multiple_of_block_size
    xml = EncryptionHelper.encrypted_assertion(public_key, plaintext)
    node = encrypted_node(xml)
    raw = Base64.decode64(cipher_value_node(node).text)
    cipher_value_node(node).text = Base64.strict_encode64(raw.byteslice(0, raw.bytesize - 1))
    error = assert_raises(OneLogin::RubySaml::Utils::DecryptionError) do
      OneLogin::RubySaml::Utils.decrypt_data(node, private_key)
    end
    assert_match(/not a multiple of the cipher block size/, error.message)
  end

  def test_rejects_malformed_cbc_padding_instead_of_truncating_to_end_tag
    # A payload whose strict PKCS validation fails must never be silently
    # truncated to the first Assertion closing tag. When the trailing
    # unpadded bytes form a second element, the single-root parser rejects it.
    key_bytes = SecureRandom.random_bytes(16)
    iv = SecureRandom.random_bytes(16)
    block_aligned = plaintext + " " * ((16 - plaintext.bytesize % 16) % 16)
    second_assertion = "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_evil\">injected</saml:Assertion>"
    padding = " " * ((16 - second_assertion.bytesize % 16) % 16)

    cipher = OpenSSL::Cipher.new("AES-128-CBC").encrypt
    cipher.padding = 0
    cipher.key = key_bytes
    cipher.iv = iv
    ciphertext = cipher.update(block_aligned + second_assertion + padding) << cipher.final

    wrapped = public_key.encrypt(key_bytes, { "rsa_padding_mode" => "oaep" })
    xml = EncryptionHelper.encrypted_assertion(
      public_key, block_aligned,
      symmetric_key: key_bytes,
      iv: iv,
      cbc_padding: 0
    )
    document = REXML::Document.new(xml)
    cipher_value_node(document).text = Base64.strict_encode64(iv + ciphertext)
    encrypted_key_value = REXML::XPath.first(
      document, ".//xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue",
      "xenc" => EncryptionHelper::XENC
    )
    encrypted_key_value.text = Base64.strict_encode64(wrapped)

    error = assert_raises(OneLogin::RubySaml::ValidationError) do
      response_for(document.to_s)
    end
    assert_match(/more than one root element|not well formed XML|not a valid Assertion/, error.message)
    refute_includes error.message, plaintext
  end

  # ---- Response entry point and error hygiene ----------------------------

  def test_response_rejects_unknown_algorithm_at_cryptographic_layer
    xml = EncryptionHelper.encrypted_assertion(
      public_key, plaintext,
      content_method_override: "http://www.w3.org/2001/04/xmlenc#unknown"
    )
    assert_raises(OneLogin::RubySaml::Utils::DecryptionError) { response_for(xml) }
  end

  def test_response_rejects_wrong_gcm_tag
    xml = EncryptionHelper.encrypted_assertion(
      public_key, plaintext,
      content_algorithm: "http://www.w3.org/2009/xmlenc11#aes128-gcm",
      tamper_tag: true
    )
    assert_raises(OneLogin::RubySaml::Utils::DecryptionError) { response_for(xml) }
  end

  def test_response_rejects_unsupported_oaep_parameters
    xml = EncryptionHelper.encrypted_assertion(
      public_key, plaintext,
      key_algorithm: "http://www.w3.org/2009/xmlenc11#rsa-oaep",
      oaep_digest: "SHA256"
    )
    xml.sub!('http://www.w3.org/2001/04/xmlenc#sha256',
             'http://www.w3.org/2001/04/xmlenc#sha3-256')
    assert_raises(OneLogin::RubySaml::Utils::DecryptionError) { response_for(xml) }
  end

  def test_response_keeps_decrypted_document_usable_with_valid_gcm
    xml = EncryptionHelper.encrypted_assertion(
      public_key, plaintext,
      content_algorithm: "http://www.w3.org/2009/xmlenc11#aes128-gcm"
    )
    response = response_for(xml)
    assert response.decrypted_document
    name_id = REXML::XPath.first(
      response.decrypted_document,
      "//a:NameID",
      "a" => "urn:oasis:names:tc:SAML:2.0:assertion"
    )
    assert_equal "alice@example.com", name_id.text
  end

  def test_error_messages_never_leak_private_key_or_plaintext
    xml = EncryptionHelper.encrypted_assertion(
      public_key, plaintext,
      content_algorithm: "http://www.w3.org/2009/xmlenc11#aes128-gcm",
      tamper_tag: true
    )
    error = assert_raises(OneLogin::RubySaml::Utils::DecryptionError) { response_for(xml) }
    refute_includes error.message, private_key.to_pem
    refute_includes error.message, plaintext
    refute_includes error.message, "BEGIN"
  end

  # ---- Decrypted plaintext structural parsing ----------------------------

  def test_parse_decrypted_element_accepts_a_single_root_with_legacy_trailing_bytes
    element = OneLogin::RubySaml::Utils.parse_decrypted_element(
      "#{plaintext}GARBAGE\x06\x07".b,
      "Assertion",
      "saml" => "urn:oasis:names:tc:SAML:2.0:assertion"
    )
    assert_equal "Assertion", OneLogin::RubySaml::Utils.element_local_name(element)
  end

  def test_parse_decrypted_element_rejects_content_before_root
    assert_raises(OneLogin::RubySaml::Utils::DecryptionError) do
      OneLogin::RubySaml::Utils.parse_decrypted_element(
        "GARBAGE#{plaintext}".b,
        "Assertion",
        "saml" => "urn:oasis:names:tc:SAML:2.0:assertion"
      )
    end
  end

  def test_parse_decrypted_element_rejects_a_second_root_element
    second = "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_evil\">x</saml:Assertion>"
    assert_raises(OneLogin::RubySaml::Utils::DecryptionError) do
      OneLogin::RubySaml::Utils.parse_decrypted_element(
        "#{plaintext}#{second}",
        "Assertion",
        "saml" => "urn:oasis:names:tc:SAML:2.0:assertion"
      )
    end
  end

  def test_parse_decrypted_element_rejects_wrong_root_name
    assert_raises(OneLogin::RubySaml::Utils::DecryptionError) do
      OneLogin::RubySaml::Utils.parse_decrypted_element(
        plaintext,
        "NameID",
        "saml" => "urn:oasis:names:tc:SAML:2.0:assertion"
      )
    end
  end

  def test_parse_decrypted_element_rejects_empty_plaintext
    assert_raises(OneLogin::RubySaml::Utils::DecryptionError) do
      OneLogin::RubySaml::Utils.parse_decrypted_element(
        "",
        "Assertion",
        "saml" => "urn:oasis:names:tc:SAML:2.0:assertion"
      )
    end
  end

  def test_parse_decrypted_element_rejects_malformed_xml
    assert_raises(OneLogin::RubySaml::Utils::DecryptionError) do
      OneLogin::RubySaml::Utils.parse_decrypted_element(
        "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">unclosed",
        "Assertion",
        "saml" => "urn:oasis:names:tc:SAML:2.0:assertion"
      )
    end
  end
end
