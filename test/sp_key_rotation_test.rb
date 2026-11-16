# Self-contained SP key-rotation verification for ruby-saml.
#
# Runs without test_helper / Bundler so it works offline:
#   ruby -Ilib test/sp_key_rotation_test.rb
#
# Rotation phase matrix (two local key pairs: OLD, NEW):
#
#   Phase 1 "publish new cert"   : certificate=OLD, private_key=OLD, certificate_new=NEW
#     metadata  -> signing [OLD, NEW], encryption [OLD, NEW]
#     signs with OLD key; can decrypt ONLY OLD-cert messages (NEW key not held yet)
#   Phase 2 "switch signing"     : sp_cert_multi signing=[NEW], encryption=[NEW, OLD]
#     metadata  -> signing [NEW], encryption [NEW, OLD]
#     signs with NEW key; decrypts messages for BOTH certs
#   Phase 3 "keep decrypting old": same config as phase 2
#     in-flight / replayed messages encrypted to OLD cert still decrypt
#   Phase 4 "retire old key"     : certificate=NEW, private_key=NEW
#     metadata  -> signing [NEW], encryption [NEW]
#     OLD-cert messages now FAIL to decrypt -> old key removal is only safe
#     after the IdP has confirmed switching encryption to the NEW cert.
#
# Explicit-failure checks (no accidental reliance on array order):
#   * cert/private-key mismatch -> AuthnRequest signature fails independent
#     verification against the published cert
#   * cert without private key  -> unsigned request + decryption raises
#   * validity boundary         -> check_sp_cert_expiration raises outside
#     [not_before, not_after], works inside

require 'openssl'
require 'base64'
require 'cgi'
require 'uri'
require 'rexml/document'
require 'minitest/autorun'
require 'timecop'

$LOAD_PATH.unshift(File.expand_path('../../lib', __FILE__))
require 'onelogin/ruby-saml'
require 'logger'

OneLogin::RubySaml::Logging.logger = Logger.new(File::NULL)

class SpKeyRotationTest < Minitest::Test
  MD_NS   = { 'md' => 'urn:oasis:names:tc:SAML:2.0:metadata', 'ds' => 'http://www.w3.org/2000/09/xmldsig#' }
  SIG_ALG = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'

  # --- key/cert helpers -----------------------------------------------------

  def self.make_key
    OpenSSL::PKey::RSA.new(2048)
  end

  def self.make_cert(key, name, not_before:, not_after:)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = rand(1..2_147_483_647)
    cert.subject = OpenSSL::X509::Name.parse("/CN=#{name}")
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = not_before
    cert.not_after = not_after
    cert.sign(key, OpenSSL::Digest::SHA256.new)
    cert
  end

  OLD_KEY  = make_key
  NEW_KEY  = make_key
  OLD_CERT = make_cert(OLD_KEY, 'sp-old', not_before: Time.now - 86_400, not_after: Time.now + 300 * 86_400)
  NEW_CERT = make_cert(NEW_KEY, 'sp-new', not_before: Time.now - 86_400, not_after: Time.now + 300 * 86_400)

  def fingerprint(cert)
    OpenSSL::Digest::SHA1.hexdigest(cert.to_der)
  end

  # Proves a private key matches a certificate by an actual sign/verify round.
  def key_matches_cert?(key, cert)
    nonce = "rotation-check-#{rand(1_000_000)}"
    cert.public_key.verify(OpenSSL::Digest::SHA256.new, key.sign(OpenSSL::Digest::SHA256.new, nonce), nonce)
  end

  # --- settings builders ----------------------------------------------------

  def base_settings
    settings = OneLogin::RubySaml::Settings.new
    settings.sp_entity_id = 'https://sp.example.com/saml/metadata'
    settings.assertion_consumer_service_url = 'https://sp.example.com/saml/acs'
    settings.idp_sso_service_url = 'https://idp.example.com/saml/sso'
    settings.idp_sso_service_binding = :redirect
    settings.security[:authn_requests_signed] = true
    settings.security[:want_assertions_encrypted] = true
    settings.security[:signature_method] = SIG_ALG
    settings.security[:digest_method] = SIG_ALG
    settings
  end

  def phase1_settings
    settings = base_settings
    settings.certificate = OLD_CERT.to_pem
    settings.private_key = OLD_KEY.to_pem
    settings.certificate_new = NEW_CERT.to_pem
    settings
  end

  def transition_settings(encryption_order: %i[new old])
    pairs = {
      new: { certificate: NEW_CERT.to_pem, private_key: NEW_KEY.to_pem },
      old: { certificate: OLD_CERT.to_pem, private_key: OLD_KEY.to_pem }
    }
    settings = base_settings
    settings.sp_cert_multi = {
      signing: [pairs[:new]],
      encryption: encryption_order.map { |which| pairs[which] }
    }
    settings
  end

  alias_method :phase2_settings, :transition_settings
  alias_method :phase3_settings, :transition_settings

  def phase4_settings
    settings = base_settings
    settings.certificate = NEW_CERT.to_pem
    settings.private_key = NEW_KEY.to_pem
    settings
  end

  # --- metadata inspection --------------------------------------------------

  def key_descriptor_fingerprints(settings, use)
    doc = REXML::Document.new(OneLogin::RubySaml::Metadata.new.generate(settings, false))
    REXML::XPath.match(doc, "//md:KeyDescriptor[@use='#{use}']", MD_NS).map do |kd|
      b64 = REXML::XPath.first(kd, './/ds:X509Certificate', MD_NS).text.gsub(/\s+/, '')
      OpenSSL::Digest::SHA1.hexdigest(Base64.decode64(b64))
    end
  end

  # Every cert published as use="encryption" must have a usable private key.
  def assert_encryption_keys_back_metadata!(settings)
    published = key_descriptor_fingerprints(settings, 'encryption')
    keys = settings.get_sp_decryption_keys
    refute_empty published, 'no encryption KeyDescriptor published'
    published.each do |fp|
      match = keys.any? { |k| k.public_key.to_der == published_cert_der(settings, fp) }
      assert match, "encryption KeyDescriptor #{fp} has no matching private key"
    end
  end

  def published_cert_der(settings, fp)
    doc = REXML::Document.new(OneLogin::RubySaml::Metadata.new.generate(settings, false))
    REXML::XPath.match(doc, "//md:KeyDescriptor", MD_NS).each do |kd|
      b64 = REXML::XPath.first(kd, './/ds:X509Certificate', MD_NS).text.gsub(/\s+/, '')
      der = Base64.decode64(b64)
      return OpenSSL::X509::Certificate.new(der).public_key.to_der if OpenSSL::Digest::SHA1.hexdigest(der) == fp
    end
    nil
  end

  # --- independent AuthnRequest verification --------------------------------

  # Rebuilds the signed string from the emitted URL itself (not via ruby-saml
  # helpers) and verifies the Signature with pure OpenSSL.
  def independently_verify_authn_request(settings, cert)
    url = OneLogin::RubySaml::Authrequest.new.create(settings)
    query = URI.parse(url).query
    signed_string, sig_param = query.split('&Signature=', 2)
    refute_nil sig_param, 'AuthnRequest URL carries no Signature parameter'
    signature = Base64.decode64(CGI.unescape(sig_param))
    cert.public_key.verify(OpenSSL::Digest::SHA256.new, signature, signed_string)
  end

  # --- encrypted assertion helpers ------------------------------------------

  # Builds a samlp:Response whose assertion is encrypted to `cert`
  # (AES-128-CBC data, RSA-OAEP key wrap), base64-encoded like a POST binding.
  def build_encrypted_response(cert, name_id)
    now = Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')
    assertion = "<saml:Assertion xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion' " \
                "ID='_assertion1' Version='2.0' IssueInstant='#{now}'>" \
                "<saml:Issuer>https://idp.example.com</saml:Issuer>" \
                "<saml:Subject><saml:NameID Format='urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'>#{name_id}</saml:NameID></saml:Subject>" \
                "</saml:Assertion>"

    aes = OpenSSL::Cipher.new('AES-128-CBC')
    aes.encrypt
    sym_key = aes.random_key
    iv = aes.random_iv
    cipher_text = aes.update(assertion) + aes.final

    wrapped_key = cert.public_key.public_encrypt(sym_key, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)

    xml = "<samlp:Response xmlns:samlp='urn:oasis:names:tc:SAML:2.0:protocol' ID='_resp1' Version='2.0' " \
          "IssueInstant='#{now}'>" \
          "<saml:EncryptedAssertion xmlns:saml='urn:oasis:names:tc:SAML:2.0:assertion'>" \
          "<xenc:EncryptedData xmlns:xenc='http://www.w3.org/2001/04/xmlenc#' Type='http://www.w3.org/2001/04/xmlenc#Element'>" \
          "<xenc:EncryptionMethod Algorithm='http://www.w3.org/2001/04/xmlenc#aes128-cbc'/>" \
          "<ds:KeyInfo xmlns:ds='http://www.w3.org/2000/09/xmldsig#'>" \
          "<xenc:EncryptedKey>" \
          "<xenc:EncryptionMethod Algorithm='http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'/>" \
          "<xenc:CipherData><xenc:CipherValue>#{Base64.strict_encode64(wrapped_key)}</xenc:CipherValue></xenc:CipherData>" \
          "</xenc:EncryptedKey></ds:KeyInfo>" \
          "<xenc:CipherData><xenc:CipherValue>#{Base64.strict_encode64(iv + cipher_text)}</xenc:CipherValue></xenc:CipherData>" \
          "</xenc:EncryptedData></saml:EncryptedAssertion></samlp:Response>"
    Base64.strict_encode64(xml)
  end

  # End-to-end: Response#initialize decrypts via settings.get_sp_decryption_keys.
  # The NameID is read from the decrypted document (the response fixture is
  # intentionally unsigned, so Response#name_id's signed-assertion path does
  # not apply here).
  def decrypt_name_id(settings, cert, name_id = 'user@example.com')
    response = OneLogin::RubySaml::Response.new(
      build_encrypted_response(cert, name_id), settings: settings
    )
    node = REXML::XPath.first(
      response.decrypted_document,
      '/p:Response/a:Assertion/a:Subject/a:NameID',
      { 'p' => 'urn:oasis:names:tc:SAML:2.0:protocol', 'a' => 'urn:oasis:names:tc:SAML:2.0:assertion' }
    )
    node && node.text
  end

  # ==========================================================================
  # Phase 1: new cert published first; old key still does all the work
  # ==========================================================================

  def test_phase1_metadata_publishes_old_and_new_certs
    settings = phase1_settings
    assert_equal [fingerprint(OLD_CERT), fingerprint(NEW_CERT)], key_descriptor_fingerprints(settings, 'signing')
    assert_equal [fingerprint(OLD_CERT), fingerprint(NEW_CERT)], key_descriptor_fingerprints(settings, 'encryption')
  end

  def test_phase1_signs_with_old_key_only
    settings = phase1_settings
    cert, key = settings.get_sp_signing_pair
    assert_equal fingerprint(OLD_CERT), fingerprint(cert)
    assert key_matches_cert?(key, OLD_CERT)
    assert independently_verify_authn_request(settings, OLD_CERT)
    refute independently_verify_authn_request(settings, NEW_CERT)
  end

  def test_phase1_decrypts_old_but_not_new_cert_messages
    settings = phase1_settings
    assert_equal 'user@example.com', decrypt_name_id(settings, OLD_CERT)
    # NEW cert is published but its private key is not held yet: must fail loudly.
    assert_raises(OpenSSL::PKey::PKeyError) { decrypt_name_id(settings, NEW_CERT) }
  end

  # ==========================================================================
  # Phase 2: signing switched to NEW key; both keys decrypt
  # ==========================================================================

  def test_phase2_metadata_publishes_new_signing_and_both_encryption
    settings = phase2_settings
    assert_equal [fingerprint(NEW_CERT)], key_descriptor_fingerprints(settings, 'signing')
    assert_equal [fingerprint(NEW_CERT), fingerprint(OLD_CERT)], key_descriptor_fingerprints(settings, 'encryption')
  end

  def test_phase2_signs_with_new_key_only
    settings = phase2_settings
    cert, key = settings.get_sp_signing_pair
    assert_equal fingerprint(NEW_CERT), fingerprint(cert)
    assert key_matches_cert?(key, NEW_CERT)
    assert independently_verify_authn_request(settings, NEW_CERT)
    refute independently_verify_authn_request(settings, OLD_CERT)
  end

  def test_phase2_decrypts_both_old_and_new_cert_messages
    settings = phase2_settings
    assert_equal 2, settings.get_sp_decryption_keys.size
    assert_equal 'user@example.com', decrypt_name_id(settings, NEW_CERT)
    assert_equal 'user@example.com', decrypt_name_id(settings, OLD_CERT)
  end

  def test_phase2_every_published_encryption_cert_has_a_private_key
    assert_encryption_keys_back_metadata!(phase2_settings)
  end

  # ==========================================================================
  # Phase 3: keep decrypting old messages (in-flight during the switch)
  # ==========================================================================

  def test_phase3_message_encrypted_before_switch_still_decrypts
    # The IdP produced this response while phase 1 metadata was in effect.
    settings = phase3_settings
    assert_equal 'inflight@example.com', decrypt_name_id(settings, OLD_CERT, 'inflight@example.com')
  end

  def test_phase3_decryption_does_not_depend_on_array_order
    settings = phase3_settings(encryption_order: %i[old new])
    assert_equal 'user@example.com', decrypt_name_id(settings, NEW_CERT)
    assert_equal 'user@example.com', decrypt_name_id(settings, OLD_CERT)
  end

  # ==========================================================================
  # Phase 4: old key retired
  # ==========================================================================

  def test_phase4_metadata_publishes_only_new_cert
    settings = phase4_settings
    assert_equal [fingerprint(NEW_CERT)], key_descriptor_fingerprints(settings, 'signing')
    assert_equal [fingerprint(NEW_CERT)], key_descriptor_fingerprints(settings, 'encryption')
  end

  def test_phase4_signs_and_decrypts_with_new_key_only
    settings = phase4_settings
    assert independently_verify_authn_request(settings, NEW_CERT)
    assert_equal 'user@example.com', decrypt_name_id(settings, NEW_CERT)
  end

  def test_phase4_old_cert_messages_fail_loudly_after_retirement
    settings = phase4_settings
    # Safe-removal criterion: this raises only when no OLD-cert message can
    # still legitimately arrive; until then the old key must stay configured.
    assert_raises(OpenSSL::PKey::PKeyError) { decrypt_name_id(settings, OLD_CERT) }
  end

  # ==========================================================================
  # Explicit failures: mismatch, missing key, validity boundary, array order
  # ==========================================================================

  def test_cert_key_mismatch_fails_independent_verification
    settings = base_settings
    settings.sp_cert_multi = {
      signing: [{ certificate: NEW_CERT.to_pem, private_key: OLD_KEY.to_pem }],
      encryption: [{ certificate: NEW_CERT.to_pem, private_key: NEW_KEY.to_pem }]
    }
    # Metadata happily publishes the NEW cert...
    assert_equal [fingerprint(NEW_CERT)], key_descriptor_fingerprints(settings, 'signing')
    # ...but the request is signed by the WRONG key: independent check fails.
    refute independently_verify_authn_request(settings, NEW_CERT)
    assert independently_verify_authn_request(settings, OLD_CERT)
    refute key_matches_cert?(settings.get_sp_signing_key, NEW_CERT)
  end

  def test_cert_without_private_key_means_no_signature_and_no_decryption
    settings = base_settings
    settings.certificate = NEW_CERT.to_pem
    settings.private_key = nil

    url = OneLogin::RubySaml::Authrequest.new.create(settings)
    refute_includes URI.parse(url).query, 'Signature=', 'request must go out unsigned when no key is held'

    error = assert_raises(OneLogin::RubySaml::ValidationError) do
      OneLogin::RubySaml::Response.new(build_encrypted_response(NEW_CERT, 'u@example.com'), settings: settings)
    end
    assert_includes error.message, 'no SP private key'
  end

  def test_sp_cert_multi_rejects_pair_without_private_key
    settings = base_settings
    settings.sp_cert_multi = { signing: [{ certificate: NEW_CERT.to_pem }] }
    assert_raises(ArgumentError) { settings.get_sp_certs }
  end

  def test_cert_validity_boundary_with_check_sp_cert_expiration
    boundary_key = self.class.make_key
    boundary_cert = self.class.make_cert(
      boundary_key, 'sp-boundary',
      not_before: Time.utc(2026, 11, 1, 0, 0, 0),
      not_after: Time.utc(2026, 12, 1, 0, 0, 0)
    )
    settings = base_settings
    settings.certificate = boundary_cert.to_pem
    settings.private_key = boundary_key.to_pem
    settings.security[:check_sp_cert_expiration] = true

    Timecop.freeze(Time.utc(2026, 11, 15, 12, 0, 0)) do
      assert_equal [fingerprint(boundary_cert)], key_descriptor_fingerprints(settings, 'signing')
    end
    # Last valid instant (not_after is inclusive).
    Timecop.freeze(Time.utc(2026, 12, 1, 0, 0, 0)) do
      assert_equal [fingerprint(boundary_cert)], key_descriptor_fingerprints(settings, 'signing')
    end
    # One second past expiry: hard failure, no silent fallback.
    Timecop.freeze(Time.utc(2026, 12, 1, 0, 0, 1)) do
      error = assert_raises(OneLogin::RubySaml::ValidationError) { settings.get_sp_certs }
      assert_includes error.message, 'expired'
    end
    # Not yet valid: same hard failure.
    Timecop.freeze(Time.utc(2026, 10, 31, 23, 59, 59)) do
      assert_raises(OneLogin::RubySaml::ValidationError) { settings.get_sp_certs }
    end
  end

  def test_signing_cert_is_explicitly_the_first_signing_pair
    pairs = {
      new: { certificate: NEW_CERT.to_pem, private_key: NEW_KEY.to_pem },
      old: { certificate: OLD_CERT.to_pem, private_key: OLD_KEY.to_pem }
    }
    settings = base_settings
    settings.sp_cert_multi = { signing: [pairs[:old], pairs[:new]], encryption: [pairs[:new]] }
    # ruby-saml always signs with signing.first: rotation must reorder the
    # config deliberately, never rely on incidental ordering.
    assert_equal fingerprint(OLD_CERT), fingerprint(settings.get_sp_signing_pair[0])
    settings.sp_cert_multi = { signing: [pairs[:new], pairs[:old]], encryption: [pairs[:new]] }
    assert_equal fingerprint(NEW_CERT), fingerprint(settings.get_sp_signing_pair[0])
  end
end
