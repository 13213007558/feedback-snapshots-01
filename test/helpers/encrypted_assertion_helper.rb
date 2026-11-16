require 'base64'
require 'openssl'
require 'securerandom'
require 'time'
require 'xml_security'

# Builds SAML Responses with locally generated signing/encryption material so
# the encrypted-assertion boundary tests do not rely on dated fixtures.
module EncryptedAssertionHelper
  ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion'.freeze
  PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol'.freeze
  DSIG = 'http://www.w3.org/2000/09/xmldsig#'.freeze
  XENC = 'http://www.w3.org/2001/04/xmlenc#'.freeze

  def material
    @material ||= begin
      certificate, private_key = CertificateHelper.generate_pair_material
      {
        :certificate => certificate,
        :private_key => private_key,
        :cert => OpenSSL::X509::Certificate.new(certificate),
        :key => OpenSSL::PKey::RSA.new(private_key)
      }
    end
  end

  def settings
    settings = OneLogin::RubySaml::Settings.new
    settings.idp_cert = material[:certificate]
    settings.private_key = material[:private_key]
    settings.sp_entity_id = 'http://rubysaml.com:3000/saml/metadata'
    settings.assertion_consumer_service_url = 'http://rubysaml.com:3000/saml/acs'
    settings
  end

  # @return [String] a schema-valid Assertion document
  def assertion_xml(name_id: 'alice@example.com', uid: 'alice', not_before: Time.now.utc - 600, not_on_or_after: Time.now.utc + 600)
    <<~XML.chomp
      <saml:Assertion xmlns:saml="#{ASSERTION}" xmlns:samlp="#{PROTOCOL}" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="_#{SecureRandom.hex(16)}" Version="2.0" IssueInstant="#{issue_instant}"><saml:Issuer>https://idp.example.com/metadata</saml:Issuer><saml:Subject><saml:NameID SPNameQualifier="http://rubysaml.com:3000/saml/metadata" Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">#{name_id}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="#{iso8601(not_on_or_after)}" Recipient="http://rubysaml.com:3000/saml/acs"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="#{iso8601(not_before)}" NotOnOrAfter="#{iso8601(not_on_or_after)}"><saml:AudienceRestriction><saml:Audience>http://rubysaml.com:3000/saml/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="#{issue_instant}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute Name="uid"><saml:AttributeValue>#{uid}</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>
    XML
  end

  # @return [String] the assertion signed by the local IdP material
  def signed_assertion(assertion = assertion_xml)
    document = XMLSecurity::Document.new(assertion)
    document.uuid = document.root.attributes['ID']
    document.sign_document(material[:key], material[:cert])
    document.to_s
  end

  # Encrypts an assertion with a fresh AES key wrapped for the SP material.
  def encrypt_assertion(plaintext)
    cipher = OpenSSL::Cipher.new('AES-128-CBC').encrypt
    cipher.padding = 0
    symmetric_key = SecureRandom.random_bytes(16)
    initialization_vector = SecureRandom.random_bytes(16)
    cipher.key = symmetric_key
    cipher.iv = initialization_vector

    padding_length = 16 - (plaintext.bytesize % 16)
    padding = SecureRandom.random_bytes(padding_length - 1) + [padding_length].pack('C')
    cipher_text = initialization_vector + cipher.update(plaintext.b + padding.b) + cipher.final

    encrypted_key = material[:key].public_key.public_encrypt(symmetric_key, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)

    "<saml:EncryptedAssertion xmlns:saml=\"#{ASSERTION}\">" \
      "<xenc:EncryptedData xmlns:xenc=\"#{XENC}\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\">" \
      "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"/>" \
      "<ds:KeyInfo xmlns:ds=\"#{DSIG}\"><xenc:EncryptedKey>" \
      "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"/>" \
      "<xenc:CipherData><xenc:CipherValue>#{base64(encrypted_key)}</xenc:CipherValue></xenc:CipherData>" \
      "</xenc:EncryptedKey></ds:KeyInfo>" \
      "<xenc:CipherData><xenc:CipherValue>#{base64(cipher_text)}</xenc:CipherValue></xenc:CipherData>" \
      "</xenc:EncryptedData></saml:EncryptedAssertion>"
  end

  # Builds a Response, optionally signing the outer message.
  #
  # @param assertion [String] plaintext assertion (already signed if desired)
  # @param response_signed [Boolean] whether to sign the outer Response
  # @return [String] base64-encoded SAML Response
  def encrypted_response(assertion, response_signed: true)
    response_id = "_#{SecureRandom.hex(16)}"
    response = "<samlp:Response xmlns:samlp=\"#{PROTOCOL}\" xmlns:saml=\"#{ASSERTION}\" " \
      "ID=\"#{response_id}\" Version=\"2.0\" IssueInstant=\"#{issue_instant}\" " \
      "Destination=\"http://rubysaml.com:3000/saml/acs\">" \
      "<saml:Issuer>https://idp.example.com/metadata</saml:Issuer>" \
      "<samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status>" \
      "#{encrypt_assertion(assertion)}</samlp:Response>"

    if response_signed
      document = XMLSecurity::Document.new(response)
      document.uuid = response_id
      document.sign_document(material[:key], material[:cert])
      response = document.to_s
    end

    Base64.encode64(response)
  end

  def tamper_signature_value(signed_xml)
    signed_xml.sub(/<ds:SignatureValue>(.)/) do
      replacement = Regexp.last_match(1) == 'A' ? 'B' : 'A'
      "<ds:SignatureValue>#{replacement}"
    end
  end

  def build_response(assertion, outer_signed:, inner_signed:)
    assertion = signed_assertion(assertion) if inner_signed
    encrypted_response(assertion, response_signed: outer_signed)
  end

  def base64(value)
    Base64.strict_encode64(value)
  end

  def issue_instant
    iso8601(Time.now.utc)
  end

  def iso8601(time)
    time.utc.strftime('%Y-%m-%dT%H:%M:%SZ')
  end
end
