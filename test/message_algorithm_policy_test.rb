require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

# Tests for the migratable message algorithm policy:
# inbound allowed SignatureMethod/DigestMethod lists (XML signatures and
# HTTP-Redirect SigAlg) are configured independently from the outbound
# algorithms and from the IdP certificate fingerprint algorithm.
module MessageAlgorithmPolicyHelpers
  RSA_SHA1   = XMLSecurity::Document::RSA_SHA1
  RSA_SHA256 = XMLSecurity::Document::RSA_SHA256
  SHA1       = XMLSecurity::Document::SHA1
  SHA256     = XMLSecurity::Document::SHA256

  STRICT_OPTS = {
    :allowed_signature_methods => [RSA_SHA256],
    :allowed_digest_methods    => [SHA256]
  }.freeze

  # Temporary compatibility scope for legacy IdPs that still sign with SHA-1
  COMPAT_OPTS = {
    :allowed_signature_methods => [RSA_SHA1, RSA_SHA256],
    :allowed_digest_methods    => [SHA1, SHA256]
  }.freeze

  def settings
    @settings ||= OneLogin::RubySaml::Settings.new
  end

  def sign_response_xml(signature_method, digest_method)
    xml = Base64.decode64(fixture("test_sign.xml"))
    document = XMLSecurity::Document.new(xml)
    document.sign_document(ruby_saml_key, ruby_saml_cert, signature_method, digest_method)
    document.to_s
  end

  def sha1_fingerprint
    OpenSSL::Digest::SHA1.hexdigest(ruby_saml_cert.to_der)
  end

  def signed_document(signature_method, digest_method)
    XMLSecurity::SignedDocument.new(sign_response_xml(signature_method, digest_method))
  end

  def validate_signed_response(signature_method, digest_method)
    response = OneLogin::RubySaml::Response.new(sign_response_xml(signature_method, digest_method))
    response.settings = settings
    Timecop.freeze(Time.parse("2015-03-18T04:50:24Z")) do
      response.is_valid?
    end
    response
  end
end

class MessageAlgorithmPolicyTest < Minitest::Test
  include MessageAlgorithmPolicyHelpers

  describe "inbound XML signature policy" do
    include MessageAlgorithmPolicyHelpers
    it "accepts SHA-256 signature and digest under a strict policy" do
      document = signed_document(RSA_SHA256, SHA256)
      assert document.validate_document(sha1_fingerprint, true, STRICT_OPTS), document.errors.inspect
    end

    it "rejects a SHA-1 message under a strict policy" do
      document = signed_document(RSA_SHA1, SHA1)
      assert !document.validate_document(sha1_fingerprint, true, STRICT_OPTS)
      assert_includes document.errors, "Signature Method '#{RSA_SHA1}' is not allowed"
    end

    it "raises on a SHA-1 message under a strict policy when soft is false" do
      document = signed_document(RSA_SHA1, SHA1)
      exception = assert_raises(OneLogin::RubySaml::ValidationError) do
        document.validate_document(sha1_fingerprint, false, STRICT_OPTS)
      end
      assert_equal "Signature Method '#{RSA_SHA1}' is not allowed", exception.message
    end

    it "accepts a SHA-1 message under the temporary compatibility policy" do
      document = signed_document(RSA_SHA1, SHA1)
      assert document.validate_document(sha1_fingerprint, true, COMPAT_OPTS), document.errors.inspect
    end

    it "rejects a SHA-1 digest even when the SHA-256 signature method is allowed" do
      document = signed_document(RSA_SHA256, SHA1)
      assert !document.validate_document(sha1_fingerprint, true, STRICT_OPTS)
      assert_includes document.errors, "Digest Method '#{SHA1}' is not allowed"
    end

    it "rejects a SHA-1 signature method even when the SHA-256 digest is allowed" do
      document = signed_document(RSA_SHA1, SHA256)
      assert !document.validate_document(sha1_fingerprint, true, STRICT_OPTS)
      assert_includes document.errors, "Signature Method '#{RSA_SHA1}' is not allowed"
    end

    it "accepts a mixed SHA-256 signature with SHA-1 digest when the compat policy allows both axes" do
      document = signed_document(RSA_SHA256, SHA1)
      assert document.validate_document(sha1_fingerprint, true, COMPAT_OPTS), document.errors.inspect
    end

    it "rejects an algorithm that is not even supported instead of falling back to SHA-1" do
      document = signed_document(RSA_SHA256, SHA256)
      opts = {
        :allowed_signature_methods => [RSA_SHA256],
        :allowed_digest_methods    => [SHA256]
      }
      assert document.validate_document(sha1_fingerprint, true, opts), document.errors.inspect
      # A message declaring an unknown algorithm URI is not in the allowlist,
      # so it is rejected rather than silently treated as SHA-1.
      xml = sign_response_xml(RSA_SHA256, SHA256)
      xml.sub!(RSA_SHA256, 'http://example.com/rsa-sha999')
      tampered = XMLSecurity::SignedDocument.new(xml)
      assert !tampered.validate_document(sha1_fingerprint, true, opts)
      assert_includes tampered.errors, "Signature Method 'http://example.com/rsa-sha999' is not allowed"
    end

    it "rejects conflicting SignatureMethod declarations even when both are allowed" do
      xml = sign_response_xml(RSA_SHA256, SHA256)
      xml.sub!("<ds:Reference ", "<ds:SignatureMethod Algorithm=\"#{RSA_SHA1}\"/><ds:Reference ")
      document = XMLSecurity::SignedDocument.new(xml)
      assert !document.validate_document(sha1_fingerprint, true, COMPAT_OPTS)
      assert_includes document.errors, "Conflicting SignatureMethod or DigestMethod declarations"
    end

    it "rejects conflicting DigestMethod declarations across references even when both are allowed" do
      xml = sign_response_xml(RSA_SHA256, SHA256)
      extra_reference = "<ds:Reference URI=\"#_other\"><ds:DigestMethod Algorithm=\"#{SHA1}\"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference>"
      xml.sub!("</ds:SignedInfo>", "#{extra_reference}</ds:SignedInfo>")
      document = XMLSecurity::SignedDocument.new(xml)
      assert !document.validate_document(sha1_fingerprint, true, COMPAT_OPTS)
      assert_includes document.errors, "Conflicting SignatureMethod or DigestMethod declarations"
    end
  end

  describe "settings driven response validation" do
    include MessageAlgorithmPolicyHelpers

    before do
      settings.assertion_consumer_service_url = "http://recipient"
      settings.idp_cert = ruby_saml_cert_text
    end

    it "rejects a SHA-1 response when security allows only SHA-256" do
      settings.security[:allowed_signature_methods] = [RSA_SHA256]
      settings.security[:allowed_digest_methods] = [SHA256]
      response = validate_signed_response(RSA_SHA1, SHA1)
      assert_includes response.errors, "Invalid Signature on SAML Response"
      assert_includes response.document.errors, "Signature Method '#{RSA_SHA1}' is not allowed"
    end

    it "accepts a SHA-1 response with the default legacy-compatible security settings" do
      response = validate_signed_response(RSA_SHA1, SHA1)
      assert_empty response.errors
    end

    it "accepts a SHA-256 response when security allows only SHA-256" do
      settings.security[:allowed_signature_methods] = [RSA_SHA256]
      settings.security[:allowed_digest_methods] = [SHA256]
      response = validate_signed_response(RSA_SHA256, SHA256)
      assert_empty response.errors
    end
  end

  describe "certificate fingerprint algorithm independence" do
    include MessageAlgorithmPolicyHelpers

    before do
      settings.assertion_consumer_service_url = "http://recipient"
      settings.idp_cert = ruby_saml_cert_text
      settings.security[:allowed_signature_methods] = [RSA_SHA256]
      settings.security[:allowed_digest_methods] = [SHA256]
    end

    it "still rejects a SHA-1 message when the fingerprint algorithm is upgraded to SHA-256" do
      settings.idp_cert_fingerprint_algorithm = SHA256
      response = validate_signed_response(RSA_SHA1, SHA1)
      assert_includes response.errors, "Invalid Signature on SAML Response"
      assert_includes response.document.errors, "Signature Method '#{RSA_SHA1}' is not allowed"
    end

    it "accepts a SHA-256 message when the fingerprint algorithm is upgraded to SHA-256" do
      settings.idp_cert_fingerprint_algorithm = SHA256
      response = validate_signed_response(RSA_SHA256, SHA256)
      assert_empty response.errors
    end

    it "accepts a SHA-256 message while the fingerprint algorithm stays SHA-1" do
      assert_equal SHA1, settings.idp_cert_fingerprint_algorithm
      response = validate_signed_response(RSA_SHA256, SHA256)
      assert_empty response.errors
    end
  end

  describe "HTTP-Redirect binding inbound policy" do
    include MessageAlgorithmPolicyHelpers

    before do
      settings.security[:logout_requests_signed] = true
      settings.security[:logout_responses_signed] = true
      settings.certificate = ruby_saml_cert_text
      settings.private_key = ruby_saml_key_text
      settings.idp_cert = ruby_saml_cert_text
      settings.idp_slo_service_url = "http://example.com?field=value"
    end

    def signed_logout_request(signature_method)
      settings.security[:signature_method] = signature_method
      params = OneLogin::RubySaml::Logoutrequest.new.create_params(settings, :RelayState => 'http://example.com')
      params['RelayState'] = params[:RelayState]
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new(params['SAMLRequest'], :get_params => params)
      logout_request.settings = settings
      logout_request
    end

    def signed_logout_response(signature_method)
      settings.security[:signature_method] = signature_method
      params = OneLogin::RubySaml::SloLogoutresponse.new.create_params(settings, random_id, "Custom Logout Message", :RelayState => 'http://example.com')
      params['RelayState'] = params[:RelayState]
      OneLogin::RubySaml::Logoutresponse.new(params['SAMLResponse'], settings, :get_params => params)
    end

    it "rejects a SHA-1 SigAlg on LogoutRequest under a strict policy" do
      settings.security[:allowed_signature_methods] = [RSA_SHA256]
      logout_request = signed_logout_request(RSA_SHA1)
      assert !logout_request.send(:validate_signature)
      assert_includes logout_request.errors, "Invalid Signature on Logout Request"
    end

    it "accepts a SHA-1 SigAlg on LogoutRequest under the temporary compatibility policy" do
      settings.security[:allowed_signature_methods] = [RSA_SHA1, RSA_SHA256]
      logout_request = signed_logout_request(RSA_SHA1)
      assert logout_request.send(:validate_signature), logout_request.errors.inspect
    end

    it "accepts a SHA-256 SigAlg on LogoutRequest under a strict policy" do
      settings.security[:allowed_signature_methods] = [RSA_SHA256]
      logout_request = signed_logout_request(RSA_SHA256)
      assert logout_request.send(:validate_signature), logout_request.errors.inspect
    end

    it "rejects a SHA-1 SigAlg on LogoutResponse under a strict policy" do
      settings.security[:allowed_signature_methods] = [RSA_SHA256]
      logout_response = signed_logout_response(RSA_SHA1)
      assert !logout_response.send(:validate_signature)
      assert_includes logout_response.errors, "Invalid Signature on Logout Response"
    end

    it "accepts a SHA-256 SigAlg on LogoutResponse under a strict policy" do
      settings.security[:allowed_signature_methods] = [RSA_SHA256]
      logout_response = signed_logout_response(RSA_SHA256)
      assert logout_response.send(:validate_signature), logout_response.errors.inspect
    end

    it "rejects conflicting raw and decoded SigAlg declarations on LogoutRequest" do
      settings.security[:allowed_signature_methods] = [RSA_SHA1, RSA_SHA256]
      settings.security[:signature_method] = RSA_SHA256
      params = OneLogin::RubySaml::Logoutrequest.new.create_params(settings, :RelayState => 'http://example.com')
      params['RelayState'] = params[:RelayState]
      raw_params = {
        'SAMLRequest' => params['SAMLRequest'],
        'SigAlg'      => CGI.escape(RSA_SHA1)
      }
      logout_request = OneLogin::RubySaml::SloLogoutrequest.new(
        params['SAMLRequest'],
        :get_params => params,
        :raw_get_params => raw_params
      )
      logout_request.settings = settings
      assert !logout_request.send(:validate_signature)
      assert_includes logout_request.errors, "Conflicting SigAlg declarations on Logout Request"
    end

    it "rejects conflicting raw and decoded SigAlg declarations on LogoutResponse" do
      settings.security[:allowed_signature_methods] = [RSA_SHA1, RSA_SHA256]
      settings.security[:signature_method] = RSA_SHA256
      params = OneLogin::RubySaml::SloLogoutresponse.new.create_params(settings, random_id, "Custom Logout Message", :RelayState => 'http://example.com')
      params['RelayState'] = params[:RelayState]
      raw_params = {
        'SAMLResponse' => params['SAMLResponse'],
        'SigAlg'       => CGI.escape(RSA_SHA1)
      }
      logout_response = OneLogin::RubySaml::Logoutresponse.new(
        params['SAMLResponse'],
        settings,
        :get_params => params,
        :raw_get_params => raw_params
      )
      assert !logout_response.send(:validate_signature)
      assert_includes logout_response.errors, "Conflicting SigAlg declarations on Logout Response"
    end
  end

  describe "outbound algorithm selection" do
    include MessageAlgorithmPolicyHelpers

    before do
      settings.security[:authn_requests_signed] = true
      settings.certificate = ruby_saml_cert_text
      settings.private_key = ruby_saml_key_text
    end

    it "uses security[:signature_method] for the Redirect binding SigAlg" do
      settings.security[:signature_method] = RSA_SHA256
      params = OneLogin::RubySaml::Authrequest.new.create_params(settings)
      assert_equal RSA_SHA256, params['SigAlg']
    end

    it "uses security[:signature_method] and security[:digest_method] for embedded XML signatures" do
      settings.security[:embed_sign] = true
      settings.security[:signature_method] = RSA_SHA256
      settings.security[:digest_method] = SHA256
      xml = OneLogin::RubySaml::Authrequest.new.create_authentication_xml_doc(settings).to_s
      assert_includes xml, RSA_SHA256
      assert_includes xml, SHA256
    end
  end
end
