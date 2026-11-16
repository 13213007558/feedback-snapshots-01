require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/response'

# Security regression tests for the REXML + Nokogiri dual-parser pipeline.
#
# ruby-saml verifies XML signatures with Nokogiri while the business-facing
# accessors (name_id, attributes, sessionindex) read REXML nodes rebuilt from
# the Nokogiri canonicalization of the signed element. These tests prove that
# the node the signature Reference actually points at is the only node whose user
# information can reach a successful validation result, even when the document
# contains duplicated IDs, namespace rebindings, comments or elements sharing a
# local name in a different namespace.
class DualParserSecurityTest < Minitest::Test

  ASSERTION_NS = OneLogin::RubySaml::Response::ASSERTION
  PROTOCOL_NS  = OneLogin::RubySaml::Response::PROTOCOL
  DSIG_NS      = XMLSecurity::BaseDocument::DSIG
  C14N_NS      = XMLSecurity::BaseDocument::C14N

  SIGNED_ID      = "_signed-assertion-1"
  SIGNED_NAME_ID = "alice@example.com"
  SIGNED_ROLE    = "user"
  SIGNED_SESSION = "_session-signed-1"

  EVIL_NAME_ID = "mallory@evil.example"
  EVIL_ROLE    = "admin"
  EVIL_SESSION = "_session-evil"

  describe "dual parser signed-node selection" do

    before do
      @key  = OpenSSL::PKey::RSA.new(read_certificate("ruby-saml.key"))
      @cert = OpenSSL::X509::Certificate.new(read_certificate("ruby-saml.crt"))
      @signed_assertion = nil
    end

    let(:settings) do
      OneLogin::RubySaml::Settings.new.tap do |s|
        s.idp_cert = @cert.to_pem
        s.assertion_consumer_service_url = "https://sp.example.com/acs"
        s.sp_entity_id = "https://sp.example.com"
        s.idp_entity_id = "https://idp.example.com"
      end
    end

    # ---------- baseline and legitimate variations ----------

    it "accepts the baseline locally signed assertion and reads signed data" do
      response = build_response(signed_response_xml)

      assert response.is_valid?, response.errors.inspect
      assert_signature_points_at_signed_node(response)
      assert_business_reads_signed_data(response)
    end

    it "accepts a legal prefix change (saml -> saml2) without weakening selection" do
      xml = sign(
        response_shell(
          assertion_fragment(prefix: "saml2",
                             ns_decl: %(xmlns:saml2="#{ASSERTION_NS}"))
        )
      )
      response = build_response(xml)

      assert response.is_valid?, response.errors.inspect
      assert_signature_points_at_signed_node(response)
      assert_business_reads_signed_data(response)
    end

    it "accepts a default-namespace assertion (no prefix)" do
      xml = sign(response_shell(default_namespace_assertion_fragment))
      response = build_response(xml)

      assert response.is_valid?, response.errors.inspect
      assert_signature_points_at_signed_node(response)
      assert_business_reads_signed_data(response)
    end

    it "accepts comments inside the signed assertion (exclusive c14n strips them)" do
      xml = sign(
        response_shell(
          assertion_fragment(inner: "<!-- a comment inside the signed assertion -->")
        )
      )
      response = build_response(xml)

      assert response.is_valid?, response.errors.inspect
      assert_business_reads_signed_data(response)
    end

    # ---------- counterexamples: outer XML parses and the signature stays valid ----------

    it "keeps signed data when an unsigned duplicate-ID assertion follows the signed one" do
      evil = assertion_fragment(id: SIGNED_ID, name_id: EVIL_NAME_ID,
                                role: EVIL_ROLE, session_index: EVIL_SESSION)
      response = build_response(response_shell(signed_assertion + evil))

      # Two SAML assertions reject the document outright...
      refute response.is_valid?
      assert_includes response.errors, "SAML Response must contain 1 assertion"
      # ...and the accessors resolve through the signed node, never the evil one.
      assert_equal SIGNED_NAME_ID, response.name_id
      assert_equal SIGNED_ROLE, response.attributes["role"]
      assert_equal SIGNED_SESSION, response.sessionindex
    end

    it "reads only the signed node when a same-ID evil-namespace node follows it" do
      xml = response_shell(signed_assertion + wrapper(evil_namespace_assertion_fragment))

      # The arbitrary wrapper fails the SAML schema; neutralize that structural
      # check so the test exercises node selection rather than XSD validation.
      OneLogin::RubySaml::Response.any_instance.stubs(:valid_saml?).returns(true)
      response = build_response(xml)

      # With the unsigned duplicate after the signed node, the digest matches the
      # signed node and the response validates; business reads stay signed.
      assert response.is_valid?, response.errors.inspect
      assert_signature_points_at_signed_node(response)
      assert_business_reads_signed_data(response)
      refute_includes response.name_id.to_s, EVIL_NAME_ID
    end

    it "fails closed when a same-ID evil-namespace node precedes the signed node" do
      xml = response_shell(wrapper(evil_namespace_assertion_fragment) + signed_assertion)

      # Signature layer: the first matching node is the unsigned one, so the
      # signed digest cannot match and the ambiguity is explicitly reported.
      signed_document = XMLSecurity::SignedDocument.new(xml)
      refute signed_document.validate_signature(Base64.encode64(@cert.to_pem), true)
      assert(signed_document.errors.any? { |error| error.include?("Ambiguous Reference") },
             signed_document.errors.inspect)

      # Response layer: the document never reaches a successful validation and
      # unsigned user information is never exposed.
      OneLogin::RubySaml::Response.any_instance.stubs(:valid_saml?).returns(true)
      response = build_response(xml)
      refute response.is_valid?
      refute_equal EVIL_NAME_ID, response.name_id
      refute_equal EVIL_ROLE, response.attributes["role"]
      refute_equal EVIL_SESSION, response.sessionindex
    end

    it "does not treat a namespace-rebound Assertion as the signed SAML assertion" do
      rebound = <<~XML
      <wrapper xmlns:saml="urn:evil:rebound-namespace">
        <saml:Assertion ID="#{SIGNED_ID}" Version="2.0">
          <saml:Issuer>https://idp.example.com</saml:Issuer>
          <saml:Subject><saml:NameID>#{EVIL_NAME_ID}</saml:NameID></saml:Subject>
          <saml:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z">
            <saml:AudienceRestriction><saml:Audience>https://sp.example.com</saml:Audience></saml:AudienceRestriction>
          </saml:Conditions>
          <saml:AuthnStatement SessionIndex="#{EVIL_SESSION}"/>
          <saml:AttributeStatement>
            <saml:Attribute Name="role"><saml:AttributeValue>#{EVIL_ROLE}</saml:AttributeValue></saml:Attribute>
          </saml:AttributeStatement>
        </saml:Assertion>
      </wrapper>
      XML
      xml = response_shell(rebound + signed_assertion)

      signed_document = XMLSecurity::SignedDocument.new(xml)
      refute signed_document.validate_signature(Base64.encode64(@cert.to_pem), true)
      assert(signed_document.errors.any? { |error| error.include?("Ambiguous Reference") },
             signed_document.errors.inspect)

      OneLogin::RubySaml::Response.any_instance.stubs(:valid_saml?).returns(true)
      response = build_response(xml)
      refute response.is_valid?
      refute_equal EVIL_NAME_ID, response.name_id
      refute_equal EVIL_SESSION, response.sessionindex
    end

    it "exposes an explicit ambiguity error at the signature layer for duplicated IDs" do
      evil = assertion_fragment(id: SIGNED_ID, name_id: EVIL_NAME_ID,
                                role: EVIL_ROLE, session_index: EVIL_SESSION)
      signed_document = XMLSecurity::SignedDocument.new(response_shell(evil + signed_assertion))

      refute signed_document.validate_signature(Base64.encode64(@cert.to_pem), true)
      assert(signed_document.errors.any? { |error| error.include?("Ambiguous Reference") },
             signed_document.errors.inspect)
    end

    it "never returns evil attributes from a successful validation under any duplicate-ID layout" do
      after_xml  = response_shell(signed_assertion + wrapper(evil_namespace_assertion_fragment))
      before_xml = response_shell(wrapper(evil_namespace_assertion_fragment) + signed_assertion)

      OneLogin::RubySaml::Response.any_instance.stubs(:valid_saml?).returns(true)

      # Unsigned duplicate following the signed node: valid result, signed data only.
      after_response = build_response(after_xml)
      assert after_response.is_valid?, after_response.errors.inspect
      assert_equal [SIGNED_ROLE], after_response.attributes.multi("role")
      refute_includes after_response.attributes.to_h.values.flatten, EVIL_ROLE

      # Unsigned duplicate preceding the signed node: signature rejected, no evil data.
      before_signed_document = XMLSecurity::SignedDocument.new(before_xml)
      refute before_signed_document.validate_signature(Base64.encode64(@cert.to_pem), true)
      assert(before_signed_document.errors.any? { |error| error.include?("Ambiguous Reference") },
             before_signed_document.errors.inspect)

      before_response = build_response(before_xml)
      refute before_response.is_valid?
      refute_includes before_response.attributes.to_h.values.flatten, EVIL_ROLE
    end

    # ---------- helpers ----------

    def build_response(xml)
      OneLogin::RubySaml::Response.new(
        Base64.encode64(xml),
        settings: settings,
        skip_subject_confirmation: true
      )
    end

    def signed_response_xml
      @signed_response_xml ||= sign(response_shell(assertion_fragment))
    end

    # The signed assertion subtree, serialized exactly as it appears in the signed response.
    def signed_assertion
      @signed_assertion ||= REXML::XPath.first(
        REXML::Document.new(signed_response_xml),
        "//saml:Assertion",
        { "saml" => ASSERTION_NS }
      ).to_s
    end

    def sign(unsigned_xml)
      SigningHelper.sign_element(unsigned_xml, SIGNED_ID, @key, @cert)
    end

    def response_shell(assertion_or_inner)
      <<~XML
      <samlp:Response xmlns:samlp="#{PROTOCOL_NS}" xmlns:saml="#{ASSERTION_NS}" ID="_response-1" Version="2.0" IssueInstant="2026-11-17T00:00:00Z" Destination="https://sp.example.com/acs">
        <saml:Issuer>https://idp.example.com</saml:Issuer>
        <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
        #{assertion_or_inner}
      </samlp:Response>
      XML
    end

    def wrapper(inner)
      "<wrapper>#{inner}</wrapper>"
    end

    def assertion_fragment(prefix: "saml", id: SIGNED_ID, name_id: SIGNED_NAME_ID,
                           role: SIGNED_ROLE, session_index: SIGNED_SESSION,
                           ns_decl: "", inner: "")
      <<~XML
      <#{prefix}:Assertion #{ns_decl} ID="#{id}" Version="2.0" IssueInstant="2026-11-17T00:00:00Z">
        <#{prefix}:Issuer>https://idp.example.com</#{prefix}:Issuer>
        <#{prefix}:Subject>
          <#{prefix}:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">#{name_id}</#{prefix}:NameID>
          <#{prefix}:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <#{prefix}:SubjectConfirmationData NotOnOrAfter="2099-01-01T00:00:00Z" Recipient="https://sp.example.com/acs"/>
          </#{prefix}:SubjectConfirmation>
        </#{prefix}:Subject>
        <#{prefix}:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z">
          <#{prefix}:AudienceRestriction>
            <#{prefix}:Audience>https://sp.example.com</#{prefix}:Audience>
          </#{prefix}:AudienceRestriction>
        </#{prefix}:Conditions>
        <#{prefix}:AuthnStatement AuthnInstant="2026-11-17T00:00:00Z" SessionIndex="#{session_index}">
          <#{prefix}:AuthnContext>
            <#{prefix}:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</#{prefix}:AuthnContextClassRef>
          </#{prefix}:AuthnContext>
        </#{prefix}:AuthnStatement>
        <#{prefix}:AttributeStatement>
          <#{prefix}:Attribute Name="role"><#{prefix}:AttributeValue>#{role}</#{prefix}:AttributeValue></#{prefix}:Attribute>
        </#{prefix}:AttributeStatement>
        #{inner}
      </#{prefix}:Assertion>
      XML
    end

    def default_namespace_assertion_fragment
      <<~XML
      <Assertion xmlns="#{ASSERTION_NS}" ID="#{SIGNED_ID}" Version="2.0" IssueInstant="2026-11-17T00:00:00Z">
        <Issuer>https://idp.example.com</Issuer>
        <Subject>
          <NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">#{SIGNED_NAME_ID}</NameID>
          <SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <SubjectConfirmationData NotOnOrAfter="2099-01-01T00:00:00Z" Recipient="https://sp.example.com/acs"/>
          </SubjectConfirmation>
        </Subject>
        <Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z">
          <AudienceRestriction><Audience>https://sp.example.com</Audience></AudienceRestriction>
        </Conditions>
        <AuthnStatement AuthnInstant="2026-11-17T00:00:00Z" SessionIndex="#{SIGNED_SESSION}">
          <AuthnContext><AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</AuthnContextClassRef></AuthnContext>
        </AuthnStatement>
        <AttributeStatement><Attribute Name="role"><AttributeValue>#{SIGNED_ROLE}</AttributeValue></Attribute></AttributeStatement>
      </Assertion>
      XML
    end

    # Same local name (Assertion) and same ID value, but bound to an attacker namespace.
    def evil_namespace_assertion_fragment
      <<~XML
      <ev:Assertion xmlns:ev="urn:evil:different-namespace" ID="#{SIGNED_ID}" Version="2.0">
        <ev:Issuer>https://idp.example.com</ev:Issuer>
        <ev:Subject>
          <ev:NameID>#{EVIL_NAME_ID}</ev:NameID>
          <ev:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <ev:SubjectConfirmationData NotOnOrAfter="2099-01-01T00:00:00Z" Recipient="https://sp.example.com/acs"/>
          </ev:SubjectConfirmation>
        </ev:Subject>
        <ev:Conditions NotBefore="2000-01-01T00:00:00Z" NotOnOrAfter="2099-01-01T00:00:00Z">
          <ev:AudienceRestriction><ev:Audience>https://sp.example.com</ev:Audience></ev:AudienceRestriction>
        </ev:Conditions>
        <ev:AuthnStatement AuthnInstant="2026-11-17T00:00:00Z" SessionIndex="#{EVIL_SESSION}">
          <ev:AuthnContext><ev:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</ev:AuthnContextClassRef></ev:AuthnContext>
        </ev:AuthnStatement>
        <ev:AttributeStatement>
          <ev:Attribute Name="role"><ev:AttributeValue>#{EVIL_ROLE}</ev:AttributeValue></ev:Attribute>
        </ev:AttributeStatement>
      </ev:Assertion>
      XML
    end

    def assert_signature_points_at_signed_node(response)
      assert_equal SIGNED_ID, response.document.signed_element_id
      doc = response.send(:doc_to_validate)
      refute_nil doc.referenced_xml
      referenced_root = REXML::Document.new(doc.referenced_xml).root
      assert_equal SIGNED_ID, referenced_root.attributes["ID"]
      assert_equal ASSERTION_NS, referenced_root.namespace
    end

    def assert_business_reads_signed_data(response)
      assert_equal SIGNED_NAME_ID, response.name_id
      assert_equal SIGNED_ROLE, response.attributes["role"]
      assert_equal [SIGNED_ROLE], response.attributes.multi("role")
      assert_equal SIGNED_SESSION, response.sessionindex
      assert_equal SIGNED_ID, response.assertion_id
    end
  end

  # Produces an enveloped XML-DSig signature over an element inside a full
  # document, mirroring XMLSecurity::Document#sign_document but allowing the
  # Assertion (instead of the document root) to be the signed element.
  module SigningHelper
    module_function

    def sign_element(full_xml, target_id, key, cert)
      noko = Nokogiri::XML(full_xml)
      target = noko.at_xpath("//*[@ID=$id]", nil, { "id" => target_id })
      raise "target ##{target_id} not found" unless target

      inclusive = %w[#default samlp saml ds xs xsi]
      canonical = target.canonicalize(Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0, inclusive)
      digest = Base64.strict_encode64(OpenSSL::Digest::SHA256.digest(canonical))

      signature_xml = <<~XML
      <ds:Signature xmlns:ds="#{DSIG_NS}">
        <ds:SignedInfo>
          <ds:CanonicalizationMethod Algorithm="#{C14N_NS}"/>
          <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
          <ds:Reference URI="##{target_id}">
            <ds:Transforms>
              <ds:Transform Algorithm="#{DSIG_NS}enveloped-signature"/>
              <ds:Transform Algorithm="#{C14N_NS}">
                <ec:InclusiveNamespaces xmlns:ec="#{C14N_NS}" PrefixList="#{inclusive.join(' ')}"/>
              </ds:Transform>
            </ds:Transforms>
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
            <ds:DigestValue>#{digest}</ds:DigestValue>
          </ds:Reference>
        </ds:SignedInfo>
      </ds:Signature>
      XML

      signed_info = Nokogiri::XML(signature_xml).at_xpath("//ds:SignedInfo", "ds" => DSIG_NS)
      signed_info_canon = signed_info.canonicalize(Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0)
      signature_value = Base64.strict_encode64(key.sign(OpenSSL::Digest::SHA256.new, signed_info_canon))

      rexml = REXML::Document.new(full_xml)
      target_element = REXML::XPath.first(rexml, "//*[@ID=$id]", nil, { "id" => target_id })
      signature_element = REXML::Document.new(signature_xml).root
      signature_element.add_element("ds:SignatureValue").text = signature_value
      key_info = signature_element.add_element("ds:KeyInfo")
      x509_data = key_info.add_element("ds:X509Data")
      x509_data.add_element("ds:X509Certificate").text = Base64.strict_encode64(cert.to_der)

      issuer = target_element.elements.find { |element| element.name == "Issuer" }
      if issuer
        target_element.insert_after(issuer, signature_element)
      else
        target_element.insert_before(target_element.children.first, signature_element)
      end
      rexml.to_s
    end
  end
end
