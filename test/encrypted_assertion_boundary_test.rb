require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))

require 'onelogin/ruby-saml/response'

# Covers the trust boundaries around encrypted assertions:
#  * an outer signature covers the Response (and the encrypted Assertion payload)
#  * an inner signature covers the decrypted Assertion only
#  * successful decryption on its own is never treated as authentication
class EncryptedAssertionBoundaryTest < Minitest::Test
  include EncryptedAssertionHelper

  def response_for(assertion, outer_signed:, inner_signed:)
    OneLogin::RubySaml::Response.new(
      build_response(assertion, outer_signed: outer_signed, inner_signed: inner_signed),
      :settings => settings
    )
  end

  # --- valid deployment orders -------------------------------------------

  def test_accepts_outer_signed_response_with_encrypted_only_assertion
    response = response_for(assertion_xml, outer_signed: true, inner_signed: false)

    assert response.is_valid?, response.errors.inspect
    assert_equal({ :response => true, :assertion => false }, response.signature_coverage)
    assert_equal "alice@example.com", response.nameid
    assert_equal "alice", response.attributes[:uid]
  end

  def test_accepts_unsigned_response_with_signed_decrypted_assertion
    response = response_for(assertion_xml, outer_signed: false, inner_signed: true)

    assert response.is_valid?, response.errors.inspect
    assert_equal({ :response => false, :assertion => true }, response.signature_coverage)
    assert_equal "alice@example.com", response.nameid
    assert_equal "alice", response.attributes[:uid]
  end

  def test_reports_both_boundaries_when_both_are_signed
    response = response_for(assertion_xml, outer_signed: true, inner_signed: true)

    assert response.is_valid?, response.errors.inspect
    assert_equal({ :response => true, :assertion => true }, response.signature_coverage)
    assert_equal "alice@example.com", response.nameid
  end

  def test_rejects_decryption_without_any_signature
    response = response_for(assertion_xml, outer_signed: false, inner_signed: false)

    refute response.is_valid?
    refute response.signature_coverage[:response]
    refute response.signature_coverage[:assertion]
    assert_nil response.nameid
    assert_empty response.attributes.all
  end

  # --- original document integrity ---------------------------------------

  def test_keeps_the_original_response_encrypted_for_outer_signature_checks
    signed = signed_assertion(assertion_xml)
    response = OneLogin::RubySaml::Response.new(
      build_response(signed, outer_signed: true, inner_signed: false),
      :settings => settings
    )

    encrypted_assertions = REXML::XPath.match(
      response.document,
      "//a:EncryptedAssertion",
      { "a" => EncryptedAssertionHelper::ASSERTION }
    )
    plain_assertions = REXML::XPath.match(
      response.document,
      "//a:Assertion",
      { "a" => EncryptedAssertionHelper::ASSERTION }
    )

    assert_equal 1, encrypted_assertions.size
    assert_empty plain_assertions
    refute_includes response.document.to_s, 'alice@example.com'
    assert_includes response.decrypted_document.to_s, 'alice@example.com'
  end

  def test_exposes_signature_presence_without_treating_it_as_authentication
    response = response_for(assertion_xml, outer_signed: false, inner_signed: true)

    assert_equal({ :response => false, :assertion => true }, response.signature_presence)
    refute response.signature_coverage.values.any? { |verified| verified }

    response = response_for(assertion_xml, outer_signed: false, inner_signed: false)

    assert_equal({ :response => false, :assertion => false }, response.signature_presence)
    refute response.signature_coverage.values.any? { |verified| verified }
  end

  # --- tampered payloads -------------------------------------------------

  def test_rejects_plaintext_changes_that_invalidate_the_inner_signature
    signed = signed_assertion(assertion_xml)
    tampered = signed.sub('alice@example.com', 'attacker@example.com')
    response = response_for(tampered, outer_signed: true, inner_signed: false)

    refute response.is_valid?
    assert_includes response.errors, "Digest mismatch"
    assert_includes response.errors, "Invalid Signature on SAML Response"
    refute response.signature_coverage[:assertion]
    assert_nil response.nameid
    assert_empty response.attributes.all
  end

  def test_rejects_corrupted_inner_signature_with_valid_outer_signature
    signed = signed_assertion(assertion_xml)
    response = response_for(tamper_signature_value(signed), outer_signed: true, inner_signed: false)

    refute response.is_valid?
    assert_includes response.errors, "Invalid Signature on SAML Response"
    assert_nil response.nameid
  end

  def test_rejects_corrupted_outer_signature_with_valid_inner_signature
    signed = signed_assertion(assertion_xml)
    encrypted = encrypted_response(signed, response_signed: true)
    tampered = tamper_signature_value(Base64.decode64(encrypted))
    response = OneLogin::RubySaml::Response.new(Base64.encode64(tampered), :settings => settings)

    refute response.is_valid?
    assert_includes response.errors, "Invalid Signature on SAML Response"
    refute response.signature_coverage[:response]
    refute response.signature_coverage[:assertion]
    assert_nil response.nameid
  end

  # --- plaintext shape ---------------------------------------------------

  def test_rejects_extra_trailing_elements_after_the_assertion
    assertion = assertion_xml + '<evil xmlns="urn:evil">pwn</evil>'
    response = response_for(assertion, outer_signed: true, inner_signed: false)

    refute response.is_valid?
    assert(response.errors.any? { |error| error.include?("Invalid decrypted Assertion") })
    assert_nil response.nameid
  end

  def test_rejects_extra_trailing_elements_after_a_signed_assertion
    assertion = signed_assertion(assertion_xml) + '<evil xmlns="urn:evil">pwn</evil>'
    response = response_for(assertion, outer_signed: true, inner_signed: false)

    refute response.is_valid?
    assert(response.errors.any? { |error| error.include?("Invalid decrypted Assertion") })
  end

  def test_rejects_a_non_xml_tail
    response = response_for(assertion_xml + 'trailing-junk', outer_signed: true, inner_signed: false)

    refute response.is_valid?
    assert(response.errors.any? { |error| error.include?("Invalid decrypted Assertion") })
  end

  def test_rejects_a_wrong_plaintext_root_element
    assertion = "<Evil xmlns=\"urn:evil\">#{assertion_xml}</Evil>"
    response = response_for(assertion, outer_signed: true, inner_signed: false)

    refute response.is_valid?
    assert(response.errors.any? { |error| error.include?("Invalid decrypted Assertion") })
    assert_nil response.nameid
  end

  def test_rejects_an_assertion_root_in_the_wrong_namespace
    assertion = assertion_xml.sub(
      "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"",
      "xmlns:saml=\"urn:evil\""
    )
    response = response_for(assertion, outer_signed: true, inner_signed: false)

    refute response.is_valid?
    assert(response.errors.any? { |error| error.include?("Invalid decrypted Assertion") })
  end

  # --- cache hygiene on failure -----------------------------------------

  def test_does_not_keep_business_fields_after_a_rejected_decryption
    response = response_for(assertion_xml + '<evil/>', outer_signed: true, inner_signed: false)

    refute response.is_valid?
    assert_nil response.nameid
    assert_empty response.attributes.all
    assert_nil response.assertion_id
  end

  def test_clears_fields_cached_by_a_previous_success_when_validation_fails_later
    signed = signed_assertion(assertion_xml)
    response = OneLogin::RubySaml::Response.new(
      build_response(signed, outer_signed: true, inner_signed: false),
      :settings => settings
    )

    assert response.is_valid?
    assert_equal "alice@example.com", response.nameid

    response.settings = OneLogin::RubySaml::Settings.new
    response.settings.private_key = material[:private_key]
    response.settings.idp_cert = CertificateHelper.generate_pair_hash[:certificate]

    refute response.is_valid?
    assert_nil response.nameid
    assert_empty response.attributes.all
  end
end
