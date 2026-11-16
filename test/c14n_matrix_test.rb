require File.expand_path(File.join(File.dirname(__FILE__), "test_helper"))
require 'json'
require 'xml_security'

# Compatibility matrix for canonicalization. Every positive fixture is signed
# by an independent implementation (xmlsec1, or xmllint + openssl for the
# comment case). expected.json records the exact Reference and SignedInfo
# canonical bytes and digests that implementation produced, so the assertions
# below compare bytes, not just "validation returned true".
#
# See test/c14n_matrix/README.md for the matrix and the accept/reject policy.
class C14nMatrixTest < Minitest::Test
  MATRIX = File.expand_path(File.join(File.dirname(__FILE__), "c14n_matrix", "fixtures"))
  EXPECTED = JSON.parse(File.read(File.join(MATRIX, "expected.json")))
  CERT = OpenSSL::X509::Certificate.new(
    File.read(File.join(File.dirname(__FILE__), "certificates", "ruby-saml.crt")))
  FINGERPRINT = Digest::SHA1.hexdigest(CERT.to_der).scan(/../).join(":")

  def fixture(name)
    File.read(File.join(MATRIX, name))
  end

  def signed_document(name)
    XMLSecurity::SignedDocument.new(fixture(name))
  end

  def canonical_bytes(document)
    {
      :reference => document.referenced_xml.to_s,
      :signed_info => document.instance_variable_get(:@cached_signed_info).to_s
    }
  end

  def decoded(value)
    Base64.strict_decode64(value)
  end

  def expected_case(name)
    EXPECTED["cases"].fetch(name)
  end

  # Every positive fixture must validate and reproduce the signer's bytes.
  EXPECTED["cases"].each do |name, expected|
    define_method("test_positive_#{name}") do
      document = signed_document(expected["fixture"])
      assert document.validate_document_with_cert(CERT, true),
             "expected #{name} to validate, errors: #{document.errors.inspect}"

      bytes = canonical_bytes(document)
      assert_equal decoded(expected["reference_canonical_b64"]), bytes[:reference],
                   "Reference canonical bytes differ from the signer for #{name}"
      assert_equal decoded(expected["signed_info_canonical_b64"]), bytes[:signed_info],
                   "SignedInfo canonical bytes differ from the signer for #{name}"

      assert_equal decoded(expected["reference_digest_b64"]),
                   Digest::SHA256.digest(bytes[:reference])
      assert_equal decoded(expected["signed_info_sha256_b64"]),
                   Digest::SHA256.digest(bytes[:signed_info])

      assert_includes fixture(expected["fixture"]),
                      "<ds:DigestValue>#{expected["reference_digest_b64"]}</ds:DigestValue>"
    end
  end

  # One declared parameter changed; the original signature must not verify.
  EXPECTED["negative"].each do |name, expected|
    define_method("test_negative_#{name}") do
      document = signed_document(expected["fixture"])
      refute document.validate_document_with_cert(CERT, true),
             "expected #{name} to be rejected (#{expected["reason"]})"
      refute_empty document.errors
    end
  end

  def test_signed_info_prefix_list_is_not_a_reference_parameter
    signed = signed_document("signed_info_prefix_only.xml")
    plain = signed_document("exclusive_no_prefix_list.xml")
    assert signed.validate_document_with_cert(CERT, true)
    assert plain.validate_document_with_cert(CERT, true)

    # foo is declared on the assertion in both documents, but only the
    # SignedInfo case names it, so only SignedInfo bytes may differ.
    assert_equal plain.referenced_xml, signed.referenced_xml
    refute_equal canonical_bytes(plain)[:signed_info],
                 canonical_bytes(signed)[:signed_info]

    tampered = signed_document("tampered_signed_info_prefix_changed.xml")
    refute tampered.validate_document_with_cert(CERT, true)
    assert_includes tampered.errors, "Key validation error"
  end

  def test_reference_prefix_list_is_not_a_signed_info_parameter
    with_list = signed_document("reference_prefix_only.xml")
    without_list = signed_document("exclusive_no_prefix_list.xml")
    assert with_list.validate_document_with_cert(CERT, true)
    assert without_list.validate_document_with_cert(CERT, true)

    # The Reference element is itself covered by SignedInfo, so its bytes
    # differ. What must not happen is foo being rendered as a SignedInfo
    # namespace declaration because the Reference asked for it.
    refute_includes canonical_bytes(with_list)[:signed_info], "xmlns:foo"
    refute_includes canonical_bytes(without_list)[:signed_info], "xmlns:foo"
    assert_includes with_list.referenced_xml, "xmlns:foo"
    refute_includes without_list.referenced_xml, "xmlns:foo"
  end

  def test_each_layer_uses_only_its_own_inclusive_namespaces
    signed_info_only = signed_document("default_ns_signed_info_only.xml")
    assert signed_info_only.validate_document_with_cert(CERT, true)
    assert_nil signed_info_only.reference_canonicalization[:inclusive_namespaces]
    assert_equal ["#default"],
                 signed_info_only.signed_info_canonicalization[:inclusive_namespaces]

    reference_only = signed_document("default_ns_reference_included.xml")
    assert reference_only.validate_document_with_cert(CERT, true)
    assert_equal ["#default"],
                 reference_only.reference_canonicalization[:inclusive_namespaces]
    assert_nil reference_only.signed_info_canonicalization[:inclusive_namespaces]
  end

  def test_ancestor_prefix_is_pulled_in_only_where_named
    # foo is declared on the Assertion in both documents. SignedInfo names it
    # (and is a descendant), so exclusive c14n renders it there; the Reference
    # does not name it, so it is absent from Reference bytes.
    document = signed_document("signed_info_ancestor_prefix.xml")
    assert document.validate_document_with_cert(CERT, true)
    assert_includes canonical_bytes(document)[:signed_info], 'xmlns:foo="urn:foo"'
    refute_includes document.referenced_xml, "xmlns:foo"
  end

  def test_reference_without_transform_defaults_to_inclusive_c14n_1_0
    document = signed_document("reference_without_c14n_transform.xml")
    assert document.validate_document_with_cert(CERT, true)
    assert_equal Nokogiri::XML::XML_C14N_1_0,
                 document.reference_canonicalization[:mode]
    refute_equal Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0,
                 document.reference_canonicalization[:mode]
  end

  def test_inclusive_signed_info_does_not_change_exclusive_reference
    document = signed_document("signed_info_inclusive.xml")
    assert document.validate_document_with_cert(CERT, true)
    assert_equal Nokogiri::XML::XML_C14N_1_0,
                 document.signed_info_canonicalization[:mode]
    assert_equal Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0,
                 document.reference_canonicalization[:mode]
  end

  def test_comments_are_dropped_without_with_comments_algorithm
    document = signed_document("exclusive_comments_dropped.xml")
    assert document.validate_document_with_cert(CERT, true)
    refute_includes document.referenced_xml, "payload comment"
    refute_includes document.instance_variable_get(:@cached_signed_info),
                    "signed info comment"
  end

  def test_comments_are_kept_when_with_comments_is_declared
    document = signed_document("exclusive_with_comments.xml")
    assert document.validate_document_with_cert(CERT, true)
    assert_includes document.referenced_xml, "payload comment"
    assert_includes document.instance_variable_get(:@cached_signed_info),
                    "signed info comment"
    assert document.reference_canonicalization[:with_comments]
    assert document.signed_info_canonicalization[:with_comments]
  end

  def test_stripping_a_signed_comment_is_rejected
    stripped = fixture("exclusive_with_comments.xml").sub("<!-- payload comment -->", "")
    tampered = XMLSecurity::SignedDocument.new(stripped)
    refute tampered.validate_document_with_cert(CERT, true)
    assert_includes tampered.errors, "Digest mismatch"
  end

  def test_moving_signed_info_out_of_its_namespace_scope_is_rejected
    in_place = signed_document("signature_in_place.xml")
    moved = signed_document("signature_moved_out_of_scope.xml")

    assert in_place.validate_document_with_cert(CERT, true)
    refute moved.validate_document_with_cert(CERT, true)
    assert_includes moved.errors, "Key validation error"
    refute_equal canonical_bytes(in_place)[:signed_info],
                 canonical_bytes(moved)[:signed_info]
  end

  def test_two_signature_layers_resolve_independently
    document = signed_document("two_signature_layers.xml")
    assert document.validate_document_with_cert(CERT, true)

    expected = expected_case("two_signature_layers")
    assert_equal decoded(expected["reference_canonical_b64"]),
                 document.referenced_xml
    assert_equal Nokogiri::XML::XML_C14N_1_0,
                 document.reference_canonicalization[:mode]

    # Validate the Assertion layer too. Remove the Response signature textually
    # so the remaining bytes are unchanged, then check that layer against its
    # own algorithm (exclusive c14n with xs and foo) and golden bytes.
    assertion_only = fixture("two_signature_layers.xml").sub(
      /<ds:Signature xmlns:ds="http:\/\/www\.w3\.org\/2000\/09\/xmldsig#">.*?<\/ds:Signature>/m, "")
    second = XMLSecurity::SignedDocument.new(assertion_only)
    assert second.validate_document_with_cert(CERT, true)

    secondary = expected["secondary_layer"]
    assert_equal decoded(secondary["reference_canonical_b64"]),
                 second.referenced_xml
    assert_equal decoded(secondary["signed_info_canonical_b64"]),
                 second.instance_variable_get(:@cached_signed_info)
    assert_equal Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0,
                 second.reference_canonicalization[:mode]
    assert_equal %w[xs foo],
                 second.reference_canonicalization[:inclusive_namespaces]
  end

  def test_signed_metadata_uses_documented_verification_entry_point
    document = XMLSecurity::SignedDocument.new(fixture("signed_metadata.xml"))
    assert document.validate_document_with_cert(CERT, false)
    assert_equal decoded(expected_case("signed_metadata")["reference_canonical_b64"]),
                 document.referenced_xml
  end

  def test_pretty_printing_signed_metadata_is_rejected
    formatted = String.new
    REXML::Document.new(fixture("signed_metadata.xml")).write(formatted, 2)
    refute_equal fixture("signed_metadata.xml"), formatted

    document = XMLSecurity::SignedDocument.new(formatted)
    refute document.validate_document_with_cert(CERT, true),
           "pretty-printing after signing must invalidate the signature"
    refute_empty document.errors
  end

  def test_checked_in_adfs_fixture_still_validates
    document = XMLSecurity::SignedDocument.new(
      File.read(File.join(File.dirname(__FILE__), "responses", "adfs_response_sha256.xml")))
    assert document.validate_document(
      "28:74:9B:E8:1F:E8:10:9C:A8:7C:A9:C3:E3:C5:01:6C:92:1C:B4:BA")
  end
end
