# -*- ruby encoding: utf-8 -*-
require_relative 'test_helper'

# Structural mutation tests for the LDAP PDU dispatcher.
#
# These tests exist because a security gateway must not treat "the bytes can
# be decoded by the BER parser" as "this is a trustworthy LDAP success
# response". A BER decode succeeding only proves the wire bytes are
# well-formed TLV octets. It does not prove that:
#
#   * the protocolOp carries the APPLICATION class and the constructed bit
#     required by RFC 4511 (section 4.1.1);
#   * the messageID element is actually an INTEGER (RFC 4511 MessageID);
#   * the resultCode of an LDAPResult is an ENUMERATED (RFC 4511 section
#     4.1.9), so a numerically equal value of the wrong ASN.1 type cannot be
#     read as "success".
#
# Every negative case below is derived from a known-good BindResponse,
# SearchResultDone or ModifyResponse and is exercised through the real
# socket read path (Net::BER::BERParser#read_ber followed by
# Net::LDAP::PDU dispatch), not by constructing PDU objects directly. That
# keeps the tests honest about what an attacker on the wire can actually
# achieve. A small number of legal, non-canonical encodings are kept as
# compatibility controls so that "every odd packet is rejected" is never
# mistaken for correct behaviour.
#
# Rejection rationale key:
#   :ber_layer      - Net::BER rejects the tag because no object type is
#                     compiled for that class/encoding in AsnSyntax.
#   :pdu_dispatch   - Net::LDAP::PDU rejects a tag whose low five bits do
#                     not name a known protocolOp ("unknown pdu-type").
#   :pdu_structure  - Net::LDAP::PDU rejects a structurally invalid PDU:
#                     wrong tag class, primitive protocolOp, non-INTEGER
#                     messageID, or malformed LDAPResult fields.
#   :no_false_success - the packet decodes but MUST NOT report success or a
#                     spoofed operation result.
class TestPDUStructuralMutation < Test::Unit::TestCase
  # A socket-like transport. It includes the real BER parser so responses go
  # through exactly the same read_ber -> PDU path used with a TCP socket.
  class BERTransport
    include Net::BER::BERParser

    def initialize(bytes)
      @io = StringIO.new(bytes)
    end

    def getbyte
      @io.getbyte
    end

    def read(length)
      @io.read(length)
    end

    def write(_data)
    end

    def close
    end
  end

  APPLICATION      = Net::BER::TAG_CLASS[:application]
  CONTEXT          = Net::BER::TAG_CLASS[:context_specific]
  PRIVATE          = Net::BER::TAG_CLASS[:private]
  UNIVERSAL        = Net::BER::TAG_CLASS[:universal]
  CONSTRUCTED      = Net::BER::ENCODING_TYPE[:constructed]
  PRIMITIVE        = Net::BER::ENCODING_TYPE[:primitive]

  BIND_TAG         = Net::LDAP::PDU::BindResult          # APPLICATION 1
  SEARCH_DONE_TAG  = Net::LDAP::PDU::SearchResult        # APPLICATION 5
  MODIFY_TAG       = Net::LDAP::PDU::ModifyResponse      # APPLICATION 7

  # --- low level BER builders -------------------------------------------

  def tlv(tag, content)
    [tag].pack('C') + content.length.to_ber_length_encoding + content
  end

  def integer(value)
    value.to_ber
  end

  def enumerated(value)
    value.to_ber_enumerated
  end

  def octet_string(value = '')
    value.to_ber
  end

  # An LDAPResult body (resultCode ENUMERATED, matchedDN, errorMessage)
  # wrapped in a chosen protocolOp tag.
  def ldap_result_tag(tag, result_code = Net::LDAP::ResultCodeSuccess)
    tlv(tag, enumerated(result_code) + octet_string('') + octet_string(''))
  end

  # A complete LDAPMessage envelope. message_id_bytes lets callers supply a
  # mutated messageID encoding rather than a plain INTEGER.
  def message(message_id_bytes, protocol_op)
    tlv(0x30, message_id_bytes + protocol_op)
  end

  def bind_response(tag = APPLICATION + CONSTRUCTED + BIND_TAG,
                    result_code = Net::LDAP::ResultCodeSuccess)
    ldap_result_tag(tag, result_code)
  end

  def search_done_response(tag = APPLICATION + CONSTRUCTED + SEARCH_DONE_TAG,
                           result_code = Net::LDAP::ResultCodeSuccess)
    ldap_result_tag(tag, result_code)
  end

  def modify_response(tag = APPLICATION + CONSTRUCTED + MODIFY_TAG,
                      result_code = Net::LDAP::ResultCodeSuccess)
    ldap_result_tag(tag, result_code)
  end

  # Build a well-formed envelope and then overwrite exactly the protocolOp
  # tag octet (the byte immediately following the messageID TLV) so that only
  # the tag class / constructed bit changes.
  def mutate_protocol_op_tag(packet, new_tag)
    mutated = packet.dup
    # Envelope layout: [0x30][length][INTEGER TLV ...][protocolOp tag].
    tag_index = 2 + integer(1).length
    original = mutated.getbyte(tag_index)
    assert_equal APPLICATION + CONSTRUCTED, original & 0xE0,
                 'precondition: mutation targets an APPLICATION constructed protocolOp'
    mutated.setbyte(tag_index, new_tag)
    mutated
  end

  def read_pdu(packet)
    connection = Net::LDAP::Connection.new(:socket => BERTransport.new(packet))
    connection.send(:read)
  end

  # A structurally invalid protocolOp must be refused. Depending on the tag,
  # the BER syntax table rejects it first (Net::BER::BerError) or it reaches
  # the PDU dispatcher which enforces the APPLICATION-constructed contract
  # (Net::LDAP::PDU::Error). The two are independent RuntimeError hierarchies,
  # so both are accepted; the security requirement is that the packet never
  # becomes a successful operation result.
  def assert_structurally_rejected
    yield
    flunk 'expected a Net::BER::BerError or Net::LDAP::PDU::Error rejection'
  rescue Net::BER::BerError, Net::LDAP::PDU::Error => e
    e
  end

  def bind_with(packet)
    connection = Net::LDAP::Connection.new(:socket => BERTransport.new(packet))
    connection.bind(:method => :simple, :username => 'cn=u', :password => 'p')
  end

  def modify_with(packet)
    connection = Net::LDAP::Connection.new(:socket => BERTransport.new(packet))
    connection.modify(:dn => 'cn=u',
                      :operations => [[:replace, 'mail', 'a@example.com']])
  end

  def search_with(packet)
    connection = Net::LDAP::Connection.new(:socket => BERTransport.new(packet))
    connection.search(:base => 'dc=example,dc=org')
  end

  # --- canonical baseline: a genuine success response is accepted --------

  def test_canonical_bind_response_is_trusted
    packet = message(integer(1), bind_response)
    pdu = read_pdu(packet)

    assert_equal BIND_TAG, pdu.app_tag
    assert_equal 1, pdu.message_id
    assert pdu.success?
    assert_equal Net::LDAP::ResultCodeSuccess, pdu.result_code
  end

  def test_canonical_modify_response_reports_success
    pdu = modify_with(message(integer(1), modify_response))

    assert_equal MODIFY_TAG, pdu.app_tag
    assert pdu.success?
  end

  def test_canonical_search_done_reports_success
    pdu = search_with(message(integer(1), search_done_response))

    assert_equal SEARCH_DONE_TAG, pdu.app_tag
    assert pdu.success?
  end

  # --- 1. tag class mutation ---------------------------------------------
  # RFC 4511 defines every protocolOp as [APPLICATION n] SEQUENCE. A value
  # whose tag merely shares the low five bits but lives in another class is a
  # different ASN.1 type and must never be dispatched as that protocolOp.

  def test_context_class_bind_tag_is_not_a_bind_result
    # [CONTEXT 1] constructed (0xA1) shares low bits with [APPLICATION 1].
    packet = mutate_protocol_op_tag(
      message(integer(1), bind_response),
      CONTEXT + CONSTRUCTED + BIND_TAG
    )

    error = assert_structurally_rejected { read_pdu(packet) }
    assert_match(/application/i, error.message)
    assert_no_successful_bind(packet)
  end

  def test_context_class_modify_tag_is_not_a_modify_response
    packet = mutate_protocol_op_tag(
      message(integer(1), modify_response),
      CONTEXT + CONSTRUCTED + MODIFY_TAG
    )

    assert_structurally_rejected { modify_with(packet) }
  end

  def test_context_class_search_done_tag_is_not_a_search_result
    packet = mutate_protocol_op_tag(
      message(integer(1), search_done_response),
      CONTEXT + CONSTRUCTED + SEARCH_DONE_TAG
    )

    assert_structurally_rejected { search_with(packet) }
  end

  def test_context_class_search_entry_tag_is_not_an_entry
    # SearchResultEntry is [APPLICATION 4]; a context-specific [4] (0xA4)
    # must not be dispatched as a returned entry.
    attribute = [octet_string('uid'), [octet_string('user1')].to_ber_set].to_ber_sequence
    entry_body = octet_string('uid=u,dc=x') + [attribute].to_ber_sequence
    spoofed_entry = tlv(CONTEXT + CONSTRUCTED + Net::LDAP::PDU::SearchReturnedData,
                        entry_body)
    packet = message(integer(1), spoofed_entry)

    assert_structurally_rejected { read_pdu(packet) }
  end

  def test_canonical_search_entry_is_dispatched
    attribute = [octet_string('uid'), [octet_string('user1')].to_ber_set].to_ber_sequence
    entry_body = octet_string('uid=u,dc=x') + [attribute].to_ber_sequence
    entry = tlv(APPLICATION + CONSTRUCTED + Net::LDAP::PDU::SearchReturnedData,
                entry_body)
    done = search_done_response
    # Two envelopes: one entry, then the SearchResultDone.
    packets = message(integer(1), entry) + message(integer(1), done)

    connection = Net::LDAP::Connection.new(:socket => BERTransport.new(packets))
    entries = []
    result = connection.search(:base => 'dc=example,dc=org') { |e| entries << e }

    assert_equal 1, entries.length
    assert_equal ['user1'], entries.first[:uid]
    assert result.success?
  end

  def test_private_class_bind_tag_is_rejected
    packet = mutate_protocol_op_tag(
      message(integer(1), bind_response),
      PRIVATE + CONSTRUCTED + BIND_TAG
    )

    # Rejected either by the BER syntax or by strict PDU validation, but in
    # no case interpreted as a successful BindResponse.
    assert_structurally_rejected { read_pdu(packet) }
  end

  def test_universal_class_bind_tag_is_rejected
    packet = mutate_protocol_op_tag(
      message(integer(1), bind_response),
      UNIVERSAL + CONSTRUCTED + BIND_TAG
    )

    assert_structurally_rejected { read_pdu(packet) }
  end

  # --- 2. constructed-bit mutation ---------------------------------------
  # A protocolOp is a constructed SEQUENCE. Clearing the constructed bit
  # turns it into a primitive value, which cannot hold the LDAPResult fields
  # and must be refused rather than parsed as a response.

  def test_primitive_application_bind_tag_is_rejected
    packet = mutate_protocol_op_tag(
      message(integer(1), bind_response),
      APPLICATION + PRIMITIVE + BIND_TAG
    )

    assert_structurally_rejected { read_pdu(packet) }
  end

  def test_primitive_application_modify_tag_is_rejected
    packet = mutate_protocol_op_tag(
      message(integer(1), modify_response),
      APPLICATION + PRIMITIVE + MODIFY_TAG
    )

    assert_structurally_rejected { modify_with(packet) }
  end

  def test_primitive_context_bind_tag_is_rejected
    packet = mutate_protocol_op_tag(
      message(integer(1), bind_response),
      CONTEXT + PRIMITIVE + BIND_TAG
    )

    assert_structurally_rejected { read_pdu(packet) }
  end

  # --- 3. message ID type mutation ---------------------------------------
  # MessageID ::= INTEGER (0..maxInt). A non-INTEGER messageID must not be
  # coerced via #to_i into a plausible ID, because that lets an attacker align
  # a spoofed answer with an outstanding request.

  def test_enumerated_message_id_is_rejected
    packet = message(enumerated(1), bind_response)

    assert_raise(Net::LDAP::PDU::Error) { read_pdu(packet) }
  end

  def test_context_primitive_message_id_is_rejected
    packet = message(tlv(0x80, integer(1)[2..-1]), bind_response)

    assert_raise(Net::LDAP::PDU::Error) { read_pdu(packet) }
  end

  def test_octet_string_message_id_is_rejected
    packet = message(octet_string([1].pack('C')), bind_response)

    assert_raise(Net::LDAP::PDU::Error) { read_pdu(packet) }
  end

  # --- 4. result field inconsistency -------------------------------------
  # resultCode is ENUMERATED. A numerically equal INTEGER must not be read as
  # success; structurally wrong result fields must not yield a usable result.

  def test_integer_result_code_is_not_treated_as_success
    # Same numeric value (0) as success, but encoded as INTEGER (0x02) rather
    # than ENUMERATED (0x0A). The values happen to compare equal numerically,
    # but the wrong ASN.1 type must be refused rather than read as success.
    body = tlv(APPLICATION + CONSTRUCTED + BIND_TAG,
               integer(0) + octet_string('') + octet_string(''))
    packet = message(integer(1), body)

    error = assert_raise(Net::LDAP::PDU::Error) { read_pdu(packet) }
    assert_match(/ENUMERATED/i, error.message)
  end

  def test_octet_string_result_code_is_not_success
    body = tlv(APPLICATION + CONSTRUCTED + BIND_TAG,
               octet_string([0].pack('C')) + octet_string('') + octet_string(''))
    packet = message(integer(1), body)

    # A non-integer resultCode cannot name success: it is either rejected as a
    # malformed LDAPResult or, if it parses, reports a non-success status.
    begin
      pdu = read_pdu(packet)
    rescue Net::LDAP::PDU::Error
      return
    end
    refute pdu.success?
    assert_not_equal Net::LDAP::ResultCodeSuccess, pdu.result_code
  end

  def test_short_bind_result_is_rejected
    # Only two of the three required LDAPResult fields.
    body = tlv(APPLICATION + CONSTRUCTED + BIND_TAG,
               enumerated(0) + octet_string(''))
    packet = message(integer(1), body)

    assert_raise(Net::LDAP::PDU::Error) { read_pdu(packet) }
  end

  def test_non_success_enumerated_code_is_failure
    packet = message(
      integer(1),
      bind_response(APPLICATION + CONSTRUCTED + BIND_TAG,
                    Net::LDAP::ResultCodeInvalidCredentials)
    )

    pdu = read_pdu(packet)
    refute pdu.success?
    assert pdu.failure?
    assert_equal Net::LDAP::ResultCodeInvalidCredentials, pdu.result_code
  end

  # --- legal non-canonical compatibility controls ------------------------
  # BER (unlike DER) permits non-minimal INTEGER content octets. Such a packet
  # is still a valid APPLICATION constructed response with an INTEGER
  # messageID and an ENUMERATED resultCode, so it must continue to be
  # accepted. These guards prove the strict checks target type/tag identity
  # rather than rejecting every unusual encoding.

  def test_non_minimal_message_id_integer_is_accepted
    non_minimal_id = tlv(0x02, [0x00, 0x01].pack('C*'))
    packet = message(non_minimal_id, bind_response)

    pdu = read_pdu(packet)
    assert_equal 1, pdu.message_id
    assert pdu.success?
  end

  def test_non_minimal_enumerated_result_code_is_accepted
    non_minimal_code = tlv(0x0A, [0x00, 0x00].pack('C*'))
    body = tlv(APPLICATION + CONSTRUCTED + BIND_TAG,
               non_minimal_code + octet_string('') + octet_string(''))
    packet = message(integer(1), body)

    pdu = read_pdu(packet)
    assert pdu.success?
    assert_equal Net::LDAP::ResultCodeSuccess, pdu.result_code
  end

  private

  def assert_no_successful_bind(packet)
    result = begin
      bind_with(packet)
    rescue Net::BER::BerError, Net::LDAP::PDU::Error
      nil
    end

    if result
      refute result.success?, 'spoofed tag must not produce a successful bind'
    end
  end
end
