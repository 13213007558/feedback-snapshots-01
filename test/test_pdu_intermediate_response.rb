# -*- ruby encoding: utf-8 -*-
require_relative "test_helper"
require_relative "sync_protocol_helper"

class TestPDUIntermediateResponse < Test::Unit::TestCase
  include SyncProtocolHelper

  def test_parses_intermediate_response_application_tag_25
    bytes = info_pdu(7, sync_info_newcookie("ck-x"))
    pdu = parse_pdu(bytes)

    assert_equal Net::LDAP::PDU::IntermediateResponse, pdu.app_tag
    assert_equal 7, pdu.message_id
    assert_equal SyncProtocolHelper::OID::INFO, pdu.intermediate_response[:name]
  end

  def test_intermediate_response_carries_sync_info_payload
    bytes = info_pdu(3, sync_info_id_set(refresh_deletes: true, uuids: [uuid(9)]))
    pdu = parse_pdu(bytes)

    info = Net::LDAP::Sync::Codec.info_message(pdu)
    assert_equal :sync_id_set, info[:type]
    assert_equal true, info[:refresh_deletes]
    assert_equal [uuid(9)], info[:uuids]
  end

  def test_search_result_done_exposes_sync_done_control
    bytes = done_pdu(2, cookie: "ck", refresh_deletes: true)
    pdu = parse_pdu(bytes)

    assert_equal Net::LDAP::PDU::SearchResult, pdu.app_tag
    done = Net::LDAP::Sync::Codec.done_control(pdu)
    assert_equal true, done[:refresh_deletes]
    assert_equal "ck", done[:cookie]
  end
end
