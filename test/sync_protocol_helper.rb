# -*- ruby encoding: utf-8 -*-
# In-memory RFC 4533 protocol sequences for the Content Synchronization
# tests. Every helper emits real BER bytes that travel through
# Net::LDAP::PDU and the BER parser, so the tests exercise the same decode
# path as a live socket without needing a directory server.
module SyncProtocolHelper
  module OID
    REQUEST = "1.3.6.1.4.1.4203.1.9.1.1"
    STATE = "1.3.6.1.4.1.4203.1.9.1.2"
    DONE = "1.3.6.1.4.1.4203.1.9.1.3"
    INFO = "1.3.6.1.4.1.4203.1.9.1.4"
  end

  # Deterministic 16-byte UUIDs keyed by a single byte for readable tests.
  def uuid(byte)
    ([byte] + [0] * 15).pack("C*")
  end

  def entry(dn, attributes = {})
    entry = Net::LDAP::Entry.new(dn)
    attributes.each { |name, values| entry[name] = values }
    entry
  end

  # ---- Control value encoders (the inner OCTET STRING content) ----

  def sync_state_value(state, entry_uuid, cookie = nil)
    content = [state.to_ber_enumerated, entry_uuid.to_ber_bin]
    content << cookie.to_ber_bin if cookie
    content.to_ber_sequence
  end

  def sync_done_value(cookie: nil, refresh_deletes: false)
    content = []
    content << cookie.to_ber_bin if cookie
    content << refresh_deletes.to_ber if refresh_deletes
    content.to_ber_sequence
  end

  def sync_info_newcookie(cookie)
    cookie.to_ber_bin(0x80)
  end

  def sync_info_refresh_present(cookie: nil, refresh_done: false)
    content = []
    content << cookie.to_ber_bin if cookie
    content << refresh_done.to_ber if refresh_done
    content.to_ber_sequence.to_ber(0xA2)
  end

  def sync_info_refresh_delete(cookie: nil, refresh_done: true)
    content = []
    content << cookie.to_ber_bin if cookie
    content << refresh_done.to_ber unless refresh_done
    content.to_ber_sequence.to_ber(0xA1)
  end

  def sync_info_id_set(cookie: nil, refresh_deletes: false, uuids: [])
    content = []
    content << cookie.to_ber_bin if cookie
    content << refresh_deletes.to_ber if refresh_deletes
    content << uuids.map { |u| u.to_ber_bin }.to_ber_set
    content.to_ber_sequence.to_ber(0xA3)
  end

  # ---- Full PDU encoders ----

  def control(oid, value, criticality = false)
    [oid.to_ber, criticality.to_ber, value.to_ber].to_ber_sequence
  end

  def entry_pdu(message_id, dn, state, entry_uuid, attributes = {}, cookie = nil)
    attrs = attributes.map do |name, values|
      [name.to_s.to_ber, Array(values).map(&:to_ber).to_ber_set].to_ber_sequence
    end
    search_entry = [dn.to_ber, attrs.to_ber_sequence].to_ber_appsequence(Net::LDAP::PDU::SearchReturnedData)
    controls = [control(OID::STATE, sync_state_value(state, entry_uuid, cookie))]
    [message_id.to_ber, search_entry, controls.to_ber_contextspecific(0)].to_ber_sequence
  end

  def info_pdu(message_id, info_value)
    body = [
      OID::INFO.to_ber_contextspecific(0),
      info_value.to_ber_contextspecific(1),
    ].to_ber_appsequence(Net::LDAP::PDU::IntermediateResponse)
    [message_id.to_ber, body].to_ber_sequence
  end

  def done_pdu(message_id, result_code: Net::LDAP::ResultCodeSuccess,
               cookie: nil, refresh_deletes: false, error_message: "")
    body = [
      result_code.to_ber_enumerated,
      "".to_ber,
      error_message.to_ber,
    ].to_ber_appsequence(Net::LDAP::PDU::SearchResult)
    controls = [control(OID::DONE, sync_done_value(cookie: cookie,
                                                    refresh_deletes: refresh_deletes))]
    [message_id.to_ber, body, controls.to_ber_contextspecific(0)].to_ber_sequence
  end

  def result_pdu(message_id, result_code, error_message = "")
    body = [
      result_code.to_ber_enumerated,
      "".to_ber,
      error_message.to_ber,
    ].to_ber_appsequence(Net::LDAP::PDU::SearchResult)
    [message_id.to_ber, body].to_ber_sequence
  end

  # Parse a complete BER PDU exactly as Connection#read would.
  def parse_pdu(bytes)
    Net::LDAP::PDU.new(bytes.read_ber(Net::LDAP::AsnSyntax))
  end
end
