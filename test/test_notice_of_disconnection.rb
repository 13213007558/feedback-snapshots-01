# -*- ruby encoding: utf-8 -*-
require_relative 'test_helper'

# RFC 4511 section 4.4.1: a server may send an unsolicited Notice of
# Disconnection as an ExtendedResponse with message ID 0 and the
# 1.3.6.1.4.1.1466.20036 responseName OID, then close the connection.
class TestNoticeOfDisconnection < Test::Unit::TestCase
  # In-memory socket. Server bytes are pushed onto a StringIO; every
  # outgoing request is recorded so tests can prove that no further
  # security-sensitive request is written after disconnection.
  class FakeSocket
    attr_reader :written

    def initialize
      @read_io = StringIO.new
      @written = []
      @closed = false
    end

    def read_ber(syntax = nil, &block)
      return nil if @read_io.eof?
      @read_io.read_ber(syntax, &block)
    end

    def write(data)
      raise IOError, "closed stream" if @closed
      @written << data
      data.bytesize
    end

    def close
      @closed = true
    end

    def closed?
      @closed
    end
  end

  def setup
    @socket = FakeSocket.new
    @connection = Net::LDAP::Connection.new(:socket => @socket)
  end

  # Build a real BER-encoded Notice of Disconnection packet so the full
  # parser (including the responseName [10] OID syntax) is exercised.
  def disconnect_notice(code: Net::LDAP::ResultCodeUnavailable,
                        message: "server is shutting down",
                        oid: Net::LDAP::NoticeOfDisconnectOid)
    ext = [
      code.to_ber,
      "".to_ber,
      message.to_ber,
      oid.to_ber_contextspecific(10),
    ].to_ber_appsequence(Net::LDAP::PDU::ExtendedResponse)

    [0.to_ber, ext].to_ber_sequence
  end

  def modify_response(message_id, code: Net::LDAP::ResultCodeSuccess)
    result = [code.to_ber, "".to_ber, "".to_ber]
             .to_ber_appsequence(Net::LDAP::PDU::ModifyResponse)
    [message_id.to_ber, result].to_ber_sequence
  end

  def bind_response(message_id, code: Net::LDAP::ResultCodeSuccess)
    result = [code.to_ber, "".to_ber, "".to_ber]
             .to_ber_appsequence(Net::LDAP::PDU::BindResult)
    [message_id.to_ber, result].to_ber_sequence
  end

  def modify_args
    {
      :dn => "uid=user1,ou=People,dc=example,dc=org",
      :operations => [[:replace, "mail", "user1@example.com"]],
    }
  end

  def test_parses_response_name_oid_as_string
    @socket.instance_variable_set(:@read_io, StringIO.new(disconnect_notice.b))

    pdu = @connection.send(:read)

    assert_equal 0, pdu.message_id
    assert_equal Net::LDAP::PDU::ExtendedResponse, pdu.app_tag
    assert_equal Net::LDAP::NoticeOfDisconnectOid, pdu.extended_response
    assert pdu.notice_of_disconnection?
  end

  def test_notice_injected_before_query_terminates_without_fabricated_success
    @socket.instance_variable_set(:@read_io, StringIO.new(disconnect_notice.b))

    error = assert_raise(Net::LDAP::NoticeOfDisconnectionError) do
      @connection.modify(modify_args)
    end

    assert_equal Net::LDAP::ResultCodeUnavailable, error.result_code
    assert_equal "server is shutting down", error.error_message
    # No successful result PDU can be fabricated from the notice.
    assert_empty @connection.message_queue
    assert @socket.closed?

    # A follow-up security-sensitive operation must not reach the socket.
    assert_raise(Net::LDAP::NoticeOfDisconnectionError) do
      @connection.password_modify(
        :dn => "cn=admin,dc=example,dc=org",
        :old_password => "secret",
        :new_password => "rotated",
      )
    end
    assert_equal 1, @socket.written.size
  end

  def test_notice_injected_during_query_unblocks_waiting_caller
    @socket.instance_variable_set(
      :@read_io,
      StringIO.new(disconnect_notice(message: "administrative reset").b)
    )

    error = assert_raise(Net::LDAP::NoticeOfDisconnectionError) do
      @connection.modify(modify_args)
    end

    assert_equal "administrative reset", error.error_message
    # Only the in-flight modify request was written.
    assert_equal 1, @socket.written.size
    assert @socket.closed?
  end

  def test_notice_injected_after_cached_response_uses_same_reason
    @connection.next_msgid # reserve message ID 1 for an earlier operation
    packets = [
      modify_response(1), # cached for the earlier operation
      disconnect_notice,  # read while waiting for ID 2
    ].map(&:b).join
    @socket.instance_variable_set(:@read_io, StringIO.new(packets))

    error = assert_raise(Net::LDAP::NoticeOfDisconnectionError) do
      @connection.modify(modify_args)
    end

    assert_equal Net::LDAP::ResultCodeUnavailable, error.result_code
    assert @socket.closed?
    # The cached normal response must have been discarded with the queue
    # rather than surfaced as a successful result.
    assert_empty @connection.message_queue
  end

  def test_waiting_and_later_operations_get_identical_termination_reason
    @socket.instance_variable_set(:@read_io, StringIO.new(disconnect_notice.b))

    first_error = assert_raise(Net::LDAP::NoticeOfDisconnectionError) do
      @connection.modify(modify_args)
    end

    second_error = assert_raise(Net::LDAP::NoticeOfDisconnectionError) do
      @connection.modify(modify_args)
    end

    assert_equal first_error.message, second_error.message
    assert_equal first_error.result_code, second_error.result_code
    # The second operation must never have reached the closed socket.
    assert_equal 1, @socket.written.size
  end

  def test_no_security_sensitive_request_is_sent_after_disconnection
    # Only the bind response is available initially. The notice arrives
    # while the password-modify operation is waiting for its result.
    packets = bind_response(1) + disconnect_notice
    @socket.instance_variable_set(:@read_io, StringIO.new(packets.b))

    assert @connection.bind(method: :simple,
                            username: "cn=admin,dc=example,dc=org",
                            password: "secret")
    assert_equal 1, @socket.written.size

    assert_raise(Net::LDAP::NoticeOfDisconnectionError) do
      @connection.password_modify(
        :dn => "cn=admin,dc=example,dc=org",
        :old_password => "secret",
        :new_password => "rotated",
      )
    end

    # The password modify request was written before the notice was read,
    # but every subsequent request must be refused locally without touching
    # the dead connection.
    assert_equal 2, @socket.written.size
    assert_raise(Net::LDAP::NoticeOfDisconnectionError) do
      @connection.modify(modify_args)
    end
    assert_equal 2, @socket.written.size
  end

  def test_message_id_zero_with_wrong_oid_is_not_a_disconnection
    ext = [
      Net::LDAP::ResultCodeSuccess.to_ber,
      "".to_ber,
      "".to_ber,
      "1.3.6.1.4.1.4203.1.11.3".to_ber_contextspecific(10), # whoami OID
    ].to_ber_appsequence(Net::LDAP::PDU::ExtendedResponse)
    packets = [
      [0.to_ber, ext].to_ber_sequence,
      bind_response(1),
    ].map(&:b).join
    @socket.instance_variable_set(:@read_io, StringIO.new(packets))

    result = @connection.bind(method: :anon)

    assert result.success?
    refute @socket.closed?
  end

  def test_non_zero_message_id_extended_response_is_not_a_disconnection
    ext = [
      Net::LDAP::ResultCodeUnavailable.to_ber,
      "".to_ber,
      "not a disconnect".to_ber,
      Net::LDAP::NoticeOfDisconnectOid.to_ber_contextspecific(10),
    ].to_ber_appsequence(Net::LDAP::PDU::ExtendedResponse)
    packets = [
      [3.to_ber, ext].to_ber_sequence,
      bind_response(1),
    ].map(&:b).join
    @socket.instance_variable_set(:@read_io, StringIO.new(packets))

    result = @connection.bind(method: :anon)

    assert result.success?
    refute @socket.closed?
  end

  def test_notice_is_not_left_in_message_queue
    @socket.instance_variable_set(:@read_io, StringIO.new(disconnect_notice.b))

    assert_raise(Net::LDAP::NoticeOfDisconnectionError) do
      @connection.modify(modify_args)
    end

    assert_empty @connection.message_queue
  end

  def test_search_during_notice_raises_without_fabricated_result_set
    attribute = [
      "uid".to_ber,
      ["user1".to_ber].to_ber_set,
    ].to_ber_sequence
    search_data = [
      "uid=user1,ou=People,dc=example,dc=org".to_ber,
      [attribute].to_ber_sequence,
    ].to_ber_appsequence(Net::LDAP::PDU::SearchReturnedData)
    packets = [
      [2.to_ber, search_data].to_ber_sequence,
      disconnect_notice,
    ].map(&:b).join
    @socket.instance_variable_set(:@read_io, StringIO.new(packets))
    @connection.next_msgid # the search runs on message ID 2

    entries = []
    assert_raise(Net::LDAP::NoticeOfDisconnectionError) do
      @connection.search(
        :base => "ou=People,dc=example,dc=org",
        :ignore_server_caps => true,
      ) { |entry| entries << entry }
    end

    # The entry received before the notice must not be misrepresented as a
    # successful, complete search, and nothing remains queued.
    assert_equal 1, entries.size
    assert_empty @connection.message_queue
    assert @socket.closed?
  end
end
