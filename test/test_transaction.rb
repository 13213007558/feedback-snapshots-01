require_relative 'test_helper'

# Offline verification of RFC 5805 LDAP transaction support. No network is
# used: a fake socket records the BER bytes written and serves scripted
# responses.
class TestLDAPTransactions < Test::Unit::TestCase
  TXN_OID = Net::LDAP::TransactionSpecificationOid
  START_OID = Net::LDAP::StartTransactionOid
  END_OID = Net::LDAP::EndTransactionOid

  module BerWalk
    module_function

    def read_length(io)
      first = io.readbyte
      return first if first < 0x80

      io.read(first & 0x7f).bytes.reduce(0) { |acc, byte| (acc << 8) | byte }
    end

    # Reads one complete TLV and returns [tag, value_bytes].
    def read_tlv(io)
      tag = io.readbyte
      length = read_length(io)
      [tag, io.read(length)]
    end

    # The leading INTEGER of a BER SEQUENCE (the LDAP message id).
    def message_id_of(bytes)
      _seq_tag, seq_value = read_tlv(StringIO.new(bytes))
      _int_tag, value = read_tlv(StringIO.new(seq_value))
      value.bytes.reduce(0) { |acc, byte| (acc << 8) | byte }
    end

    # The application tag of the request element (second element of the
    # outer message SEQUENCE).
    def app_tag_of(bytes)
      _seq_tag, seq_value = read_tlv(StringIO.new(bytes))
      inner = StringIO.new(seq_value)
      read_tlv(inner) # message id
      tag, _value = read_tlv(inner)
      tag & 0x1f
    end

    # Returns the raw controls field bytes (context [0]) of a message, or
    # nil when the message carries no controls.
    def controls_field_of(bytes)
      _seq_tag, seq_value = read_tlv(StringIO.new(bytes))
      inner = StringIO.new(seq_value)
      read_tlv(inner) # message id
      read_tlv(inner) # request body
      return nil if inner.eof?

      _tag, value = read_tlv(inner)
      value
    end

    # Parses a controls field (the context [0] OCTET STRING whose content is
    # a BER SEQUENCE OF Control) into an array of
    # [oid, criticality, control_value] triples.
    def parse_controls(field_bytes)
      io = StringIO.new(field_bytes)
      controls = []
      until io.eof?
        _control_tag, control_value = read_tlv(io)
        cio = StringIO.new(control_value)
        oid = read_tlv(cio)[1]
        crit_value = read_tlv(cio)[1]
        # The remaining element (if any) is the control OCTET STRING value.
        value_tlv = cio.eof? ? nil : read_tlv(cio)[1]
        controls << [oid, crit_value, value_tlv]
      end
      controls
    end
  end

  # A socket that records writes and returns canned PDUs, stamping each
  # response with the message id of the preceding request.
  class FakeSocket
    attr_reader :writes, :closed_count

    def initialize(responses)
      @responses = responses
      @writes = []
      @closed_count = 0
    end

    def write(bytes)
      @writes << bytes.b
      bytes.bytesize
    end

    def read_ber(_syntax = nil)
      response = @responses.shift
      response[0] = BerWalk.message_id_of(@writes.last)
      response
    end

    def close
      @closed_count += 1
    end
  end

  # Raises a protocol error once +fail_after+ successful reads have occurred.
  class FlakySocket < FakeSocket
    def initialize(responses, fail_after)
      super(responses)
      @fail_after = fail_after
      @reads = 0
    end

    def read_ber(syntax = nil)
      @reads += 1
      if @reads > @fail_after
        raise Net::LDAP::ResponseMissingOrInvalidError, "response missing or invalid"
      end

      super(syntax)
    end
  end

  def extended_response(code, value = nil)
    inner = Net::BER::BerIdentifiedArray.new([code, "", ""] + (value ? [value] : []))
    inner.ber_identifier = Net::LDAP::PDU::ExtendedResponse
    [0, inner]
  end

  def operation_response(tag, code, message = "")
    inner = Net::BER::BerIdentifiedArray.new([code, "", message])
    inner.ber_identifier = tag
    [0, inner]
  end

  def start_response(identifier = "txn-identifier")
    extended_response(Net::LDAP::ResultCodeSuccess, identifier)
  end

  def commit_response(code = Net::LDAP::ResultCodeSuccess)
    extended_response(code)
  end

  def bind_result_pdu(code = Net::LDAP::ResultCodeSuccess)
    Net::LDAP::PDU.new(operation_response(Net::LDAP::PDU::BindResult, code))
  end

  def build_connection(responses, socket_class: FakeSocket)
    socket = socket_class.new(responses)
    connection = Net::LDAP::Connection.new(:socket => socket)
    [connection, socket]
  end

  def build_ldap(responses, socket_class: FakeSocket)
    connection, socket = build_connection(responses, socket_class: socket_class)
    ldap = Net::LDAP.new
    ldap.connection = connection
    [ldap, connection, socket]
  end

  def add_args
    { dn: "cn=George,ou=people,dc=example,dc=com",
      attributes: { cn: "George", objectclass: "person" } }
  end

  def app_tags(socket)
    socket.writes.map { |bytes| BerWalk.app_tag_of(bytes) }
  end

  def controls_in(message)
    field = BerWalk.controls_field_of(message)
    flunk("expected a controls field") if field.nil?
    BerWalk.parse_controls(field)
  end

  # ---------- Connection-level extended operations ----------

  def test_start_transaction_wires_extended_request_and_reads_identifier
    connection, socket = build_connection([start_response("id-42")])

    pdu = connection.start_transaction

    assert_equal Net::LDAP::PDU::ExtendedRequest,
                 BerWalk.app_tag_of(socket.writes.first)
    assert_includes socket.writes.first, START_OID
    assert pdu.success?
    assert_equal "id-42", pdu.extended_response
  end

  def test_start_transaction_raises_when_response_missing
    socket = FlakySocket.new([], 0)
    connection = Net::LDAP::Connection.new(:socket => socket)

    assert_raise Net::LDAP::ResponseMissingOrInvalidError do
      connection.start_transaction
    end
  end

  def test_end_transaction_commit_encoding
    connection, socket = build_connection([commit_response])

    connection.end_transaction("id-7", true)

    message = socket.writes.first
    assert_equal Net::LDAP::PDU::ExtendedRequest, BerWalk.app_tag_of(message)
    assert_includes message, END_OID
    assert_includes message, true.to_ber
    assert_includes message, "id-7".to_ber
  end

  def test_end_transaction_abort_encoding
    connection, socket = build_connection([commit_response])

    connection.end_transaction("id-8", false)

    message = socket.writes.first
    assert_includes message, false.to_ber
    assert_includes message, "id-8".to_ber
  end

  # ---------- Transaction control attached to each update ----------

  def test_each_update_carries_the_transaction_specification_control
    ldap, _connection, socket = build_ldap([
      start_response("id-9"),
      operation_response(Net::LDAP::PDU::AddResponse, 0),
      operation_response(Net::LDAP::PDU::ModifyResponse, 0),
      operation_response(Net::LDAP::PDU::DeleteResponse, 0),
      operation_response(Net::LDAP::PDU::ModifyRDNResponse, 0),
      commit_response,
    ])

    result = ldap.transaction do |txn|
      txn.add(add_args)
      txn.modify(dn: "cn=x", operations: [[:replace, :cn, "y"]])
      txn.delete(dn: "cn=x")
      txn.rename(olddn: "cn=a", newrdn: "cn=b")
    end

    assert result.committed?
    assert_equal [
      Net::LDAP::PDU::ExtendedRequest,   # start
      Net::LDAP::PDU::AddRequest,
      Net::LDAP::PDU::ModifyRequest,
      Net::LDAP::PDU::DeleteRequest,
      Net::LDAP::PDU::ModifyRDNRequest,
      Net::LDAP::PDU::ExtendedRequest,   # end
    ], app_tags(socket)

    socket.writes[1..4].each do |message|
      control = controls_in(message).first
      assert_equal TXN_OID, control[0]
      assert_equal "\xFF".b, control[1]        # BOOLEAN TRUE (criticality)
      assert_equal "id-9", control[2]          # transaction identifier
    end
  end

  def test_transaction_control_is_merged_with_existing_controls
    ldap, _connection, socket = build_ldap([
      start_response("id-10"),
      operation_response(Net::LDAP::PDU::AddResponse, 0),
      commit_response,
    ])
    user_control = ["1.2.3.4".to_ber, false.to_ber].to_ber_sequence

    ldap.transaction do |txn|
      txn.add(add_args.merge(controls: [user_control]))
    end

    oids = controls_in(socket.writes[1]).map(&:first)
    assert_includes oids, "1.2.3.4"
    assert_includes oids, TXN_OID
    assert_equal 2, oids.length
  end

  def test_modify_convenience_wrappers_join_the_transaction
    ldap, _connection, socket = build_ldap([
      start_response("id-11"),
      operation_response(Net::LDAP::PDU::ModifyResponse, 0),
      operation_response(Net::LDAP::PDU::ModifyResponse, 0),
      operation_response(Net::LDAP::PDU::ModifyResponse, 0),
      commit_response,
    ])

    result = ldap.transaction do |txn|
      txn.add_attribute("cn=x", :mail, "a@example.com")
      txn.replace_attribute("cn=x", :mail, "b@example.com")
      txn.delete_attribute("cn=x", :mail)
    end

    assert result.committed?
    # start, three modify updates carrying the control, commit
    modify_messages = socket.writes[1..3]
    assert_equal [Net::LDAP::PDU::ModifyRequest] * 3,
                 modify_messages.map { |m| BerWalk.app_tag_of(m) }
    modify_messages.each do |message|
      assert_equal TXN_OID, controls_in(message).first[0]
    end
  end

  # ---------- Success path ----------

  def test_successful_commit
    ldap, _connection, socket = build_ldap([
      start_response,
      operation_response(Net::LDAP::PDU::AddResponse, 0),
      commit_response,
    ])

    result = ldap.transaction { |txn| txn.add(add_args) }

    assert result.committed?
    assert result.success?
    refute result.rolled_back?
    refute result.unknown?
    refute result.not_started?
    assert_equal :committed, result.reason
    assert_equal Net::LDAP::ResultCodeSuccess, result.code
    assert_nil ldap.current_transaction
    assert_equal 3, socket.writes.length
  end

  # ---------- Start transaction extension failure ----------

  def test_start_extension_failure_is_not_started
    ldap, _connection, socket = build_ldap([
      extended_response(Net::LDAP::ResultCodeUnwillingToPerform),
    ])

    result = ldap.transaction { |txn| txn.add(add_args) }

    assert result.not_started?
    assert_equal :start_failed, result.reason
    assert_equal Net::LDAP::ResultCodeUnwillingToPerform, result.code
    refute result.committed?
    assert_equal 1, socket.writes.length # only the start request
  end

  def test_start_extension_network_error_is_not_started
    socket = FlakySocket.new([], 0)
    connection = Net::LDAP::Connection.new(:socket => socket)
    ldap = Net::LDAP.new
    ldap.connection = connection

    result = ldap.transaction { |txn| txn.add(add_args) }

    assert result.not_started?
    assert_equal :start_failed, result.reason
    assert_kind_of Net::LDAP::ResponseMissingOrInvalidError, result.error
  end

  # ---------- Single operation failure ----------

  def test_failed_update_aborts_and_reports_rolled_back
    ldap, _connection, socket = build_ldap([
      start_response,
      operation_response(Net::LDAP::PDU::AddResponse,
                         Net::LDAP::ResultCodeEntryAlreadyExists, "already there"),
      commit_response, # the abort request succeeds
    ])

    result = ldap.transaction { |txn| txn.add(add_args) }

    assert result.rolled_back?
    assert_equal :operation_failed, result.reason
    assert_equal :add, result.operation
    assert_equal Net::LDAP::ResultCodeEntryAlreadyExists, result.code
    assert_equal "already there", result.message
    assert_equal 3, socket.writes.length # start, failed add, abort
    assert_equal Net::LDAP::PDU::ExtendedRequest,
                 BerWalk.app_tag_of(socket.writes.last)
  end

  def test_failed_update_with_unconfirmable_abort_is_unknown
    socket = FlakySocket.new([
      start_response,
      operation_response(Net::LDAP::PDU::AddResponse,
                         Net::LDAP::ResultCodeEntryAlreadyExists),
    ], 2)
    connection = Net::LDAP::Connection.new(:socket => socket)
    ldap = Net::LDAP.new
    ldap.connection = connection

    result = ldap.transaction { |txn| txn.add(add_args) }

    assert result.unknown?
    assert_equal :abort_failed, result.reason
  end

  # ---------- Exception inside the block ----------

  def test_block_exception_triggers_abort_and_is_reported
    ldap, _connection, socket = build_ldap([
      start_response,
      commit_response,
    ])

    error = Class.new(StandardError)
    result = ldap.transaction do |_txn|
      raise error, "kaboom"
    end

    assert result.rolled_back?
    assert_equal :block_exception, result.reason
    assert_kind_of error, result.error
    assert_equal "kaboom", result.error.message
    assert_equal 2, socket.writes.length # start + abort, no updates
    assert_nil ldap.current_transaction
  end

  def test_block_exception_with_lost_abort_is_unknown
    socket = FlakySocket.new([start_response], 1)
    connection = Net::LDAP::Connection.new(:socket => socket)
    ldap = Net::LDAP.new
    ldap.connection = connection

    result = ldap.transaction { |_txn| raise StandardError, "boom" }

    assert result.unknown?
    assert_equal :abort_failed, result.reason
    assert_equal "boom", result.error.message
  end

  # ---------- Commit settlement failure / missing response ----------

  def test_unsuccessful_commit_is_definite_rollback
    ldap, _connection, _socket = build_ldap([
      start_response,
      operation_response(Net::LDAP::PDU::ModifyResponse, 0),
      extended_response(Net::LDAP::ResultCodeOperationsError),
    ])

    result = ldap.transaction do |txn|
      txn.modify(dn: "cn=x", operations: [[:replace, :cn, "z"]])
    end

    assert result.rolled_back?
    assert_equal :commit_failed, result.reason
    assert_equal Net::LDAP::ResultCodeOperationsError, result.code
  end

  def test_missing_commit_response_is_unknown
    socket = FlakySocket.new([
      start_response,
      operation_response(Net::LDAP::PDU::ModifyResponse, 0),
    ], 2)
    connection = Net::LDAP::Connection.new(:socket => socket)
    ldap = Net::LDAP.new
    ldap.connection = connection

    result = ldap.transaction do |txn|
      txn.modify(dn: "cn=x", operations: [[:replace, :cn, "z"]])
    end

    assert result.unknown?
    refute result.committed?
    refute result.rolled_back?
    assert_equal :commit_response_missing, result.reason
    assert_kind_of Net::LDAP::ResponseMissingOrInvalidError, result.error
  end

  # ---------- Transaction coordination guards ----------

  def test_transactions_cannot_be_nested
    ldap, _connection, _socket = build_ldap([start_response, commit_response])

    assert_raise Net::LDAP::NestedTransactionError do
      ldap.transaction do |_txn|
        ldap.transaction { |_inner| }
      end
    end
    assert_nil ldap.current_transaction
  end

  def test_bind_is_rejected_inside_a_transaction
    ldap, _connection, socket = build_ldap([start_response, commit_response])

    result = ldap.transaction do |txn|
      assert_raise Net::LDAP::OperationNotAllowedInTransactionError do
        txn.bind
      end
    end

    assert result.committed?
    refute_includes app_tags(socket), Net::LDAP::PDU::BindRequest
  end

  def test_operation_on_a_swapped_connection_is_rejected
    ldap, _connection, _socket = build_ldap([start_response, commit_response])
    other = Net::LDAP::Connection.new(:socket => FakeSocket.new([]))
    original = ldap.connection

    assert_raise Net::LDAP::TransactionConnectionError do
      ldap.transaction do |txn|
        txn.connection = other
        txn.add(add_args)
      end
    end
    assert_nil ldap.current_transaction
  ensure
    ldap.connection = original
  end

  def test_search_does_not_carry_transaction_control
    ldap, _connection, socket = build_ldap([
      start_response,
      operation_response(Net::LDAP::PDU::SearchResult, 0),
      operation_response(Net::LDAP::PDU::AddResponse, 0),
      commit_response,
    ])

    ldap.transaction do |txn|
      txn.search(base: "dc=example,dc=com", ignore_server_caps: true)
      txn.add(add_args)
    end

    assert_nil BerWalk.controls_field_of(socket.writes[1])
    assert_not_nil BerWalk.controls_field_of(socket.writes[2])
  end

  def test_transaction_without_open_connection_establishes_and_closes_its_own
    socket = FakeSocket.new([
      start_response,
      operation_response(Net::LDAP::PDU::AddResponse, 0),
      commit_response,
    ])
    connection = Net::LDAP::Connection.new(:socket => socket)
    flexmock(connection).should_receive(:bind).and_return(bind_result_pdu)
    flexmock(Net::LDAP::Connection).should_receive(:new).and_return(connection)
    ldap = Net::LDAP.new(host: "127.0.0.1", port: 389)

    result = ldap.transaction { |txn| txn.add(add_args) }

    assert result.committed?
    assert_equal 1, socket.closed_count
    assert_nil ldap.connection
  end

  def test_bind_failure_before_start_returns_not_started
    socket = FakeSocket.new([])
    connection = Net::LDAP::Connection.new(:socket => socket)
    failure = bind_result_pdu(Net::LDAP::ResultCodeInvalidCredentials)
    flexmock(connection).should_receive(:bind).and_return(failure)
    flexmock(Net::LDAP::Connection).should_receive(:new).and_return(connection)
    ldap = Net::LDAP.new(host: "127.0.0.1", port: 389)

    result = ldap.transaction { |txn| txn.add(add_args) }

    assert result.not_started?
    assert_equal :start_failed, result.reason
    assert_equal Net::LDAP::ResultCodeInvalidCredentials, result.code
  end
end

class TestLDAPTransactionResult < Test::Unit::TestCase
  def result(overrides = {})
    Net::LDAP::Transaction::Result.new(
      **{ status: :committed, reason: :committed }.merge(overrides))
  end

  def test_predicate_methods_match_status
    assert result(status: :committed).committed?
    assert result(status: :rolled_back).rolled_back?
    assert result(status: :unknown).unknown?
    assert result(status: :not_started).not_started?
  end

  def test_success_and_failure
    assert result(status: :committed).success?
    refute result(status: :rolled_back).success?
    assert result(status: :unknown).failure?
  end

  def test_to_h_exposes_classification
    hash = result(status: :rolled_back, reason: :operation_failed,
                  code: 68, operation: :add).to_h
    assert_equal :rolled_back, hash[:status]
    assert_equal :operation_failed, hash[:reason]
    assert_equal 68, hash[:code]
    assert_equal :add, hash[:operation]
  end

  def test_unknown_status_constants_are_exhaustive
    assert_equal [:committed, :rolled_back, :unknown, :not_started],
                 Net::LDAP::Transaction::Result::STATUSES
    assert_includes Net::LDAP::Transaction::Result::REASONS, :commit_response_missing
  end

  def test_invalid_status_is_rejected
    assert_raise ArgumentError do
      Net::LDAP::Transaction::Result.new(status: :bogus)
    end
  end

  def test_invalid_reason_is_rejected
    assert_raise ArgumentError do
      Net::LDAP::Transaction::Result.new(status: :unknown, reason: :bogus)
    end
  end
end
