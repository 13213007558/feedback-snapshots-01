# -*- ruby encoding: utf-8 -*-
require_relative "test_helper"
require_relative "sync_protocol_helper"

# Drives Net::LDAP#sync_refresh through the real Connection#search loop,
# feeding BER-encoded PDUs from an in-memory socket.
class TestSyncRefresh < Test::Unit::TestCase
  include SyncProtocolHelper

  class MemorySocket
    def initialize(frames)
      @io = StringIO.new(frames.join)
    end

    def read_ber(syntax = nil, &block)
      @io.read_ber(syntax, &block)
    end

    def write(_bytes)
      # Requests are accepted but not interpreted in this harness.
    end

    def close; end
  end

  def setup
    @u1 = uuid(1)
    @u2 = uuid(2)
    @frames = [
      entry_pdu(1, "cn=one", Net::LDAP::Sync::STATE_ADD, @u1, "cn" => "one"),
      entry_pdu(1, "cn=two", Net::LDAP::Sync::STATE_ADD, @u2, "cn" => "two"),
      done_pdu(1, cookie: "ck-initial", refresh_deletes: false),
    ]
  end

  def build_ldap(frames)
    socket = MemorySocket.new(frames)
    ldap = Net::LDAP.new(host: "localhost", port: 389)
    connection = Net::LDAP::Connection.new(socket: socket)
    ldap.instance_variable_set(:@open_connection, connection)
    ldap
  end

  def test_initial_refresh_returns_replacement_and_cookie
    ldap = build_ldap(@frames)

    result = ldap.sync_refresh(base: "dc=example,dc=org")

    assert_equal [@u1, @u2].sort, result.entries.keys.sort
    assert_equal "ck-initial", result.cookie
    assert_equal false, result.refresh_deletes
    assert_equal Net::LDAP::ResultCodeSuccess, ldap.get_operation_result.code
  end

  def test_incremental_present_refresh_replaces_permissions
    previous = {
      @u1 => entry("cn=one", "cn" => "old"),
      @u2 => entry("cn=two", "cn" => "two"),
    }
    frames = [
      entry_pdu(1, "cn=one", Net::LDAP::Sync::STATE_ADD, @u1, "cn" => "new"),
      entry_pdu(1, "cn=two", Net::LDAP::Sync::STATE_PRESENT, @u2),
      done_pdu(1, cookie: "ck-next", refresh_deletes: false),
    ]
    ldap = build_ldap(frames)

    result = ldap.sync_refresh(base: "dc=example,dc=org", cookie: "ck-initial",
                               previous_entries: previous)

    assert_equal [@u1, @u2].sort, result.entries.keys.sort
    assert_equal "new", result.entries[@u1][:cn].first
    assert_equal "ck-next", result.cookie
    # The caller's previous mirror is untouched on success.
    assert_equal "old", previous[@u1][:cn].first
  end

  def test_truncated_stream_raises_and_publishes_nothing
    ldap = build_ldap(@frames[0...1])

    assert_raise(Net::LDAP::Sync::IncompleteRefreshError) do
      ldap.sync_refresh(base: "dc=example,dc=org")
    end
  end

  def test_refresh_required_surfaces_cookie_for_retry
    frames = [
      entry_pdu(1, "cn=one", Net::LDAP::Sync::STATE_PRESENT, @u1),
      done_pdu(1, result_code: Net::LDAP::Sync::RESULT_SYNC_REFRESH_REQUIRED,
                  cookie: "ck-reload"),
    ]
    ldap = build_ldap(frames)

    error = assert_raise(Net::LDAP::Sync::RefreshRequiredError) do
      ldap.sync_refresh(base: "dc=example,dc=org", previous_entries: { @u1 => entry("cn=one") })
    end
    assert_equal "ck-reload", error.cookie
  end

  def test_request_control_uses_refresh_only_mode_and_cookie
    encoded = Net::LDAP::Sync::Codec.encode_request_control(mode: Net::LDAP::Sync::MODE_REFRESH_ONLY,
                                                            cookie: "ck-x")
    parsed = encoded.read_ber(Net::LDAP::AsnSyntax)
    assert_equal Net::LDAP::Sync::OID::REQUEST, parsed[0]
    value = parsed[2].read_ber(Net::LDAP::Sync::Codec::SYNC_SYNTAX)
    assert_equal Net::LDAP::Sync::MODE_REFRESH_ONLY, value[0]
    assert_equal "ck-x", value[1]
  end
end
