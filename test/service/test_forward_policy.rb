require_relative '../common'
require 'net/ssh'
require 'net/ssh/authentication/agent'
require 'net/ssh/connection/session'
require 'net/ssh/service/forward'

module Service
  # Tests for the destination policy of Service::Forward. They use an in-memory
  # session, channel and fake sockets, and drive forwarded-tcpip packets
  # directly, so no listener is bound and no destination is connected.
  class TestForwardPolicy < NetSSHTest
    include Net::SSH::Connection::Constants

    SESSION_ID = "an-observed-session-id".freeze

    class PolicySession
      attr_reader :sent, :options, :transport

      def initialize(options = {}, session_id: SESSION_ID)
        @sent = []
        @options = options
        @transport = PolicyTransport.new(session_id)
        @listening = {}
        @pending = nil
      end

      def listening
        @listening
      end

      def logger; end

      def on_open_channel(*); end

      def listen_to(io, &callback)
        @listening[io] = callback
      end

      def stop_listening_to(io)
        @listening.delete(io)
      end

      def open_channel(type, *extra, &block)
        @sent << [:open_channel, type, *extra]
        channel = Net::SSH::Connection::Channel.new(self, type, 0)
        channel.do_open_confirmation(7, 0x20000, 0x8000)
        block&.call(channel)
        channel
      end

      def send_global_request(type, *extra, &callback)
        @sent << [:global_request, type, *extra]
        @pending = callback
      end

      def succeed_global_request(*response)
        @pending.call(true, Net::SSH::Buffer.from(*response))
      end

      def fail_global_request
        @pending.call(false, nil)
      end
    end

    class PolicyTransport
      attr_reader :algorithms

      def initialize(session_id)
        @algorithms = Struct.new(:session_id).new(session_id)
      end
    end

    # The parts of a socket that prepare_client and Channel#send_data touch.
    class PolicySocket
      attr_accessor :logger, :available
      attr_reader :closed

      def initialize
        @available = 0
        @closed = false
      end

      def closed?
        @closed
      end

      def close
        @closed = true
      end

      def shutdown
        @closed = true
      end
    end

    class FakeServer
      attr_reader :addr, :accepted

      def initialize(port, client = nil)
        @addr = ["AF_INET", port, "127.0.0.1", "127.0.0.1"]
        @client = client
        @accepted = 0
      end

      def accept
        @accepted += 1
        @client
      end

      def close
        @closed = true
      end

      def closed?
        @closed
      end

      def shutdown; end
    end

    def setup
      @session = PolicySession.new({ user: "alice" })
      @forward = Net::SSH::Service::Forward.new(@session)
      @requests = []
      @connect_attempts = []
      @resolve_calls = []
      @forward.resolver = lambda do |host, port|
        @resolve_calls << [host, port]
        %w[192.0.2.10 192.0.2.11]
      end
      @forward.connector = lambda do |host, port|
        @connect_attempts << [host, port]
        PolicySocket.new
      end
    end

    def policy(&block)
      @forward.policy = lambda do |request|
        @requests << request
        block.call(request)
      end
    end

    def test_no_policy_keeps_unrestricted_remote_forwarding
      @forward.remote(22, "db.internal", 2222)

      assert_equal [], @requests
      assert_equal [[:global_request, "tcpip-forward", :string, "127.0.0.1", :long, 2222]], @session.sent

      @session.succeed_global_request
      assert_equal [[2222, "127.0.0.1"]], @forward.active_remotes
      assert_equal({ [22, "db.internal"] => [2222, "127.0.0.1"] }, @forward.active_remote_destinations)
    end

    def test_local_forward_reports_direction_and_server_resolution_without_pinning_an_ip
      policy { |request| [request.host, request.port] }
      with_fake_server(4000) do
        @forward.local(4000, "internal.example", 5432)
      end

      assert_equal 1, @requests.length
      request = @requests.first
      assert_equal :local, request.direction
      assert_equal ["internal.example", 5432], [request.host, request.port]
      assert_equal [:server, :client], [request.target_resolution, request.listener_resolution]
      assert_nil request.resolved_ips
      assert_equal SESSION_ID, request.session_id
      assert_equal "alice", request.user
      assert_equal [], @resolve_calls # only the server resolves the destination
    end

    def test_local_forward_refused_by_policy_is_not_bound_and_opens_no_channel
      policy { |_request| nil }
      TCPServer.expects(:new).never

      error = assert_raises(Net::SSH::Service::Forward::NotPermitted) do
        @forward.local(4000, "internal.example", 5432)
      end
      assert_match(/not permitted/, error.message)
      assert_equal [], @session.sent
      assert_equal [], @forward.active_locals
    end

    def test_local_policy_cannot_claim_to_have_pinned_an_address
      policy { |request| [request.host, request.port, "192.0.2.10"] }
      TCPServer.expects(:new).never

      error = assert_raises(ArgumentError) { @forward.local(4000, "internal.example", 5432) }
      assert_match(/server/, error.message)
      assert_equal [], @session.sent
    end

    def test_local_forward_refuses_an_ephemeral_port_before_binding
      policy { |_request| nil }
      TCPServer.expects(:new).never

      assert_raises(Net::SSH::Service::Forward::NotPermitted) { @forward.local(0, "internal.example", 5432) }
      assert_equal [], @session.sent
    end

    def test_refused_local_connection_does_not_open_a_channel
      policy { |request| [request.host, request.port] }
      client = PolicySocket.new
      server = FakeServer.new(4000, client)
      TCPServer.stubs(:new).returns(server)

      @forward.local(4000, "internal.example", 5432)
      callback = @session.listening[server]
      refute_nil callback

      callback.call(server)
      assert_equal 1, server.accepted
      assert_equal [[:open_channel, "direct-tcpip", :string, "internal.example", :long, 5432,
                     :string, "127.0.0.1", :long, 4000]], @session.sent
    ensure
      @session.listening.delete(server)
      client.close
    end

    def test_local_forward_connection_accepted_before_cancel_is_refused_after_cancel
      policy { |request| [request.host, request.port] }
      client = PolicySocket.new
      server = FakeServer.new(4000, client)
      TCPServer.stubs(:new).returns(server)

      @forward.local(4000, "internal.example", 5432)
      callback = @session.listening[server]
      @forward.cancel_local(4000)

      # The accepted connection is handed to the callback after the cancellation.
      callback.call(server)
      assert client.closed?, "an accepted connection of a cancelled forward must not be served"
      assert_equal [], @session.sent, "no channel may be opened for a cancelled forward"
    end

    def test_remote_forward_resolves_destination_once_and_pins_the_address
      policy { |request| [request.host, request.port] }
      @forward.remote(22, "db.internal", 0)

      assert_equal [["db.internal", 22]], @resolve_calls
      request = @requests.first
      assert_equal :remote, request.direction
      assert_equal [:client, :server], [request.target_resolution, request.listener_resolution]
      assert_equal %w[192.0.2.10 192.0.2.11], request.resolved_ips

      @session.succeed_global_request(:long, 6100)
      assert_equal [[6100, "127.0.0.1"]], @forward.active_remotes
    end

    def test_remote_forward_out_of_range_port_is_refused_before_listening
      policy { |request| request.port == 22 ? [request.host, request.port] : nil }

      assert_raises(Net::SSH::Service::Forward::NotPermitted) do
        @forward.remote(70_000, "db.internal", 3000)
      end
      assert_equal [], @session.sent
      assert_equal [], @forward.active_remotes
    end

    def test_remote_forward_to_destination_outside_the_allow_list_is_refused
      policy { |request| request.host == "db.internal" ? [request.host, 5432] : nil }

      assert_raises(Net::SSH::Service::Forward::NotPermitted) do
        @forward.remote(5432, "attacker.example", 3000)
      end
      assert_equal [], @session.sent
    end

    def test_server_opened_channel_connects_only_to_the_approved_destination
      policy { |request| [request.host, request.port] }
      @forward.remote(5432, "db.internal", 6000)
      @session.succeed_global_request
      requests_before = @requests.length

      channel = Net::SSH::Connection::Channel.new(@session, "forwarded-tcpip", 1)
      @forward.send(:forwarded_tcpip, @session, channel, channel_packet(6000, "127.0.0.1", "198.51.100.9", 4567))

      assert_equal [["192.0.2.10", 5432]], @connect_attempts
      server = @requests.last
      assert_equal requests_before + 1, @requests.length
      assert_equal :server, server.direction
      assert_equal ["db.internal", 5432], [server.host, server.port]
      assert_equal ["127.0.0.1", 6000, "198.51.100.9", 4567],
                   [server.listen_host, server.listen_port, server.originator_host, server.originator_port]
      assert_equal %w[192.0.2.10 192.0.2.11], server.resolved_ips
      assert_equal [], @resolve_calls.last(2) - [["db.internal", 5432]] # no second resolution
    end

    def test_server_opened_channel_to_an_unapproved_destination_is_never_connected
      policy { |request| request.direction == :remote ? [request.host, request.port] : nil }
      @forward.remote(5432, "db.internal", 6000)
      @session.succeed_global_request

      error = assert_raises(Net::SSH::ChannelOpenFailed) do
        channel = Net::SSH::Connection::Channel.new(@session, "forwarded-tcpip", 1)
        @forward.send(:forwarded_tcpip, @session, channel, channel_packet(6000, "127.0.0.1", "198.51.100.9", 4567))
      end
      assert_equal 1, error.code
      assert_equal [], @connect_attempts, "a refused channel must not reach the connector"
    end

    def test_policy_set_after_a_remote_forward_pins_the_channel_it_opens
      @forward.remote(5432, "db.internal", 6000)
      @session.succeed_global_request
      policy { |request| [request.host, request.port] }

      channel = Net::SSH::Connection::Channel.new(@session, "forwarded-tcpip", 1)
      @forward.send(:forwarded_tcpip, @session, channel, channel_packet(6000, "127.0.0.1", "198.51.100.9", 4567))

      assert_equal [["192.0.2.10", 5432]], @connect_attempts
      assert_equal %w[192.0.2.10 192.0.2.11], @requests.last.resolved_ips
    end

    def test_server_opened_channel_for_unknown_listener_is_refused_without_connecting
      @forward.remote(5432, "db.internal", 6000)
      @session.succeed_global_request
      @requests.clear
      @resolve_calls.clear

      assert_raises(Net::SSH::ChannelOpenFailed) do
        channel = Net::SSH::Connection::Channel.new(@session, "forwarded-tcpip", 1)
        @forward.send(:forwarded_tcpip, @session, channel, channel_packet(6001, "127.0.0.1", "198.51.100.9", 4567))
      end
      assert_equal [], @connect_attempts
      assert_equal [], @resolve_calls
      assert_equal [], @requests, "an unknown listener is refused before the policy runs"
    end

    def test_cancel_remote_revokes_permit_before_the_late_channel_open
      policy { |request| [request.host, request.port] }
      @forward.remote(5432, "db.internal", 6000)
      @session.succeed_global_request
      @forward.cancel_remote(6000)
      requests_before = @requests.length
      @resolve_calls.clear
      @connect_attempts.clear

      error = assert_raises(Net::SSH::ChannelOpenFailed) do
        channel = Net::SSH::Connection::Channel.new(@session, "forwarded-tcpip", 1)
        @forward.send(:forwarded_tcpip, @session, channel, channel_packet(6000, "127.0.0.1", "198.51.100.9", 4567))
      end
      assert_match(/cancelled/, error.message)
      assert_equal requests_before, @requests.length, "a cancelled permit is refused before the policy runs"
      assert_equal [], @connect_attempts
      assert_equal [], @resolve_calls
    end

    def test_cancel_remote_before_the_global_request_succeeds_does_not_register_the_forward
      policy { |request| [request.host, request.port] }
      @forward.remote(5432, "db.internal", 0)
      @forward.cancel_remote(0)

      @session.succeed_global_request(:long, 6000)
      assert_equal [], @forward.active_remotes
    end

    def test_cancel_local_revokes_the_permit_used_by_accepted_connections
      policy { |request| [request.host, request.port] }
      server = FakeServer.new(4000)
      TCPServer.stubs(:new).returns(server)

      @forward.local(4000, "internal.example", 5432)
      grant = @forward.instance_variable_get(:@local_forwarded_ports).values.first.grant

      @forward.cancel_local(4000)
      refute grant.active?
      assert_equal [], @forward.active_locals
    end

    def test_policy_permits_are_bound_to_the_session_identity
      permit = Net::SSH::Service::Forward::Permit.new(
        Net::SSH::Service::Forward::Request.new(direction: :remote, host: "db.internal", port: 5432,
                                                session_id: "another-session", user: "alice")
      )
      @forward.policy = ->(_request) { permit }

      assert_raises(ArgumentError) { @forward.remote(5432, "db.internal", 6000) }
      assert_equal [], @session.sent
    end

    def test_identity_without_an_observable_session_id_is_not_guessed
      session = PolicySession.new({ user: "alice" }, session_id: nil)
      session.transport.define_singleton_method(:algorithms) do
        raise Net::SSH::NotSupportedOverControlMaster, "belongs to the ControlMaster"
      end
      forward = Net::SSH::Service::Forward.new(session)
      forward.resolver = ->(_host, _port) { %w[192.0.2.10] }
      requests = []
      forward.policy = lambda do |request|
        requests << request
        [request.host, request.port]
      end
      forward.remote(5432, "db.internal", 6000)

      request = requests.first
      assert_nil request.session_id, "an unobservable session id must not be fabricated"
      assert_nil request.user, "the ControlMaster's authenticated user is not observable here"
    end

    def test_policy_permits_are_bound_to_the_request_they_were_issued_for
      permit = Net::SSH::Service::Forward::Permit.new(
        Net::SSH::Service::Forward::Request.new(direction: :remote, host: "other.internal", port: 5432,
                                                session_id: SESSION_ID, user: "alice")
      )
      @forward.policy = ->(_request) { permit }

      assert_raises(ArgumentError) { @forward.remote(5432, "db.internal", 6000) }
      assert_equal [], @session.sent
      assert_equal [], @forward.active_remotes
    end

    def test_policy_cannot_redirect_a_permit_to_another_destination
      policy { |_request| ["attacker.example", 5432] }
      assert_raises(ArgumentError) { @forward.remote(5432, "db.internal", 6000) }
      assert_equal [], @session.sent
    end

    def test_policy_cannot_add_an_address_outside_the_resolved_set
      policy { |request| [request.host, request.port, "203.0.113.5"] }
      assert_raises(ArgumentError) { @forward.remote(5432, "db.internal", 6000) }
      assert_equal [], @session.sent
    end

    def test_forward_policy_option_is_applied_to_the_session
      policy = ->(_request) { nil }
      forward = mock("forward")
      forward.expects(:policy=).with(policy)
      forward.expects(:policy_identity=).with([SESSION_ID, "testuser"])
      transport = mock("transport")
      transport.stubs(:algorithms).returns(stub(session_id: SESSION_ID))
      connection = mock("connection")
      connection.stubs(:closed?).returns(false)
      connection.stubs(:close)
      connection.stubs(:forward).returns(forward)
      connection.stubs(:transport).returns(transport)

      Net::SSH::Transport::Session.stubs(:new).returns(transport)
      Net::SSH::Authentication::Session.stubs(:new).returns(stub(authenticate: true))
      Net::SSH::Connection::Session.stubs(:new).returns(connection)

      Net::SSH.start("localhost", "testuser", forward_policy: policy) do |ssh|
        assert_same connection, ssh
      end
    end

    def test_setting_a_non_callable_policy_is_rejected
      assert_raises(ArgumentError) { @forward.policy = "allow all" }
      assert_nil @forward.policy
    end

    private

    def channel_packet(connected_port, connected_address, originator_address, originator_port)
      Net::SSH::Buffer.from(
        :string, connected_address, :long, connected_port,
        :string, originator_address, :long, originator_port
      )
    end

    def with_fake_server(port)
      server = FakeServer.new(port)
      TCPServer.stubs(:new).returns(server)
      yield
      server
    end
  end
end
