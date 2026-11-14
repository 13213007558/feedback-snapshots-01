require_relative '../common'
require 'net/ssh/authentication/session'
require 'net/ssh/authentication/agent_signing'

# End-to-end checks through Authentication::Session and the real publickey
# method, against a fake agent that records the sign requests it receives.
module Authentication
  class TestAgentSigningFlow < NetSSHTest
    include Net::SSH::Authentication::Constants
    include Net::SSH::Transport::Constants

    class FakeAgent
      attr_reader :sign_requests
      attr_writer :identities

      def initialize
        @sign_requests = []
        @identities = []
      end

      def sign(key, data, flags = 0)
        @sign_requests << { key: key, data: data, flags: flags }
        "sig-#{@sign_requests.length}"
      end

      def identities
        @identities
      end

      def close; end
    end

    def setup
      @fake_agent = FakeAgent.new
      Net::SSH::Authentication::Agent.stubs(:connect).returns(@fake_agent)
      @key = OpenSSL::PKey::RSA.new(1024)
      @fake_agent.identities = [@key.public_key]
    end

    # Two connections to different verified hosts, each authenticating with the
    # agent. The hook sees each connection's own target, and each connection
    # sends exactly the one signature it needs.
    def test_two_sessions_get_only_their_own_verified_target
      contexts = []
      authorization = ->(context) { contexts << context; true }

      first = transport(host: "one.example.com")
      expect_publickey_accepted(first)
      manager = auth_session(first, authorization)
      assert manager.authenticate("ssh-connection", "jamis")

      second = transport(host: "two.example.com")
      expect_publickey_accepted(second)
      assert auth_session(second, authorization).authenticate("ssh-connection", "jamis")

      assert_equal %w[one.example.com two.example.com], contexts.map(&:host)
      assert_equal %w[one.example.com two.example.com], contexts.map { |c| c.target.host }
      assert_equal [%w[session-one], %w[session-two]], contexts.map { |c| [c.session_id] }
      assert_equal 2, @fake_agent.sign_requests.length
      assert_equal 1, first.signed_request_count
      assert_equal 1, second.signed_request_count
    end

    # A rekey between two authentications must not reuse the old target.
    def test_authentication_retry_after_rekey_uses_the_new_target
      contexts = []
      authorization = ->(context) { contexts << context; true }
      transport = transport(host: "one.example.com", key_exchange: 1)

      expect_publickey_accepted(transport)
      session = auth_session(transport, authorization)
      assert session.authenticate("ssh-connection", "jamis")

      new_host_key = OpenSSL::PKey::RSA.new(1024)
      transport.forget_verified_host_key
      transport.host_key_verified!(new_host_key, new_host_key.fingerprint("SHA256"))

      transport.reset_script
      expect_publickey_accepted(transport)
      assert session.authenticate("ssh-connection", "jamis")

      assert_equal 2, contexts.length
      assert_equal [1, 2], contexts.map(&:key_exchange)
      refute_same contexts[0].host_key, contexts[1].host_key
      assert_equal new_host_key.to_blob, contexts[1].host_key.to_blob
      assert_equal 2, @fake_agent.sign_requests.length
    end

    # Between rekey and verification no signature may be requested, even though
    # an earlier authentication on the connection succeeded.
    def test_retried_authentication_is_refused_while_the_new_key_exchange_is_unverified
      transport = transport(host: "one.example.com")
      expect_publickey_accepted(transport)
      session = auth_session(transport, ->(_context) { true })
      assert session.authenticate("ssh-connection", "jamis")
      assert_equal 1, @fake_agent.sign_requests.length

      transport.forget_verified_host_key
      transport.reset_script
      expect_publickey_refused(transport)
      refute session.authenticate("ssh-connection", "jamis")
      assert_equal 1, @fake_agent.sign_requests.length
    end

    # A refused key is skipped like any other refused identity: the next key is
    # offered, and the refused key is never sent to the agent.
    def test_refused_key_is_not_signed_with_but_the_next_key_is
      refused = @key.public_key
      allowed = OpenSSL::PKey::RSA.new(1024).public_key
      @fake_agent.identities = [refused, allowed]
      refused_keys = [refused.to_blob]
      authorization = ->(context) { !refused_keys.include?(context.public_key.to_blob) }

      transport = transport(host: "one.example.com")
      expect_publickey_refused_then_accepted(transport, allowed)
      assert auth_session(transport, authorization).authenticate("ssh-connection", "jamis")

      assert_equal [allowed.to_blob], @fake_agent.sign_requests.map { |r| r[:key].to_blob }
      assert_equal [refused.to_blob, allowed.to_blob], transport.offered_key_blobs
    end

    private

    def auth_session(transport, authorization)
      Net::SSH::Authentication::Session.new(
        transport,
        auth_methods: %w[publickey], pubkey_algorithms: %w[ssh-rsa],
        agent_signing_authorization: authorization
      )
    end

    # A MockTransport that also answers what agent signing authorization asks
    # of the connection's transport, and records the key requests it receives.
    class VerifiableTransport < MockTransport
      include Net::SSH::Authentication::Constants
      include Net::SSH::Transport::Constants

      attr_reader :offered_key_blobs

      def initialize(host:, host_key:, session_id:, key_exchange:, options: {})
        super(options)
        @host = host
        @port = 22
        @offered_key_blobs = []
        @signed_request_count = 0
        @key_exchange_sequence = key_exchange
        @verified_host_key = host_key
        @algorithms = Struct.new(:session_id).new(session_id)
        reset_script
      end

      attr_reader :host, :port

      def algorithms
        @algorithms
      end

      attr_reader :verified_host_key

      def verified_host_key_fingerprint
        verified_host_key&.fingerprint("SHA256")
      end

      def key_exchange_sequence
        @key_exchange_sequence
      end

      def host_key_verified!(key, _fingerprint)
        @verified_host_key = key
        @key_exchange_sequence += 1
      end

      def forget_verified_host_key
        @verified_host_key = nil
      end

      def reset_script
        @expectations = []
        @queue = []
        @signed_request_count = 0
      end

      def signed_request_count
        @signed_request_count
      end

      # Same scripting contract as MockTransport, but it counts signed
      # publickey requests and records which keys were offered.
      def send_message(message)
        buffer = Net::SSH::Buffer.new(message.to_s)
        type = buffer.read_byte
        if type == USERAUTH_REQUEST
          buffer.read_string
          buffer.read_string
          buffer.read_string
          signed = buffer.read_bool
          buffer.read_string
          offered = Net::SSH::Buffer.new(buffer.read_string).read_key
          buffer.read_string if signed
          @offered_key_blobs << offered.to_blob unless signed
          @signed_request_count += 1 if signed
        elsif type == SERVICE_REQUEST
          buffer.read_string
        end
        super
      end
    end

    def transport(host:, key_exchange: 1)
      session_id = "session-#{host.sub(/\.example\.com\z/, '')}"
      VerifiableTransport.new(host: host, host_key: OpenSSL::PKey::RSA.new(1024),
                              session_id: session_id, key_exchange: key_exchange,
                              options: { pubkey_algorithms: %w[ssh-rsa] })
    end

    def expect_publickey_accepted(transport)
      expect_service_accept(transport)
      key = @fake_agent.identities.first
      transport.expect do |t, packet|
        assert_equal USERAUTH_REQUEST, packet.type
        assert_unsigned(transport, packet, key)
        t.return(USERAUTH_PK_OK)
      end
      transport.expect do |t, packet|
        assert_equal USERAUTH_REQUEST, packet.type
        assert_signed(transport, packet)
        t.return(USERAUTH_SUCCESS)
      end
    end

    def expect_publickey_refused(transport)
      expect_service_accept(transport)
      key = @fake_agent.identities.first
      transport.expect do |t, packet|
        assert_unsigned(transport, packet, key)
        t.return(USERAUTH_PK_OK)
      end
    end

    def expect_publickey_refused_then_accepted(transport, signed_key)
      expect_service_accept(transport)
      refused, allowed = @fake_agent.identities
      transport.expect do |t, packet|
        assert_unsigned(transport, packet, refused)
        t.return(USERAUTH_PK_OK)
      end
      transport.expect do |t, packet|
        assert_unsigned(transport, packet, allowed)
        t.return(USERAUTH_PK_OK)
      end
      transport.expect do |t, packet|
        assert_signed(transport, packet, signed_key)
        t.return(USERAUTH_SUCCESS)
      end
    end

    def expect_service_accept(transport)
      transport.expect do |t, packet|
        assert_equal SERVICE_REQUEST, packet.type
        assert_equal "ssh-userauth", packet.read_string
        t.return(SERVICE_ACCEPT)
      end
    end

    def assert_unsigned(_transport, packet, key)
      assert_equal "jamis", packet.read_string
      assert_equal "ssh-connection", packet.read_string
      assert_equal "publickey", packet.read_string
      assert_equal false, packet.read_bool
      assert_equal key.ssh_type, packet.read_string
      assert_equal key.to_blob, Net::SSH::Buffer.new(packet.read_string).read_key.to_blob
    end

    def assert_signed(_transport, packet, key = nil)
      assert_equal "jamis", packet.read_string
      assert_equal "ssh-connection", packet.read_string
      assert_equal "publickey", packet.read_string
      assert_equal true, packet.read_bool
      assert_equal "ssh-rsa", packet.read_string
      offered = Net::SSH::Buffer.new(packet.read_string).read_key
      assert_equal key.to_blob, offered.to_blob if key
      refute_nil packet.read_string
    end
  end
end
