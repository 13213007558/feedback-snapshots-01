require_relative '../common'
require 'net/ssh/authentication/key_manager'
require 'net/ssh/authentication/agent_signing'
require 'net/ssh/transport/session'

# These tests use a fake agent that records every SSH2_AGENT_SIGN_REQUEST it
# receives, so a hook's decision can be checked against the requests that
# actually reach the agent, not only against what net-ssh returns.
module Authentication
  class TestAgentSigning < NetSSHTest
    include Net::SSH::Authentication::Constants

    # An ssh-agent stand-in that records every signing request it is given.
    class FakeAgent
      attr_reader :sign_requests

      def self.connect(*)
        @instance
      end

      class << self
        attr_accessor :instance
      end

      def initialize
        @sign_requests = []
        @mutex = Mutex.new
      end

      def sign(key, data, flags = 0)
        @mutex.synchronize { @sign_requests << { key: key, data: data, flags: flags } }
        "sig-#{@sign_requests.length}"
      end

      def close; end
    end

    def setup
      @previous_fake_agent = FakeAgent.instance
      @fake_agent = FakeAgent.instance = FakeAgent.new
      Net::SSH::Authentication::Agent.stubs(:connect).returns(@fake_agent)
    end

    def teardown
      FakeAgent.instance = @previous_fake_agent
    end

    # Two sessions to two distinct, verified targets. Each manager is bound to
    # its own transport and agent, as authentication creates it.
    def test_hook_sees_the_verified_target_of_each_session
      contexts = []
      authorization = ->(context) { contexts << context; true }
      manager_one, key_one = session_manager(host: "one.example.com", host_key: rsa(1024), authorization: authorization)
      manager_two, key_two = session_manager(host: "two.example.com", host_key: rsa(1024),
                                             session_id: "other-session-id", authorization: authorization)

      manager_one.sign(key_one, "data-one")
      manager_two.sign(key_two, "data-two")

      assert_equal %w[one.example.com two.example.com], contexts.map(&:host)
      assert_equal %w[one.example.com two.example.com], contexts.map { |c| c.target.host }
      refute_equal contexts[0].session_id, contexts[1].session_id
      assert_equal %i[publickey publickey], contexts.map(&:purpose)
      assert_equal [key_one.to_blob, key_two.to_blob], contexts.map { |c| c.public_key.to_blob }
      assert_equal 2, @fake_agent.sign_requests.length
    end

    def test_host_key_the_hook_was_shown_is_the_verified_one
      transport = transport_stub(host_key: rsa(1024))
      seen = nil
      manager, key = session_manager(transport: transport, authorization: lambda do |context|
        seen = context
        true
      end)

      manager.sign(key, "data")

      assert_equal transport.verified_host_key.to_blob, seen.host_key.to_blob
      assert_equal transport.verified_host_key_fingerprint, seen.host_key_fingerprint
      assert_match(/\ASHA256:/, seen.host_key_fingerprint)
    end

    def test_denied_key_never_reaches_the_agent
      manager, key = session_manager(authorization: ->(_context) { false })

      assert_raises(Net::SSH::Authentication::AgentSigningDenied) { manager.sign(key, "data") }
      assert_empty @fake_agent.sign_requests
    end

    def test_refused_key_never_reaches_the_agent_and_a_different_key_still_can_sign
      transport = transport_stub
      refused = rsa(1024).public_key
      allowed = OpenSSL::PKey::EC.new(OpenSSL::PKey::EC.generate("prime256v1").public_to_der)

      requested = []
      manager = Net::SSH::Authentication::KeyManager.new(
        nil, { password_prompt: MockPrompt.new,
               agent_signing_authorization: lambda do |context|
                 requested << context.public_key
                 context.public_key.to_blob != refused.to_blob
               end },
        transport
      )
      manager.known_identities[refused] = { from: :agent, identity: refused }
      manager.known_identities[allowed] = { from: :agent, identity: allowed }

      assert_raises(Net::SSH::Authentication::AgentSigningDenied) { manager.sign(refused, "data") }
      assert_equal "sig-1", manager.sign(allowed, "data")
      assert_equal [refused, allowed], requested
      assert_equal [allowed.to_blob], @fake_agent.sign_requests.map { |r| r[:key].to_blob }
    end

    def test_hook_is_not_called_and_agent_is_not_asked_before_host_key_verification
      transport = transport_stub(verified: false)
      called = false
      manager, key = session_manager(transport: transport, authorization: ->(_context) { called = true; true })

      assert_raises(Net::SSH::Authentication::AgentSigningDenied) { manager.sign(key, "data") }
      assert_equal false, called
      assert_empty @fake_agent.sign_requests
    end

    def test_rekey_invalidates_the_verified_target_until_verified_again
      transport = transport_stub
      manager, key = session_manager(transport: transport, authorization: ->(_context) { true })

      assert_equal "sig-1", manager.sign(key, "static-key-data")

      # A new key exchange forgets the previous host key, as Transport::Session
      # does when it sees KEXINIT or starts a rekey.
      transport.forget_verified_host_key
      assert_raises(Net::SSH::Authentication::AgentSigningDenied) { manager.sign(key, "static-key-data") }
      assert_equal 1, @fake_agent.sign_requests.length

      rekeyed = rsa(1024)
      transport.host_key_verified!(rekeyed, rekeyed.fingerprint("SHA256"))
      assert_equal "sig-2", manager.sign(key, "static-key-data")
      assert_equal 2, @fake_agent.sign_requests.length
    end

    def test_hook_raising_refuses_the_signature_instead_of_reaching_the_agent
      manager, key = session_manager(authorization: ->(_context) { raise "boom" })

      assert_raises(Net::SSH::Authentication::AgentSigningDenied) { manager.sign(key, "data") }
      assert_empty @fake_agent.sign_requests
    end

    def test_decision_is_void_if_the_connection_moves_on_while_the_hook_decides
      transport = transport_stub
      manager, key = session_manager(transport: transport, authorization: lambda do |_context|
        # A rekey completes while the application is deciding.
        transport.forget_verified_host_key
        new_key = rsa(1024)
        transport.host_key_verified!(new_key, new_key.fingerprint("SHA256"))
        true
      end)

      error = assert_raises(Net::SSH::Authentication::AgentSigningDenied) { manager.sign(key, "data") }
      assert_match(/moved to another key exchange/, error.message)
      assert_empty @fake_agent.sign_requests
    end

    def test_decision_is_void_if_the_host_key_stops_being_verified_while_the_hook_decides
      transport = transport_stub
      manager, key = session_manager(transport: transport, authorization: lambda do |_context|
        transport.forget_verified_host_key
        true
      end)

      error = assert_raises(Net::SSH::Authentication::AgentSigningDenied) { manager.sign(key, "data") }
      assert_match(/no longer verified/, error.message)
      assert_empty @fake_agent.sign_requests
    end

    def test_concurrent_signing_on_two_sessions_stays_within_each_target
      contexts = []
      mutex = Mutex.new
      authorization = lambda do |context|
        mutex.synchronize { contexts << context }
        true
      end
      manager_one, key_one, agent_one = isolated_session_manager(host: "one.example.com", authorization: authorization)
      manager_two, key_two, agent_two = isolated_session_manager(host: "two.example.com", authorization: authorization)

      threads = []
      10.times do |i|
        threads << Thread.new { manager_one.sign(key_one, "one-#{i}") }
        threads << Thread.new { manager_two.sign(key_two, "two-#{i}") }
      end
      threads.each(&:join)

      assert_equal 10, agent_one.sign_requests.length
      assert_equal 10, agent_two.sign_requests.length
      assert_equal [key_one.to_blob], agent_one.sign_requests.map { |r| r[:key].to_blob }.uniq
      assert_equal [key_two.to_blob], agent_two.sign_requests.map { |r| r[:key].to_blob }.uniq

      by_host = contexts.group_by(&:host)
      assert_equal %w[one.example.com two.example.com], by_host.keys.sort
      assert_equal [key_one.to_blob], by_host["one.example.com"].map { |c| c.public_key.to_blob }.uniq
      assert_equal [key_two.to_blob], by_host["two.example.com"].map { |c| c.public_key.to_blob }.uniq
      assert_equal ["session-one"], by_host["one.example.com"].map(&:session_id).uniq
      assert_equal ["session-two"], by_host["two.example.com"].map(&:session_id).uniq
    end

    def test_context_exposes_no_private_key_or_signature_material
      contexts = []
      manager, key = session_manager(authorization: ->(context) { contexts << context; true })

      signature = manager.sign(key, "the data being signed")
      context = contexts.first

      refute context.to_h.values.any? { |value| value.to_s.include?("the data being signed") }
      refute context.to_h.values.any? { |value| value.to_s.include?(signature) }
      refute context.respond_to?(:private_key)
      refute context.respond_to?(:data)
      assert context.to_h.values.none? { |value| value.is_a?(OpenSSL::PKey::PKey) }
      assert_equal key.to_blob, context.public_key.to_blob
    end

    def test_context_is_frozen
      contexts = []
      manager, key = session_manager(authorization: ->(context) { contexts << context; true })

      manager.sign(key, "data")
      assert contexts.first.frozen?
      assert contexts.first.target.frozen?
    end

    def test_purpose_distinguishes_hostbased_from_publickey
      purposes = []
      manager, key = session_manager(authorization: ->(context) { purposes << context.purpose; true })

      manager.sign(key, "data", nil, purpose: :hostbased)
      manager.sign(key, "data", nil, purpose: :publickey)

      assert_equal %i[hostbased publickey], purposes
    end

    def test_hook_is_optional_but_host_key_verification_is_not
      manager, key = session_manager
      assert_nil manager.options[:agent_signing_authorization]

      assert_equal "sig-1", manager.sign(key, "data")

      unverified, key = session_manager(transport: transport_stub(verified: false))
      assert_raises(Net::SSH::Authentication::AgentSigningDenied) { unverified.sign(key, "data") }
    end

    def test_agent_signing_authorization_must_be_callable
      error = assert_raises(ArgumentError) do
        Net::SSH::Authentication::KeyManager.new(nil, agent_signing_authorization: "not callable", password_prompt: MockPrompt.new)
      end
      assert_match(/must respond to call or be nil/, error.message)
    end

    private

    def rsa(bits)
      OpenSSL::PKey::RSA.new(bits)
    end

    def transport_stub(host_key: rsa(1024), verified: true, session_id: "session-id")
      transport = Net::SSH::Transport::Session.allocate
      transport.instance_variable_set(:@host, "net.ssh.test")
      transport.instance_variable_set(:@port, 22)
      transport.instance_variable_set(:@options, {})
      transport.instance_variable_set(:@algorithms, stub("algorithms", session_id: session_id))
      transport.instance_variable_set(:@key_exchange_sequence, 0)
      transport.instance_variable_set(:@verified_host_key, nil)
      transport.instance_variable_set(:@verified_host_key_fingerprint, nil)
      transport.host_key_verified!(host_key, host_key.fingerprint("SHA256")) if verified
      transport
    end

    # A manager bound to its own fake agent, for tests that must keep two
    # sessions' signatures apart.
    def isolated_session_manager(host:, authorization: nil)
      agent = FakeAgent.new
      key = rsa(1024).public_key
      transport = transport_stub(host_key: rsa(1024), session_id: "session-#{host.delete_suffix('.example.com')}")
      transport.instance_variable_set(:@host, host)
      options = { password_prompt: MockPrompt.new }
      options[:agent_signing_authorization] = authorization if authorization
      manager = Net::SSH::Authentication::KeyManager.new(nil, options, transport)
      manager.stubs(:agent).returns(agent)
      manager.known_identities[key] = { from: :agent, identity: key }
      [manager, key, agent]
    end

    def session_manager(host: "net.ssh.test", host_key: rsa(1024), transport: nil, authorization: nil, session_id: "session-id")
      transport ||= transport_stub(host_key: host_key, session_id: session_id)
      transport.instance_variable_set(:@host, host)
      key = rsa(1024).public_key
      options = { password_prompt: MockPrompt.new }
      options[:agent_signing_authorization] = authorization if authorization
      manager = Net::SSH::Authentication::KeyManager.new(nil, options, transport)
      manager.known_identities[key] = { from: :agent, identity: key }
      [manager, key]
    end
  end
end
