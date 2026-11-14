require_relative '../common'
require_relative 'fake_master'
require 'net/ssh'

module NetSSH
  class TestControlMaster < NetSSHTest
    def setup
      skip "ControlMaster needs UNIX sockets" if Gem.win_platform?
      @dir = Dir.mktmpdir('cm')
      @path = File.join(@dir, 'ctl')
      @log = StringIO.new
      @logger = Logger.new(@log)
      @logger.level = Logger::DEBUG
    end

    def teardown
      @master&.stop
      FileUtils.rm_rf(@dir) if @dir
    end

    def start(options = {}, &block)
      Net::SSH.start('example.com', 'alice', { config: false, logger: @logger, control_master: :auto, control_path: @path }.merge(options), &block)
    end

    # A ControlPath that binds the socket to the host, port and user, like the
    # ssh_config default ~/.ssh/cm-%r@%h:%p.
    def bound_path
      File.join(@dir, 'cm-%r@%h:%p')
    end

    def expect_direct_connection
      direct = mock('direct connection')
      direct.stubs(:closed?).returns(true)
      Net::SSH.expects(:connect_directly).with('example.com', 'alice', anything).returns(direct)
      direct
    end

    def test_exec_through_master
      @master = FakeMaster.new(@path, output: "hi\n", exit_status: 3)
      Net::SSH.expects(:connect_directly).never

      start do |ssh|
        assert_instance_of Net::SSH::Multiplex::ProxyTransport, ssh.transport
        result = ssh.exec!("echo hi")
        assert_equal "hi\n", result
        assert_equal 3, result.exitstatus
      end
      assert_equal 1, @master.connections
      assert_includes @log.string, "using ControlMaster at #{@path}"
    end

    def test_old_protocol_version_falls_back
      @master = FakeMaster.new(@path, mode: :old_version)
      direct = expect_direct_connection

      assert_equal direct, start
      assert_match(/WARN -- : control_master: not using ControlMaster at .*unsupported mux protocol version 3/, @log.string)
    end

    def test_refused_proxy_falls_back
      @master = FakeMaster.new(@path, mode: :refuse)
      direct = expect_direct_connection

      assert_equal direct, start
      assert_match(/WARN -- : .*master refused proxy request: Permission denied/, @log.string)
    end

    def test_missing_socket_falls_back
      direct = expect_direct_connection

      assert_equal direct, start
      assert_match(/INFO -- : control_master: no ControlMaster at .*No such file or directory/, @log.string)
      refute_includes @log.string, "WARN"
    end

    def test_stale_socket_falls_back
      UNIXServer.new(@path).close
      direct = expect_direct_connection

      assert_equal direct, start
      assert_match(/INFO -- : control_master: no ControlMaster at .*Connection refused/, @log.string)
      refute_includes @log.string, "WARN"
    end

    def test_silent_master_times_out_and_falls_back
      @master = FakeMaster.new(@path, mode: :silent)
      direct = expect_direct_connection

      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      assert_equal direct, start(timeout: 0.3)
      assert_operator Process.clock_gettime(Process::CLOCK_MONOTONIC) - started, :<, 2
      assert_match(/WARN -- : .*timed out/, @log.string)
    end

    def test_master_of_another_user_falls_back
      @master = FakeMaster.new(@path)
      Process.stubs(:euid).returns(Process.uid + 1)
      direct = expect_direct_connection

      assert_equal direct, start
      assert_match(/WARN -- : .*owned by uid #{Process.uid}/, @log.string)
    end

    def test_invalid_control_path_raises
      Net::SSH.expects(:connect_directly).never
      Net::SSH::Multiplex::Client.expects(:new).never
      {
        "#{@dir}/%z" => /invalid control_path ".*%z": unknown token %z/,
        "#{@dir}/${NET_SSH_TEST_CM_UNSET}" => /invalid control_path .*: variable \$\{NET_SSH_TEST_CM_UNSET\} is not set/,
        "#{@dir}/${NET_SSH_TEST_CM_UNSET" => /invalid control_path .*: unterminated \$\{/,
        "~net_ssh_no_such_user/ctl" => %r{invalid control_path "~net_ssh_no_such_user/ctl": .*net_ssh_no_such_user},
        "#{@dir}/#{'x' * 200}" => /invalid control_path .*too long/
      }.each do |control_path, message|
        error = assert_raises(ArgumentError) { start(control_path: control_path) }
        assert_match message, error.message
      end
    end

    def test_error_building_the_session_propagates
      @master = FakeMaster.new(@path)
      Net::SSH.expects(:connect_directly).never
      Net::SSH::Multiplex::ProxyTransport.stubs(:new).raises(NoMethodError, "boom")

      assert_raises(NoMethodError) { start }
      refute_includes @log.string, "not using ControlMaster"
    end

    def test_control_path_none_falls_back
      direct = expect_direct_connection
      Net::SSH::Multiplex::Client.expects(:new).never

      assert_equal direct, start(control_path: 'none')
    end

    def test_remote_forwarding_raises
      @master = FakeMaster.new(@path)
      start do |ssh|
        assert_raises(Net::SSH::NotSupportedOverControlMaster) { ssh.forward.remote(8080, 'localhost', 80) }
        assert_raises(Net::SSH::NotSupportedOverControlMaster) { ssh.forward.cancel_remote(8080) }
        assert_equal "hello\n", ssh.exec!("true")
      end
      refute_includes @master.received_types, Net::SSH::Connection::Constants::GLOBAL_REQUEST
    end

    def test_global_request_raises
      @master = FakeMaster.new(@path)
      start do |ssh|
        error = assert_raises(Net::SSH::NotSupportedOverControlMaster) { ssh.send_global_request("keepalive@openssh.com") }
        assert_match(/keepalive@openssh.com/, error.message)
      end
    end

    def test_agent_forwarding_request_raises
      @master = FakeMaster.new(@path)
      start do |ssh|
        channel = ssh.open_channel
        ssh.loop { channel.remote_id.nil? }
        assert_raises(Net::SSH::NotSupportedOverControlMaster) { ssh.forward.agent(channel) }
      end
    end

    def test_forward_agent_option_is_ignored
      @master = FakeMaster.new(@path)
      Net::SSH.expects(:connect_directly).never

      start(forward_agent: true) do |ssh|
        refute ssh.options[:forward_agent]
        assert_equal "hello\n", ssh.exec!("true")
      end
      assert_equal ["exec"], @master.received_requests
      assert_match(/INFO -- : control_master: ignoring ForwardAgent, the ControlMaster's own ForwardAgent setting applies/, @log.string)
      refute_match(/WARN/, @log.string)
    end

    def test_forward_agent_from_ssh_config_is_ignored
      @master = FakeMaster.new(@path)
      config = File.join(@dir, 'config')
      File.write(config, "Host *\n  ForwardAgent yes\n")

      start(config: config) do |ssh|
        refute ssh.options[:forward_agent]
        ssh.exec!("true")
      end
      assert_equal ["exec"], @master.received_requests
      assert_includes @log.string, "ignoring ForwardAgent"
    end

    def test_keepalive_is_disabled
      @master = FakeMaster.new(@path)
      start(keepalive: true, keepalive_interval: 0.05) do |ssh|
        refute ssh.options[:keepalive]
        3.times do
          sleep 0.06
          ssh.process(0.01)
        end
        ssh.exec!("true")
      end
      refute_includes @master.received_types, Net::SSH::Connection::Constants::GLOBAL_REQUEST
      assert_includes @log.string, "keepalive is left to the ControlMaster"
    end

    def test_logs_explicit_master_owned_options_at_info
      @master = FakeMaster.new(@path)
      start(password: 'secret', verify_host_key: :always, port: 22, &:close)
      assert_match(/INFO -- : control_master: ignoring password, verify_host_key, the ControlMaster's own settings apply/, @log.string)
      refute_match(/WARN/, @log.string)
    end

    def test_sshkit_style_options_through_master
      @master = FakeMaster.new(@path)
      Net::SSH.expects(:connect_directly).never

      options = { forward_agent: true, keys: [File.join(@dir, 'id_ed25519')], keys_only: true,
                  known_hosts: Net::SSH::KnownHosts, password_prompt: Net::SSH::Prompt.default,
                  keepalive: true, keepalive_interval: 30 }
      start(options) { |ssh| assert_equal "hello\n", ssh.exec!("true") }
      assert_equal 1, @master.connections
      refute_match(/WARN/, @log.string)
    end

    def test_ssh_config_control_path_is_used
      @master = FakeMaster.new(File.join(@dir, 'alice@example.com:2222'))
      config = File.join(@dir, 'config')
      File.write(config, "Host example.com\n  Port 2222\n  ControlMaster auto\n  ControlPath #{@dir}/%r@%h:%p\n")
      Net::SSH.expects(:connect_directly).never

      Net::SSH.start('example.com', 'alice', config: config, logger: @logger, control_master: :auto, &:close)
      assert_equal 1, @master.connections
    end

    def test_ssh_config_control_master_alone_does_not_enable_it
      @master = FakeMaster.new(@path)
      config = File.join(@dir, 'config')
      File.write(config, "Host *\n  ControlMaster yes\n  ControlPath #{@path}\n")
      direct = expect_direct_connection
      Net::SSH::Multiplex::Client.expects(:new).never

      assert_equal direct, Net::SSH.start('example.com', 'alice', config: config, logger: @logger)
      assert_equal 0, @master.connections
    end

    def test_default_never_touches_the_socket
      @master = FakeMaster.new(@path)
      direct = expect_direct_connection
      Net::SSH::Multiplex::Client.expects(:new).never

      assert_equal direct, Net::SSH.start('example.com', 'alice', config: false, logger: @logger, control_path: @path)
      assert_equal 0, @master.connections
    end

    def test_control_master_false
      @master = FakeMaster.new(@path)
      direct = expect_direct_connection

      assert_equal direct, start(control_master: false)
      assert_equal 0, @master.connections
    end

    def test_invalid_control_master_value
      assert_raises(ArgumentError) { start(control_master: :yes) }
      assert_raises(ArgumentError) { start(control_master: :yes, forward_agent: true) }
    end

    def test_nil_control_options_raise
      error = assert_raises(ArgumentError) { start(control_master: nil) }
      assert_match(/control_master: false/, error.message)
      error = assert_raises(ArgumentError) { start(control_path: nil) }
      assert_match(/control_path: 'none'/, error.message)
    end

    def test_invalid_control_master_policy_raises
      error = assert_raises(ArgumentError) { start(control_master_policy: :paranoid) }
      assert_match(/control_master_policy must be one of :allow, :strict, :direct/, error.message)
    end

    def test_strict_policy_rejects_an_explicit_verifier_before_any_channel
      @master = FakeMaster.new(@path)
      Net::SSH.expects(:connect_directly).never

      error = assert_raises(Net::SSH::ControlMasterSecurityError) do
        start(control_master_policy: :strict, verify_host_key: :always)
      end
      assert_match(/refusing to reuse the ControlMaster/, error.message)
      assert_match(/verify_host_key/, error.message)
      assert_equal 1, @master.connections
      assert_empty @master.received_types
    end

    def test_strict_policy_rejects_an_explicit_algorithm_restriction
      @master = FakeMaster.new(@path)
      Net::SSH.expects(:connect_directly).never

      error = assert_raises(Net::SSH::ControlMasterSecurityError) do
        start(control_master_policy: :strict, encryption: 'aes256-gcm@openssh.com')
      end
      assert_match(/encryption/, error.message)
      assert_empty @master.received_types
    end

    def test_strict_policy_rejects_an_explicit_identity
      @master = FakeMaster.new(@path)
      error = assert_raises(Net::SSH::ControlMasterSecurityError) do
        start(control_master_policy: :strict, keys: [File.join(@dir, 'id_ed25519')])
      end
      assert_match(/keys/, error.message)
      assert_empty @master.received_types
    end

    def test_strict_policy_rejects_a_fixed_control_path
      @master = FakeMaster.new(@path)
      error = assert_raises(Net::SSH::ControlMasterSecurityError) do
        start(control_master_policy: :strict)
      end
      assert_match(/which host, port and user the master is connected to/, error.message)
      assert_empty @master.received_types
    end

    def test_strict_policy_allows_a_bound_path_with_layer_options
      @master = FakeMaster.new(File.join(@dir, 'cm-alice@example.com:22'))
      Net::SSH.expects(:connect_directly).never

      start(control_path: bound_path, control_master_policy: :strict, send_env: ['LANG']) do |ssh|
        assert_instance_of Net::SSH::Multiplex::ProxyTransport, ssh.transport
        assert_equal "hello\n", ssh.exec!("true")
      end
      assert_equal 1, @master.connections
    end

    def test_strict_policy_does_not_open_the_master_when_no_socket
      direct = expect_direct_connection
      assert_equal direct, start(control_master_policy: :strict, verify_host_key: :always)
      assert_equal 0, @master.connections if @master
    end

    def test_direct_policy_falls_back_to_a_fresh_connection
      @master = FakeMaster.new(@path)
      direct = expect_direct_connection

      assert_equal direct, start(control_master_policy: :direct, verify_host_key: :always)
      assert_equal 1, @master.connections
      assert_empty @master.received_types
      assert_match(/WARN.*bypassing the ControlMaster and connecting directly/, @log.string)
    end

    def test_direct_policy_uses_the_master_when_requirements_are_layer_guaranteed
      @master = FakeMaster.new(File.join(@dir, 'cm-alice@example.com:22'))
      Net::SSH.expects(:connect_directly).never

      start(control_path: bound_path, control_master_policy: :direct, send_env: ['LANG'], &:close)
      assert_equal 1, @master.connections
    end

    def test_allow_policy_keeps_reusing_the_master
      @master = FakeMaster.new(@path)
      Net::SSH.expects(:connect_directly).never

      start(verify_host_key: :always) do |ssh|
        assert_instance_of Net::SSH::Multiplex::ProxyTransport, ssh.transport
        assert_equal "hello\n", ssh.exec!("true")
      end
      assert_equal 1, @master.connections
      assert_match(/INFO.*reusing despite requirements/, @log.string)
    end

    def test_a_different_alias_through_a_bound_path_uses_its_own_master
      @master = FakeMaster.new(@path)
      other = FakeMaster.new(File.join(@dir, 'cm-bob@other.example:2222'))
      Net::SSH.expects(:connect_directly).never

      path = File.join(@dir, 'cm-%r@%h:%p')
      Net::SSH.start('other.example', 'bob', config: false, logger: @logger, port: 2222,
                                            control_master: :auto, control_path: path,
                                            control_master_policy: :strict, &:close)
      assert_equal 1, other.connections
      assert_equal 0, @master.connections
    ensure
      other&.stop
    end

    def test_ssh_config_verifier_is_not_a_strict_policy_conflict
      @master = FakeMaster.new(File.join(@dir, 'cm-alice@example.com:22'))
      Net::SSH.expects(:connect_directly).never
      config = File.join(@dir, 'config')
      File.write(config, "Host *\n  StrictHostKeyChecking yes\n")

      start(config: config, control_path: bound_path, control_master_policy: :strict, &:close)
      assert_equal 1, @master.connections
    end
  end
end
