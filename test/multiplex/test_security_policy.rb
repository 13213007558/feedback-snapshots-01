require_relative '../common'
require 'net/ssh'
require 'net/ssh/multiplex/security_policy'

module NetSSH
  class TestSecurityPolicy < NetSSHTest
    def setup
      @log = StringIO.new
      @logger = Logger.new(@log)
      @logger.level = Logger::DEBUG
    end

    def policy(control_path: '/tmp/ssh-%r@%h:%p', explicit: nil, policy: :allow, extra: {})
      options = { control_path: control_path, control_master_policy: policy, logger: @logger }.merge(extra)
      Net::SSH::Multiplex::SecurityPolicy.new(options, explicit: explicit || [], logger: @logger)
    end

    def test_target_bound_recognizes_full_tokens
      bound = ['/tmp/%C', '/tmp/%r@%h:%p', '/tmp/%n-%p-%r', '/tmp/%%/%r@%h:%p', '/tmp/x%Cy']
      bound.each { |path| assert Net::SSH::Multiplex::SecurityPolicy.target_bound?(path), path }
    end

    def test_target_bound_rejects_fixed_and_partial_paths
      unbound = ['/tmp/control', '/tmp/%r@%h', '/tmp/%h:%p', '/tmp/%p-%r', '/tmp/%%h']
      unbound.each { |path| refute Net::SSH::Multiplex::SecurityPolicy.target_bound?(path), path }
    end

    def test_no_conflicts_on_a_bound_path_without_master_owned_options
      assert_empty policy(explicit: %i[send_env properties timeout preopen_channels keepalive forward_agent]).violations
      assert_equal :reuse, policy.decide
    end

    def test_master_owned_explicit_option_is_a_conflict
      subject = policy(explicit: %i[verify_host_key password])
      assert_equal %i[verify_host_key password], subject.master_owned_conflicts
      assert_match(/verify_host_key.*password/, subject.violations.join)
    end

    def test_keepalive_and_forward_agent_are_not_conflicts
      assert_empty policy(explicit: %i[keepalive forward_agent]).violations
      assert_equal :reuse, policy(explicit: %i[keepalive forward_agent], policy: :strict).decide
    end

    def test_options_from_ssh_config_are_not_conflicts
      assert_empty policy(explicit: [], extra: { verify_host_key: :always, password: 'secret' }).violations
    end

    def test_fixed_control_path_is_an_unverifiable_target
      violations = policy(control_path: '/tmp/fixed-socket').violations
      assert_equal 1, violations.size
      assert_match(%r{no %C or %h/%n, %p and %r tokens}, violations.join)
    end

    def test_allow_policy_reuses_and_logs
      assert_equal :reuse, policy(control_path: '/tmp/fixed', explicit: [:keys]).decide
      assert_match(/INFO.*reusing despite requirements/, @log.string)
    end

    def test_strict_policy_raises_on_conflict
      error = assert_raises(Net::SSH::ControlMasterSecurityError) do
        policy(explicit: [:verify_host_key], policy: :strict).decide
      end
      assert_match(/refusing to reuse the ControlMaster/, error.message)
      assert_match(/verify_host_key/, error.message)
    end

    def test_strict_policy_raises_on_unverifiable_target
      error = assert_raises(Net::SSH::ControlMasterSecurityError) do
        policy(control_path: '/tmp/fixed', policy: :strict).decide
      end
      assert_match(/which host, port and user the master is connected to/, error.message)
    end

    def test_strict_policy_allows_a_safe_reuse
      assert_equal :reuse, policy(policy: :strict, explicit: [:send_env]).decide
    end

    def test_direct_policy_bypasses_the_master
      assert_equal :direct, policy(control_path: '/tmp/fixed', explicit: [:kex], policy: :direct).decide
      assert_match(/WARN.*bypassing the ControlMaster and connecting directly/, @log.string)
    end

    def test_invalid_policy_value_is_rejected
      error = assert_raises(ArgumentError) do
        Net::SSH::Multiplex.validate_options!(control_master_policy: :paranoid)
      end
      assert_match(/control_master_policy must be one of :allow, :strict, :direct/, error.message)
    end

    def test_valid_policy_values_pass_validation
      Net::SSH::Multiplex::SecurityPolicy::POLICIES.each do |value|
        Net::SSH::Multiplex.validate_options!(control_master_policy: value)
      end
    end
  end
end
