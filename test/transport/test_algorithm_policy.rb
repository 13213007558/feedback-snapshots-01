require_relative '../common'
require 'logger'
require 'net/ssh/transport/algorithms'
require 'net/ssh/transport/algorithm_policy'
require 'net/ssh/config'

module Transport
  class TestAlgorithmPolicy < NetSSHTest
    include Net::SSH::Transport::Constants

    POLICY = {
      kex: %w[diffie-hellman-group-exchange-sha256 diffie-hellman-group14-sha256],
      host_key: %w[rsa-sha2-512 rsa-sha2-256],
      encryption: %w[aes256-ctr aes128-ctr],
      hmac: %w[hmac-sha2-256 hmac-sha2-512],
      combinations: [
        { kex: 'diffie-hellman-group-exchange-sha256', host_key: 'rsa-sha2-512',
          encryption: 'aes256-ctr', hmac: 'hmac-sha2-256' }
      ]
    }.freeze

    def test_policy_filters_composed_lists_in_kexinit
      algorithms(algorithm_policy: POLICY)
      transport.expect do |_t, buffer|
        assert_kexinit(buffer,
                       kex: 'diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256',
                       host_key: 'rsa-sha2-512,rsa-sha2-256',
                       encryption: 'aes256-ctr,aes128-ctr',
                       hmac: 'hmac-sha2-512,hmac-sha2-256')
        install_mock_key_exchange(buffer)
      end
      install_mock_algorithm_lookups
      algorithms.accept_kexinit(kexinit)

      assert_equal 'diffie-hellman-group-exchange-sha256', algorithms.kex
      assert_equal 'rsa-sha2-512', algorithms.host_key
      assert_equal 'aes256-ctr', algorithms.encryption_client
      assert_equal 'hmac-sha2-256', algorithms.hmac_client
    end

    def test_compat_options_cannot_readd_weak_algorithms
      algos = algorithms(
        append_all_supported_algorithms: true,
        encryption: %w[+3des-cbc],
        hmac: %w[+hmac-md5],
        algorithm_policy: POLICY
      )
      assert_equal %w[diffie-hellman-group-exchange-sha256 diffie-hellman-group14-sha256], algos[:kex]
      assert_equal %w[aes256-ctr aes128-ctr], algos[:encryption]
      assert_equal %w[hmac-sha2-512 hmac-sha2-256], algos[:hmac]
      refute_includes algos[:encryption], '3des-cbc'
      refute_includes algos[:hmac], 'hmac-md5'
    end

    def test_config_file_defaults_are_filtered_by_policy
      config = Net::SSH::Config.translate(
        'kexalgorithms' => '+diffie-hellman-group14-sha1',
        'ciphers' => 'aes256-ctr,3des-cbc',
        'macs' => 'hmac-sha2-256,hmac-md5'
      )
      algos = algorithms(config.merge(algorithm_policy: POLICY))
      assert_equal %w[diffie-hellman-group-exchange-sha256 diffie-hellman-group14-sha256], algos[:kex]
      assert_equal %w[aes256-ctr], algos[:encryption]
      assert_equal %w[hmac-sha2-256], algos[:hmac]
    end

    def test_explicit_lists_still_take_precedence_over_defaults
      algos = algorithms(kex: %w[diffie-hellman-group14-sha256], algorithm_policy: POLICY)
      assert_equal %w[diffie-hellman-group14-sha256], algos[:kex]
    end

    def test_policy_without_intersection_fails_before_any_packet_is_sent
      error = assert_raises(Net::SSH::Exception) do
        algorithms(algorithm_policy: POLICY.merge(kex: %w[diffie-hellman-group1-sha1]))
      end
      assert_match(/algorithm policy leaves no kex algorithm/, error.message)
      assert_match(/diffie-hellman-group1-sha1/, error.message)
    end

    def test_each_algorithm_allowed_but_combination_rejected
      policy = POLICY.merge(combinations: [
                              { kex: 'diffie-hellman-group14-sha256', host_key: 'rsa-sha2-512',
                                encryption: 'aes256-ctr', hmac: 'hmac-sha2-256' }
                            ])
      algorithms(algorithm_policy: policy)
      transport.expect { |_t, buffer| assert_kexinit(buffer) }
      error = assert_raises(Net::SSH::Exception) { algorithms.accept_kexinit(kexinit) }
      assert_match(/algorithm policy rejected/, error.message)
      assert_match(/kex=diffie-hellman-group-exchange-sha256/, error.message)
      assert_match(/no combination rule accepts/, error.message)
      assert_match(/mismatches kex/, error.message)
      refute algorithms.initialized?
    end

    def test_no_intersection_with_server_list_fails_during_negotiation
      algorithms(algorithm_policy: POLICY)
      kexinit kex: 'diffie-hellman-group1-sha1'
      transport.expect { |_t, buffer| assert_kexinit(buffer) }
      error = assert_raises(Net::SSH::Exception) { algorithms.accept_kexinit(kexinit) }
      assert_match(/could not settle on kex algorithm/, error.message)
    end

    def test_valid_negotiation_is_accepted_and_explained_in_log
      string_io = StringIO.new
      logger = Logger.new(string_io)
      logger.level = Logger::INFO

      algorithms({ algorithm_policy: POLICY }, logger: logger)
      transport.expect do |_t, buffer|
        assert_kexinit(buffer)
        install_mock_key_exchange(buffer, logger: logger)
      end
      install_mock_algorithm_lookups
      algorithms.accept_kexinit(kexinit)

      assert algorithms.initialized?
      log = string_io.string
      assert_match(/algorithm policy: accepted/, log)
      assert_match(/kex=diffie-hellman-group-exchange-sha256/, log)
      assert_match(/host_key=rsa-sha2-512/, log)
      assert_match(/matched combination rule/, log)
      refute_includes log, shared_secret.to_i.to_s
      refute_includes log, session_id
    end

    def test_rekey_uses_same_policy_constraints
      algorithms(algorithm_policy: POLICY)
      transport.expect do |_t, buffer|
        assert_kexinit(buffer)
        install_mock_key_exchange(buffer)
      end
      install_mock_algorithm_lookups
      algorithms.accept_kexinit(kexinit)
      assert algorithms.initialized?

      transport.expect do |_t, buffer|
        assert_kexinit(buffer,
                       rekey: true,
                       kex: 'diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256',
                       host_key: 'rsa-sha2-512,rsa-sha2-256',
                       encryption: 'aes256-ctr,aes128-ctr',
                       hmac: 'hmac-sha2-512,hmac-sha2-256')
      end
      algorithms.rekey!
      assert algorithms.pending?

      weak_server_kexinit = P(:byte, KEXINIT,
                              :long, 1, :long, 2, :long, 3, :long, 4,
                              :string, 'diffie-hellman-group1-sha1',
                              :string, 'rsa-sha2-512',
                              :string, 'aes256-ctr', :string, 'aes256-ctr',
                              :string, 'hmac-sha2-256', :string, 'hmac-sha2-256',
                              :string, 'none', :string, 'none',
                              :string, '', :string, '',
                              :bool, false)
      assert_raises(Net::SSH::Exception) { algorithms.accept_kexinit(weak_server_kexinit) }
    end

    def test_rekey_rejects_combination_that_initial_exchange_would_reject
      policy = POLICY.merge(combinations: [
                              { kex: 'diffie-hellman-group14-sha256', host_key: 'rsa-sha2-512',
                                encryption: 'aes256-ctr', hmac: 'hmac-sha2-256' }
                            ])
      algorithms(algorithm_policy: policy)
      transport.expect { |_t, buffer| assert_kexinit(buffer) }
      assert_raises(Net::SSH::Exception) { algorithms.accept_kexinit(kexinit) }
    end

    def test_without_policy_compat_options_still_append_weak_algorithms
      algos = algorithms(append_all_supported_algorithms: true)
      assert_includes algos[:kex], 'diffie-hellman-group1-sha1'
      assert_includes algos[:encryption], '3des-cbc'
      assert_includes algos[:hmac], 'hmac-md5'
    end

    def test_policy_object_can_be_passed_directly
      policy = Net::SSH::Transport::AlgorithmPolicy.new(POLICY)
      algos = algorithms(algorithm_policy: policy)
      assert_equal policy, algos.algorithm_policy
      assert_equal %w[aes256-ctr aes128-ctr], algos[:encryption]
    end

    def test_invalid_policy_definitions_raise_argument_error
      assert_raises(ArgumentError) { algorithms(algorithm_policy: 'kex') }
      assert_raises(ArgumentError) { algorithms(algorithm_policy: { bogus: %w[x] }) }
      assert_raises(ArgumentError) { algorithms(algorithm_policy: { kex: [] }) }
      assert_raises(ArgumentError) { algorithms(algorithm_policy: { combinations: [{}] }) }
      assert_raises(ArgumentError) { algorithms(algorithm_policy: { combinations: [{ cipher: 'aes256-ctr' }] }) }
    end

    def test_evaluate_reports_each_mismatched_category
      policy = Net::SSH::Transport::AlgorithmPolicy.new(
        combinations: [
          { kex: 'a', host_key: 'b', encryption: 'c', hmac: 'd' },
          { kex: 'x', host_key: 'y', encryption: 'z', hmac: 'w' }
        ]
      )
      accepted, explanation = policy.evaluate(
        kex: 'a', host_key: 'y',
        encryption_client: 'c', encryption_server: 'c',
        hmac_client: 'w', hmac_server: 'w'
      )
      refute accepted
      assert_match(/mismatches host_key, hmac/, explanation)
      assert_match(/mismatches kex, encryption/, explanation)
    end

    def test_evaluate_accepts_when_both_directions_match_rule
      policy = Net::SSH::Transport::AlgorithmPolicy.new(POLICY)
      accepted, explanation = policy.evaluate(
        kex: 'diffie-hellman-group-exchange-sha256', host_key: 'rsa-sha2-512',
        encryption_client: 'aes256-ctr', encryption_server: 'aes256-ctr',
        hmac_client: 'hmac-sha2-256', hmac_server: 'hmac-sha2-256'
      )
      assert accepted
      assert_match(/accepted/, explanation)
    end

    private

    def install_mock_key_exchange(buffer, logger: nil)
      kex_class = Net::SSH::Transport::Kex::DiffieHellmanGroupExchangeSHA256
      Net::SSH::Transport::Kex::MAP.each_value do |klass|
        next if klass == kex_class

        klass.expects(:new).never
      end

      kex_class.expects(:new)
               .with(algorithms, transport,
                     client_version_string: Net::SSH::Transport::ServerVersion::PROTO_VERSION,
                     server_version_string: transport.server_version.version,
                     server_algorithm_packet: kexinit.to_s,
                     client_algorithm_packet: buffer.to_s,
                     need_bytes: 32,
                     minimum_dh_bits: nil,
                     logger: logger)
               .returns(stub("kex", exchange_keys: { shared_secret: shared_secret, session_id: session_id, hashing_algorithm: hashing_algorithm }))
    end

    def install_mock_algorithm_lookups
      params = { shared: shared_secret.to_ssh, hash: session_id, digester: hashing_algorithm }

      cipher_client = OpenStruct.new(implicit_map?: false, id: :client_cipher) # rubocop:disable Style/OpenStructUse
      server_cipher = OpenStruct.new(implicit_map?: false, id: :server_cipher) # rubocop:disable Style/OpenStructUse
      Net::SSH::Transport::CipherFactory.expects(:get)
                                        .with("aes256-ctr", params.merge(iv: key("A"), key: key("C"), encrypt: true))
                                        .returns(cipher_client)
      Net::SSH::Transport::CipherFactory.expects(:get)
                                        .with("aes256-ctr", params.merge(iv: key("B"), key: key("D"), decrypt: true))
                                        .returns(server_cipher)

      Net::SSH::Transport::HMAC.expects(:get).with("hmac-sha2-256", key("E"), params).returns(:client_hmac)
      Net::SSH::Transport::HMAC.expects(:get).with("hmac-sha2-256", key("F"), params).returns(:server_hmac)
    end

    def shared_secret
      @shared_secret ||= dh_512bits_bn
    end

    def session_id
      @session_id ||= "this is the session id"
    end

    def hashing_algorithm
      OpenSSL::Digest::SHA1
    end

    def key(salt)
      hashing_algorithm.digest(shared_secret.to_ssh + session_id + salt + session_id)
    end

    def kexinit(options = {})
      @kexinit ||= P(:byte, KEXINIT,
                     :long, rand(0xFFFFFFFF), :long, rand(0xFFFFFFFF), :long, rand(0xFFFFFFFF), :long, rand(0xFFFFFFFF),
                     :string, options[:kex] || "diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
                     :string, options[:host_key] || "rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-dss",
                     :string, options[:encryption_client] || "aes256-ctr,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,rijndael-cbc@lysator.liu.se,idea-cbc",
                     :string, options[:encryption_server] || "aes256-ctr,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,rijndael-cbc@lysator.liu.se,idea-cbc",
                     :string, options[:hmac_client] || "hmac-sha2-256,hmac-sha1,hmac-md5,hmac-sha1-96,hmac-md5-96",
                     :string, options[:hmac_server] || "hmac-sha2-256,hmac-sha1,hmac-md5,hmac-sha1-96,hmac-md5-96",
                     :string, options[:compression_client] || "none,zlib@openssh.com,zlib",
                     :string, options[:compression_server] || "none,zlib@openssh.com,zlib",
                     :string, options[:language_client] || "",
                     :string, options[:language_server] || "",
                     :bool, options[:first_kex_follows])
    end

    def assert_kexinit(buffer, options = {})
      assert_equal KEXINIT, buffer.type
      assert_equal 16, buffer.read(16).length
      kex = options[:kex] || 'diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256'
      kex += ',ext-info-c' unless options[:rekey]
      assert_equal kex, buffer.read_string
      assert_equal options[:host_key] || 'rsa-sha2-512,rsa-sha2-256', buffer.read_string
      assert_equal options[:encryption] || 'aes256-ctr,aes128-ctr', buffer.read_string
      assert_equal options[:encryption] || 'aes256-ctr,aes128-ctr', buffer.read_string
      assert_equal options[:hmac] || 'hmac-sha2-512,hmac-sha2-256', buffer.read_string
      assert_equal options[:hmac] || 'hmac-sha2-512,hmac-sha2-256', buffer.read_string
      assert_equal 'none,zlib@openssh.com,zlib', buffer.read_string
      assert_equal 'none,zlib@openssh.com,zlib', buffer.read_string
      assert_equal '', buffer.read_string
      assert_equal '', buffer.read_string
      assert_equal false, buffer.read_bool
    end

    def algorithms(algorithms_options = {}, transport_options = {})
      @algorithms ||= Net::SSH::Transport::Algorithms.new(
        transport(transport_options),
        algorithms_options
      )
    end

    def transport(transport_options = {})
      @transport ||= MockTransport.new(
        {
          user_known_hosts_file: '/dev/null',
          global_known_hosts_file: '/dev/null'
        }.merge(transport_options)
      )
    end
  end
end
