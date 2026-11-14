require_relative '../../common'
require 'net/ssh/transport/kex/diffie_hellman_group1_sha1'
require 'net/ssh/transport/session'

# The connection must only be told a host key was verified after the verifier
# accepted it and the server proved it owns the key.
module Transport
  module Kex
    class TestHostKeyVerified < NetSSHTest
      include Net::SSH::Transport::Constants

      def setup
        @algorithms = OpenStruct.new(host_key: "ssh-rsa", host_key_format: "ssh-rsa") # rubocop:disable Style/OpenStructUse
        @connection = MockTransport.new
        @server_key = OpenSSL::PKey::RSA.new(512)
        @server_dh_pubkey = OpenSSL::BN.new(dh_512bits_bn, 10)
        @connection.instance_variable_set(:@verified, [])
        @connection.define_singleton_method(:host_key_verified!) do |key, fingerprint|
          @verified << [key, fingerprint]
        end
        @connection.define_singleton_method(:verified_calls) { @verified }
      end

      def test_host_key_verified_is_recorded_after_the_verifier_accepts
        verifier_called = false
        @connection.verifier do |data|
          verifier_called = true
          assert_empty @connection.verified_calls
          data[:key].to_blob == @server_key.to_blob
        end

        exchange!

        assert verifier_called
        assert_equal 1, @connection.verified_calls.length
        assert_equal @server_key.to_blob, @connection.verified_calls.first[0].to_blob
        assert_match(/\ASHA256:/, @connection.verified_calls.first[1])
      end

      def test_host_key_verified_is_not_recorded_when_the_verifier_refuses
        @connection.verifier { false }

        assert_raises(Net::SSH::Exception) { exchange! }
        assert_empty @connection.verified_calls
      end

      def test_host_key_verified_is_not_recorded_when_the_server_signature_is_wrong
        @connection.verifier { true }
        @wrong_signature = true

        assert_raises(Net::SSH::Exception) { exchange! }
        assert_empty @connection.verified_calls
      end

      def test_host_key_verified_is_not_recorded_when_the_key_exchange_fails_before_verifying
        @connection.verifier { raise Net::SSH::Exception, "verifier failed" }

        assert_raises(Net::SSH::Exception) { exchange! }
        assert_empty @connection.verified_calls
      end

      private

      def exchange!
        connection = @connection
        connection.expect do |t, packet|
          assert_equal KEXDH_INIT, packet.type
          signature = @wrong_signature ? "bad" : @server_key.ssh_do_sign(session_id)
          t.return(KEXDH_REPLY, :string, Net::SSH::Buffer.from(:key, @server_key).to_s, :bignum, @server_dh_pubkey,
                   :string, Net::SSH::Buffer.from(:string, "ssh-rsa", :string, signature))
          connection.expect do |t2, packet2|
            assert_equal NEWKEYS, packet2.type
            t2.return(NEWKEYS)
          end
        end

        dh.exchange_keys
      end

      def dh
        @dh ||= Net::SSH::Transport::Kex::DiffieHellmanGroup1SHA1.new(
          @algorithms, @connection,
          client_version_string: "client version string",
          server_version_string: "server version string",
          server_algorithm_packet: "server algorithm packet",
          client_algorithm_packet: "client algorithm packet",
          need_bytes: 20
        )
      end

      def session_id
        @session_id ||= begin
          buffer = Net::SSH::Buffer.from(:string, "client version string",
                                         :string, "server version string",
                                         :string, "client algorithm packet",
                                         :string, "server algorithm packet",
                                         :string, Net::SSH::Buffer.from(:key, @server_key),
                                         :bignum, dh.dh.pub_key,
                                         :bignum, @server_dh_pubkey,
                                         :bignum, OpenSSL::BN.new(dh.dh.compute_key(@server_dh_pubkey), 2))
          OpenSSL::Digest::SHA1.digest(buffer.to_s)
        end
      end
    end
  end
end
