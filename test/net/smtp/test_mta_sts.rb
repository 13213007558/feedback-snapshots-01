# frozen_string_literal: true

require 'net/smtp'
require 'socket'
require 'test/unit'

unless defined?(OpenSSL::VERSION)
  warn "#{__FILE__}: openssl library not loaded; skipping"
  return
end

module Net
  class TestMTASTS < Test::Unit::TestCase
    FIXTURES = File.expand_path("../fixtures", __dir__)
    CA_FILE = File.join(FIXTURES, "cacert.pem")
    SERVER_KEY = File.join(FIXTURES, "server.key")
    SERVER_CERT = File.join(FIXTURES, "server.crt")

    # The fixture certificate has CN=localhost, so SNI/identity checks must
    # use this name even though the MX policy name is mail.example.com.
    CERTIFICATE_HOSTNAME = "localhost"
    MX_HOSTNAME = "mail.example.com"
    POLICY_DOMAIN = "example.com"

    # A policy whose MX covers the fixture certificate identity. Used by
    # delivery-path tests so that identity verification succeeds while
    # other policy checks remain under test.
    LOCAL_POLICY_MX = ["localhost"]

    # Transport stand-in: a Net::SMTP whose TCP socket is one end of a
    # UNIXSocket pair. The peer thread implements a minimal SMTP server.
    class FakeTransportSMTP < SMTP
      attr_reader :connection_count

      def initialize(socket, **kw)
        @fake_sockets = socket.is_a?(Array) ? socket.dup : [socket]
        @connection_count = 0
        super(kw.delete(:address) || CERTIFICATE_HOSTNAME, nil, **kw)
      end

      def tcp_socket(*)
        @connection_count += 1
        socket = @fake_sockets.shift
        raise IOError, "no transport stand-in left" if socket.nil?
        socket
      end
    end

    # A tiny SMTP server speaking over one side of a socket pair.
    class FakePeer
      attr_reader :commands, :body, :starttls_attempted

      def initialize(socket, starttls: false, auth: nil, certificate: :valid,
                     fail_handshake: false, refuse_starttls: false)
        @socket = socket
        @starttls = starttls
        @auth = auth
        @certificate = certificate
        @fail_handshake = fail_handshake
        @refuse_starttls = refuse_starttls
        @commands = []
        @body = +""
        @starttls_attempted = false
        @thread = Thread.new do
          begin
            run
          rescue Errno::EPIPE, Errno::ECONNRESET, Errno::ECONNABORTED, IOError, NoMethodError, OpenSSL::SSL::SSLError
            nil
          end
        end
      end

      def run
        @socket.puts "220 ready\r\n"
        while (line = @socket.gets)
          command = line.chomp
          @commands << command
          case command
          when /\AEHLO /
            ehlo
          when "STARTTLS"
            starttls
          when /\AAUTH /
            auth(command.split(" ", 2)[1])
          when /\AMAIL FROM:/
            @socket.puts "250 2.1.0 Ok\r\n"
          when /\ARCPT TO:/
            @socket.puts "250 2.1.0 Ok\r\n"
          when "DATA"
            data
          when "QUIT"
            @socket.puts "221 2.0.0 Bye\r\n"
            @socket.close
            break
          else
            @socket.puts "502 5.5.2 Error: command not recognized\r\n"
          end
        end
      rescue Errno::ECONNRESET, Errno::ECONNABORTED, IOError
        nil
      end

      def join(limit = 5)
        @thread.join(limit)
      end

      def alive?
        @thread.alive?
      end

      private

      def ehlo
        lines = ["250-fakeserver"]
        lines << "250-STARTTLS" if @starttls
        lines << "250-AUTH PLAIN" if @auth
        lines << "250 8BITMIME"
        @socket.puts lines.join("\r\n") + "\r\n"
      end

      def starttls
        @starttls_attempted = true
        if @refuse_starttls
          @socket.puts "454 4.7.0 TLS not available due to temporary reason\r\n"
          return
        end
        @socket.puts "220 2.0.0 Ready to start TLS\r\n"
        if @fail_handshake
          @socket.close
          return
        end
        @socket = wrap_server_socket
      end

      def wrap_server_socket
        ctx = OpenSSL::SSL::SSLContext.new
        ctx.cert = OpenSSL::X509::Certificate.new(File.read(SERVER_CERT))
        ctx.key = OpenSSL::PKey::RSA.new(File.read(SERVER_KEY))
        ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
        ssl = OpenSSL::SSL::SSLSocket.new(@socket, ctx)
        ssl.sync_close = true
        ssl.accept
        ssl
      rescue OpenSSL::SSL::SSLError, SystemCallError
        nil
      end

      def auth(argument)
        if argument == "PLAIN AGFjY291bnQAcGFzc3dvcmQ="
          @socket.puts "235 2.7.0 Authentication successful\r\n"
        else
          @socket.puts "535 5.7.8 Error: authentication failed\r\n"
        end
      end

      def data
        @socket.puts "354 End data with <CR><LF>.<CR><LF>\r\n"
        while (line = @socket.gets)
          break if line.chomp == "."
          @body << line
        end
        @socket.puts "250 2.0.0 Ok: queued\r\n"
      end
    end

    def setup
      @clients = []
      @peers = []
    end

    def teardown
      @clients.each { |socket| socket.close rescue nil }
      @peers.each { |peer| peer.join(1) }
    end

    private

    def policy(mode: :enforce, mx: LOCAL_POLICY_MX, max_age: 3600, fetched_at: Time.now,
               domain: POLICY_DOMAIN, expires_at: nil)
      SMTP::MTASTSPolicy.new(
        domain: domain, mode: mode, mx: mx, max_age: max_age,
        fetched_at: fetched_at, expires_at: expires_at
      )
    end

    def start_peer(**kw)
      client, server = UNIXSocket.pair
      @clients << client
      peer = FakePeer.new(server, **kw)
      @peers << peer
      [client, peer]
    end

    # Start +count+ independent transport stand-ins (one per connection).
    def start_peers(count, **kw)
      clients = []
      peers = []
      count.times do
        client, peer = start_peer(**kw)
        clients << client
        peers << peer
      end
      [clients, peers]
    end

    def smtp_for(client, policy: nil, starttls: :auto, **kw)
      FakeTransportSMTP.new(
        client,
        address: CERTIFICATE_HOSTNAME,
        starttls: starttls,
        tls_verify: true,
        tls_hostname: CERTIFICATE_HOSTNAME,
        ssl_context_params: { ca_file: CA_FILE },
        mta_sts_policy: policy,
        mta_sts_domain: POLICY_DOMAIN,
        mta_sts_mx_hostname: CERTIFICATE_HOSTNAME,
        **kw
      )
    end

    public

    def test_policy_parses_structured_values
      parsed = SMTP::MTASTSPolicy.parse(<<~POLICY, domain: "example.com", fetched_at: Time.now)
        version: STSv1
        mode: enforce
        mx: mail.example.com
        mx: *.example.net
        max_age: 604800
      POLICY

      assert_equal "example.com", parsed.domain
      assert_equal :enforce, parsed.mode
      assert_equal ["mail.example.com", "*.example.net"], parsed.mx
      assert_equal 604800, parsed.max_age
      assert_in_delta parsed.fetched_at + 604800, parsed.expires_at, 1
      assert_predicate parsed, :active?
    end

    def test_policy_accepts_hash_entry_point
      smtp = SMTP.new("mx.example.com", mta_sts_policy: {
        "domain" => "example.com", "mode" => "enforce",
        "mx" => ["mx.example.com"], "max_age" => "600"
      }, mta_sts_domain: "example.com")

      assert_equal :enforce, smtp.mta_sts_policy.mode
      assert_equal ["mx.example.com"], smtp.mta_sts_policy.mx
    end

    def test_policy_rejects_invalid_mode
      error = assert_raise(ArgumentError) do
        policy(mode: :bogus)
      end
      assert_match(/invalid MTA-STS policy mode/, error.message)
    end

    def test_policy_rejects_zero_max_age
      assert_raise(ArgumentError) { policy(max_age: -1) }
      assert_raise(ArgumentError) { policy(max_age: SMTP::MTASTSPolicy::MAX_MAX_AGE + 1) }
    end

    def test_mx_pattern_matching
      matcher = SMTP::MTASTSPolicy
      assert_true matcher.mx_pattern_match?("mail.example.com", "mail.example.com")
      assert_true matcher.mx_pattern_match?("MAIL.EXAMPLE.COM", "mail.example.com")
      assert_true matcher.mx_pattern_match?("*.example.com", "mail.example.com")
      assert_false matcher.mx_pattern_match?("*.example.com", "example.com")
      assert_false matcher.mx_pattern_match?("*.example.com", "foo.bar.example.com")
      assert_false matcher.mx_pattern_match?("mail.example.com", "mail.example.com.evil.test")
      assert_false matcher.mx_pattern_match?("mail.example.com", "mail.example.co")
      assert_false matcher.mx_pattern_match?("*.example.com", "evilexample.com")
    end

    def test_enforce_connects_and_sends_when_policy_matches
      client, peer = start_peer(starttls: true)
      smtp = smtp_for(client, policy: policy)
      smtp.start(user: "account", secret: "password", authtype: :plain)
      assert_predicate smtp, :mta_sts_enforced?
      smtp.send_message("Subject: test\r\n\r\nbody\r\n", "sender@example.com", "rcpt@example.com")
      smtp.finish

      assert_true peer.starttls_attempted
      assert_true peer.commands.include?("AUTH PLAIN AGFjY291bnQAcGFzc3dvcmQ=")
      assert_true peer.commands.any? { |c| c.start_with?("MAIL FROM:") }
      assert_match(/body/, peer.body)
    end

    def test_enforce_overrides_starttls_auto_when_server_cannot_starttls
      client, peer = start_peer(starttls: false)
      smtp = smtp_for(client, policy: policy, starttls: :auto)
      error = assert_raise(SMTPMTASTSPolicyError) { smtp.start }
      assert_equal :starttls_unsupported, error.reason
      peer.join

      assert_false peer.commands.any? { |c| c.start_with?("AUTH ") }
      assert_false peer.commands.any? { |c| c.start_with?("MAIL FROM:") }
      assert_false peer.commands.include?("DATA")
      assert_equal "", peer.body
    end

    def test_enforce_overrides_starttls_false
      client, peer = start_peer(starttls: true)
      smtp = smtp_for(client, policy: policy, starttls: false)
      smtp.start
      assert_true peer.starttls_attempted
      smtp.finish
    end

    def test_enforce_refuses_plaintext_when_server_refuses_starttls
      client, peer = start_peer(starttls: true, refuse_starttls: true)
      smtp = smtp_for(client, policy: policy)
      error = assert_raise(SMTPMTASTSPolicyError) { smtp.start(user: "account", secret: "password", authtype: :plain) }
      assert_equal :starttls_refused, error.reason
      peer.join

      assert_false peer.commands.any? { |c| c.start_with?("AUTH ") }
      assert_false peer.commands.any? { |c| c.start_with?("MAIL FROM:") }
      assert_equal "", peer.body
    end

    def test_enforce_refuses_when_certificate_hostname_does_not_match_selected_mx
      client, peer = start_peer(starttls: true)
      # The peer presents CN=localhost; the policy allows and the selected MX
      # is mail.example.com, so identity verification must fail.
      smtp = smtp_for(
        client,
        policy: policy(mx: [MX_HOSTNAME]),
        mta_sts_mx_hostname: MX_HOSTNAME
      )
      error = assert_raise(OpenSSL::SSL::SSLError) { smtp.start(user: "account", secret: "password", authtype: :plain) }
      assert_match(/certificate verify failed|hostname mismatch/, error.message)
      assert_predicate smtp.mta_sts_failures, :empty?
      peer.join

      assert_false peer.commands.any? { |c| c.start_with?("AUTH ") }
      assert_false peer.commands.any? { |c| c.start_with?("MAIL FROM:") }
      assert_equal "", peer.body
    end

    def test_handshake_failure_never_sends_auth_or_envelope
      client, peer = start_peer(starttls: true)
      # No trusted CA: the TLS handshake must fail before any SMTP command
      # that could leak credentials or the envelope.
      smtp = smtp_for(client, policy: policy, ssl_context_params: {})
      assert_raise(OpenSSL::SSL::SSLError) do
        smtp.start(user: "account", secret: "password", authtype: :plain)
      end
      peer.join

      assert_false peer.commands.any? { |c| c.start_with?("AUTH ") }
      assert_false peer.commands.any? { |c| c.start_with?("MAIL FROM:") }
      assert_false peer.commands.include?("DATA")
      assert_equal "", peer.body
    end

    def test_enforce_rejects_mx_outside_policy_at_connect
      client, _peer = start_peer(starttls: true)
      smtp = smtp_for(client, policy: policy(mx: ["*.example.net"]))
      error = assert_raise(SMTPMTASTSPolicyError) { smtp.start }
      assert_equal :mx_mismatch, error.reason
    end

    def test_enforce_rejects_similar_suffix_mx
      client, _peer = start_peer(starttls: true)
      smtp = smtp_for(
        client,
        policy: policy(mx: ["*.example.com"]),
        mta_sts_mx_hostname: "mail.example.com.evil.test"
      )
      error = assert_raise(SMTPMTASTSPolicyError) { smtp.start }
      assert_equal :mx_mismatch, error.reason
    end

    def test_enforce_rejects_policy_for_different_recipient_domain
      client, _peer = start_peer(starttls: true)
      smtp = smtp_for(client, policy: policy(domain: "other.example"))
      error = assert_raise(SMTPMTASTSPolicyError) { smtp.start }
      assert_equal :domain_mismatch, error.reason
    end

    def test_expired_policy_is_not_applied
      client, peer = start_peer(starttls: false)
      expired = policy(fetched_at: Time.now - 7200, max_age: 3600)
      smtp = smtp_for(client, policy: expired, starttls: :auto)

      assert_nil smtp.send(:resolve_mta_sts_policy)
      smtp.start
      refute_predicate smtp, :mta_sts_enforced?
      assert_false peer.starttls_attempted
      smtp.finish
    end

    def test_expired_policy_reports_expiration
      client, _peer = start_peer(starttls: false)
      reported = []
      expired = policy(fetched_at: Time.now - 7200, max_age: 3600)
      smtp = smtp_for(client, policy: expired, mta_sts_reporter: ->(reason, details) { reported << [reason, details] })

      smtp.start
      assert_nil smtp.mta_sts_applied_policy
      assert_equal [[:policy_expired, { :domain => POLICY_DOMAIN, :expires_at => expired.expires_at }]], reported
      smtp.finish
    end

    def test_none_mode_is_treated_as_no_policy
      client, peer = start_peer(starttls: false)
      smtp = smtp_for(client, policy: policy(mode: :none, mx: []), starttls: :auto)
      smtp.start
      assert_nil smtp.mta_sts_applied_policy
      assert_false peer.starttls_attempted
      smtp.finish
    end

    def test_missing_policy_leaves_starttls_auto_unchanged
      client, peer = start_peer(starttls: false)
      smtp = smtp_for(client, policy: nil, starttls: :auto)
      smtp.start
      assert_nil smtp.mta_sts_applied_policy
      assert_false peer.starttls_attempted
      smtp.finish

      client, peer = start_peer(starttls: true)
      smtp = smtp_for(client, policy: nil, starttls: :auto)
      smtp.start
      assert_true peer.starttls_attempted
      smtp.finish
    end

    def test_testing_mode_allows_delivery_when_starttls_unsupported_and_reports
      client, peer = start_peer(starttls: false)
      reported = []
      smtp = smtp_for(
        client,
        policy: policy(mode: :testing),
        starttls: :auto,
        mta_sts_reporter: ->(reason, details) { reported << reason }
      )
      smtp.start(user: "account", secret: "password", authtype: :plain)
      smtp.send_message("Subject: test\r\n\r\nbody\r\n", "sender@example.com", "rcpt@example.com")
      smtp.finish

      assert_true reported.include?(:starttls_unsupported)
      assert_true peer.commands.include?("AUTH PLAIN AGFjY291bnQAcGFzc3dvcmQ=")
      assert_match(/body/, peer.body)
      refute_predicate smtp, :mta_sts_enforced?
    end

    def test_testing_mode_reports_mx_mismatch_but_proceeds
      client, peer = start_peer(starttls: false)
      reported = []
      smtp = smtp_for(
        client,
        policy: policy(mode: :testing, mx: ["*.example.net"]),
        starttls: :auto,
        mta_sts_reporter: ->(reason, _details) { reported << reason }
      )

      assert_nil smtp.send(:resolve_mta_sts_policy)
      assert_equal [:mx_mismatch], reported

      smtp.start
      smtp.send_message("Subject: test\r\n\r\nbody\r\n", "sender@example.com", "rcpt@example.com")
      smtp.finish
      assert_match(/body/, peer.body)
    end

    def test_testing_mode_does_not_downgrade_starttls_always
      client, peer = start_peer(starttls: true)
      smtp = smtp_for(client, policy: policy(mode: :testing), starttls: :always)
      smtp.start
      assert_true peer.starttls_attempted
      smtp.finish
    end

    def test_testing_mode_reports_certificate_failure_and_reconnects_plaintext
      clients, peers = start_peers(2, starttls: true)
      reported = []
      smtp = smtp_for(
        clients,
        policy: policy(mode: :testing),
        starttls: :auto,
        ssl_context_params: {},
        mta_sts_reporter: ->(reason, _details) { reported << reason }
      )

      smtp.start(user: "account", secret: "password", authtype: :plain)
      smtp.send_message("Subject: test\r\n\r\nbody\r\n", "sender@example.com", "rcpt@example.com")
      smtp.finish

      assert_equal 2, smtp.connection_count
      assert_true reported.include?(:tls_failure)
      assert_true peers[1].commands.include?("AUTH PLAIN AGFjY291bnQAcGFzc3dvcmQ=")
      assert_match(/body/, peers[1].body)
      refute_predicate smtp, :mta_sts_enforced?
    end

    def test_testing_mode_keeps_starttls_always_on_certificate_failure
      client, peer = start_peer(starttls: true)
      smtp = smtp_for(client, policy: policy(mode: :testing), starttls: :always,
                      ssl_context_params: {})
      # With an untrusted CA the handshake fails; starttls: :always must not
      # silently fall back to plaintext even in testing mode.
      assert_raise(OpenSSL::SSL::SSLError) do
        smtp.start(user: "account", secret: "password", authtype: :plain)
      end
      peer.join
      assert_false peer.commands.any? { |c| c.start_with?("AUTH ") }
      assert_false peer.commands.any? { |c| c.start_with?("MAIL FROM:") }
    end

    def test_testing_mode_reports_refused_starttls
      client, peer = start_peer(starttls: true, refuse_starttls: true)
      reported = []
      smtp = smtp_for(
        client,
        policy: policy(mode: :testing),
        starttls: :auto,
        mta_sts_reporter: ->(reason, _details) { reported << reason }
      )
      smtp.start
      assert_true reported.include?(:starttls_refused)
      smtp.finish
    end

    def test_send_message_rejects_recipient_outside_policy_domain
      client, peer = start_peer(starttls: true)
      smtp = smtp_for(client, policy: policy, starttls: :always)
      smtp.start
      error = assert_raise(SMTPMTASTSPolicyError) do
        smtp.send_message("Subject: test\r\n\r\nbody\r\n", "sender@example.com", "rcpt@other.example")
      end
      assert_equal :recipient_domain_mismatch, error.reason
      peer.join

      assert_false peer.commands.any? { |c| c.start_with?("MAIL FROM:") }
      assert_equal "", peer.body
    end

    def test_send_message_requires_satisfied_policy
      client, peer = start_peer(starttls: true)
      smtp = smtp_for(client, policy: policy, starttls: :always)
      smtp.start
      smtp.instance_variable_set(:@mta_sts_satisfied, false)
      error = assert_raise(SMTPMTASTSPolicyError) do
        smtp.send_message("body", "sender@example.com", "rcpt@example.com")
      end
      assert_equal :policy_not_satisfied, error.reason
      smtp.finish
    end

    def test_policy_domain_defaults_to_policy_domain_when_unspecified
      client, peer = start_peer(starttls: true)
      smtp = FakeTransportSMTP.new(
        client,
        address: CERTIFICATE_HOSTNAME,
        starttls: :auto,
        ssl_context_params: { ca_file: CA_FILE },
        mta_sts_policy: policy,
        mta_sts_mx_hostname: CERTIFICATE_HOSTNAME
      )
      smtp.start
      assert_equal POLICY_DOMAIN, smtp.mta_sts_applied_policy.domain
      smtp.finish
    end

    def test_testing_mode_mx_mismatch_never_sets_enforced
      client, _peer = start_peer(starttls: true)
      smtp = smtp_for(client, policy: policy(mode: :testing, mx: ["*.example.net"]))
      assert_nil smtp.send(:resolve_mta_sts_policy)
      refute smtp.mta_sts_enforced?
      refute smtp.mta_sts_testing?
      assert_equal [:mx_mismatch], smtp.mta_sts_failures.map { |f| f[:reason] }
    end

    def test_ssl_context_cannot_disable_verification_under_policy
      client, _peer = start_peer(starttls: true)
      smtp = smtp_for(client, policy: policy, ssl_context_params: { ca_file: CA_FILE, verify_mode: OpenSSL::SSL::VERIFY_NONE })
      smtp.start
      assert_equal OpenSSL::SSL::VERIFY_PEER, smtp.instance_variable_get(:@ssl_context_starttls).verify_mode
      smtp.finish
    end

    def test_expired_policy_allows_plain_delivery_as_no_active_policy
      client, peer = start_peer(starttls: false)
      expired = policy(fetched_at: Time.now - 7200, max_age: 3600)
      smtp = smtp_for(client, policy: expired)
      smtp.start
      smtp.send_message("Subject: test\r\n\r\nbody\r\n", "sender@example.com", "rcpt@example.com")
      smtp.finish

      assert_nil smtp.mta_sts_applied_policy
      assert_false smtp.mta_sts_enforced?
      assert_match(/body/, peer.body)
    end

    def test_testing_policy_sends_over_verified_tls
      client, peer = start_peer(starttls: true)
      smtp = smtp_for(client, policy: policy(mode: :testing), starttls: :auto)
      smtp.start(user: "account", secret: "password", authtype: :plain)
      smtp.send_message("Subject: test\r\n\r\nbody\r\n", "sender@example.com", "rcpt@example.com")
      smtp.finish

      assert_true peer.starttls_attempted
      assert_match(/body/, peer.body)
    end

    def test_enforce_send_message_guard_covers_open_message_stream
      client, peer = start_peer(starttls: true)
      smtp = smtp_for(client, policy: policy, starttls: :always)
      smtp.start
      smtp.instance_variable_set(:@mta_sts_satisfied, false)
      error = assert_raise(SMTPMTASTSPolicyError) do
        smtp.open_message_stream("sender@example.com", "rcpt@example.com") { |stream| stream.puts "body" }
      end
      assert_equal :policy_not_satisfied, error.reason
      smtp.finish
    end

    def test_policy_reused_across_start_is_reapplied
      client, peer = start_peer(starttls: true)
      smtp = smtp_for(client, policy: policy, starttls: :always)
      smtp.start
      assert_true smtp.mta_sts_enforced?
      smtp.finish
      assert_nil smtp.mta_sts_applied_policy

      client, peer = start_peer(starttls: true)
      smtp.instance_variable_set(:@fake_sockets, [client])
      smtp.start
      assert_true smtp.mta_sts_enforced?
      smtp.finish
    end

    def test_enforce_overrides_tls_verify_false
      client, peer = start_peer(starttls: true)
      smtp = smtp_for(client, policy: policy, starttls: :always, tls_verify: false,
                      ssl_context_params: { ca_file: CA_FILE })
      smtp.start(user: "account", secret: "password", authtype: :plain)
      assert_equal OpenSSL::SSL::VERIFY_PEER, smtp.instance_variable_get(:@ssl_context_starttls).verify_mode
      smtp.send_message("Subject: test\r\n\r\nbody\r\n", "sender@example.com", "rcpt@example.com")
      smtp.finish
      assert_match(/body/, peer.body)
    end

    def test_enforce_rejects_untrusted_certificate_before_auth
      client, peer = start_peer(starttls: true)
      smtp = smtp_for(client, policy: policy, starttls: :always, ssl_context_params: {})
      assert_raise(OpenSSL::SSL::SSLError) do
        smtp.start(user: "account", secret: "password", authtype: :plain)
      end
      peer.join
      assert_false peer.commands.any? { |c| c.start_with?("AUTH ") }
      assert_false peer.commands.any? { |c| c.start_with?("MAIL FROM:") }
      assert_equal "", peer.body
    end

    def test_direct_tls_policy_pins_identity_to_selected_mx
      client, peer = start_peer(starttls: false)
      smtp = smtp_for(
        client,
        policy: policy(mx: [MX_HOSTNAME]),
        tls: true,
        tls_hostname: MX_HOSTNAME,
        mta_sts_mx_hostname: MX_HOSTNAME
      )
      # Direct TLS: the peer's certificate is CN=localhost, but the policy
      # pins the MX identity to mail.example.com. The connection must fail
      # before authentication.
      assert_raise(OpenSSL::SSL::SSLError, SMTPMTASTSPolicyError) do
        smtp.start(user: "account", secret: "password", authtype: :plain)
      end
      peer.join(1)
      assert_false peer.commands.any? { |c| c.start_with?("AUTH ") }
      assert_false peer.commands.any? { |c| c.start_with?("MAIL FROM:") }
    end
  end
end
