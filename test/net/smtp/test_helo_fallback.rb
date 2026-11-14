# coding: utf-8

require 'net/smtp'
require 'test/unit'

module Net
  # Tests for the security-sensitive EHLO -> HELO compatibility fallback.
  #
  # A real TCP listener cannot be used in some sandboxed CI environments, so
  # both the scripted server and the client talk over a UNIXSocket pair, the
  # same approach as test_starttls.rb.  Every server reply is scripted up
  # front and every command the client actually sends is recorded, which lets
  # the assertions prove that HELO is never emitted without permission.
  class TestHeloFallback < Test::Unit::TestCase
    class ScriptedSMTP < SMTP
      attr_accessor :scripted_socket

      def initialize(socket)
        @scripted_socket = socket
        super("smtp.example.com")
      end

      def tcp_socket(*)
        @scripted_socket
      end

      # The tests do not exercise real TLS negotiation; they only verify the
      # command sequence around STARTTLS and the capability reset afterwards.
      def tlsconnect(socket, *)
        socket
      end
    end

    class ScriptedServer
      GREETING = "220 scripted.example ESMTP ready\r\n"

      attr_reader :commands

      # +script+ maps a command verb ("EHLO", "HELO", "STARTTLS", ...) to a
      # queue of replies.  Each reply is either a String or an Array of
      # Strings (a multiline SMTP response); replies are consumed in order so
      # that pre- and post-STARTTLS EHLO exchanges can differ.
      def initialize(socket, script)
        @socket = socket
        @script = script.transform_values(&:dup)
        @commands = []
      end

      def run
        @thread = Thread.start do
          @socket.puts GREETING
          while (line = @socket.gets)
            command = line.chomp
            @commands << command
            verb = command.split.first
            if verb == 'QUIT'
              @socket.puts "221 2.0.0 Bye\r\n"
              break
            end
            reply = (@script[verb] || []).shift
            reply = [reply] unless reply.is_a?(Array)
            reply.each { |r| @socket.puts r }
          end
        rescue IOError, Errno::EPIPE, Errno::ECONNRESET
          nil
        end
      end

      def join
        @thread.join
      end

      def stop
        @thread&.kill
        @socket.close unless @socket.closed?
      end
    end

    HELO_DOMAIN = 'localhost'
    EHLO_LINE = "EHLO #{HELO_DOMAIN}"
    HELO_LINE = "HELO #{HELO_DOMAIN}"

    ESMTP_CAPABILITIES = [
      "250-scripted.example\r\n",
      "250-STARTTLS\r\n",
      "250-AUTH PLAIN LOGIN\r\n",
      "250 8BITMIME\r\n",
    ].freeze

    def teardown
      @smtp&.finish if @smtp&.started?
    rescue StandardError
      nil
    ensure
      @servers&.each(&:stop)
      @sockets&.each { |s| s.close unless s.closed? }
    end

    # Builds a connected pair, starts the scripted server thread and returns
    # the not-yet-started client together with the server.
    def build(script)
      client_socket, server_socket = UNIXSocket.pair
      server = ScriptedServer.new(server_socket, script)
      server.run
      smtp = ScriptedSMTP.new(client_socket)
      track(smtp, server, client_socket, server_socket)
      [smtp, server]
    end

    def track(smtp, server, *sockets)
      @smtp = smtp
      @servers = Array(@servers) << server
      @sockets = Array(@sockets).concat(sockets)
    end

    # Rebuilds the transport behind an existing client so the same SMTP
    # instance can open a second, independent connection.
    def reconnect(smtp, script)
      smtp.finish if smtp.started?
      client_socket, server_socket = UNIXSocket.pair
      server = ScriptedServer.new(server_socket, script)
      server.run
      smtp.scripted_socket = client_socket
      track(smtp, server, client_socket, server_socket)
      server
    end

    # ---- legitimate fallback: a server that truly lacks ESMTP -------------

    def test_ehlo_500_then_helo_succeeds_on_legacy_server
      smtp, server = build(
        'EHLO' => ["500 5.5.1 Error: command not recognized\r\n"],
        'HELO' => ["250 scripted.example\r\n"],
      )
      smtp.start

      assert(smtp.helo_fallback?)
      assert_equal({}, smtp.capabilities)
      assert(smtp.esmtp?, "the configured ESMTP preference must not be mutated")
      assert_equal([EHLO_LINE, HELO_LINE], server.commands)
    end

    def test_ehlo_502_then_helo_succeeds_on_legacy_server
      smtp, server = build(
        'EHLO' => ["502 5.5.2 Error: command not implemented\r\n"],
        'HELO' => ["250 scripted.example\r\n"],
      )
      smtp.start

      assert(smtp.helo_fallback?)
      assert_equal([EHLO_LINE, HELO_LINE], server.commands)
    end

    def test_legacy_fallback_advertises_no_extension
      smtp, _server = build(
        'EHLO' => ["500 5.5.1 Error: command not recognized\r\n"],
        'HELO' => ["250 scripted.example\r\n"],
      )
      smtp.start

      refute(smtp.capable?('STARTTLS'))
      refute(smtp.capable?('AUTH'))
      assert_equal([], smtp.capable_auth_types)
    end

    # ---- responses that must never trigger a fallback ---------------------

    def test_transient_421_does_not_fall_back
      smtp, server = build('EHLO' => ["421 4.3.2 Service not available\r\n"])
      assert_raise(Net::SMTPServerBusy) { smtp.start }

      assert_equal([EHLO_LINE], server.commands)
      refute(smtp.helo_fallback?)
      assert_nil(smtp.capabilities)
      assert(smtp.esmtp?)
    end

    def test_transient_451_does_not_fall_back
      smtp, server = build('EHLO' => ["451 4.7.0 Temporary error, try again later\r\n"])
      assert_raise(Net::SMTPServerBusy) { smtp.start }

      assert_equal([EHLO_LINE], server.commands)
    end

    def test_policy_rejection_550_does_not_fall_back
      smtp, server = build('EHLO' => ["550 5.7.1 Access denied\r\n"])
      assert_raise(Net::SMTPFatalError) { smtp.start }

      assert_equal([EHLO_LINE], server.commands)
    end

    def test_syntax_rejection_501_does_not_fall_back
      smtp, server = build('EHLO' => ["501 5.5.4 Invalid arguments\r\n"])
      assert_raise(Net::SMTPSyntaxError) { smtp.start }

      assert_equal([EHLO_LINE], server.commands)
    end

    def test_parameter_rejection_504_does_not_fall_back
      smtp, server = build('EHLO' => ["504 5.5.4 Command parameter not implemented\r\n"])
      assert_raise(Net::SMTPSyntaxError) { smtp.start }

      assert_equal([EHLO_LINE], server.commands)
    end

    def test_malformed_reply_does_not_fall_back
      smtp, server = build('EHLO' => ["999 9.9.9 Protocol anomaly\r\n"])
      assert_raise(Net::SMTPUnknownError) { smtp.start }

      assert_equal([EHLO_LINE], server.commands)
      refute(smtp.helo_fallback?)
    end

    def test_connection_drop_does_not_fall_back
      smtp, server = build('EHLO' => [])
      assert_raise(Net::SMTPUnknownError) { smtp.start }

      assert_equal([EHLO_LINE], server.commands)
      refute(smtp.helo_fallback?)
    end

    # ---- normal ESMTP flow ------------------------------------------------

    def test_successful_ehlo_never_sends_helo
      smtp, server = build('EHLO' => [ESMTP_CAPABILITIES])
      smtp.disable_starttls
      smtp.start

      assert_equal([EHLO_LINE], server.commands)
      refute(smtp.helo_fallback?)
      assert_equal(true, smtp.capable?('STARTTLS'))
      assert_equal(%w[PLAIN LOGIN], smtp.capabilities['AUTH'])
    end

    def test_explicit_plain_smtp_sends_only_helo
      smtp, server = build('HELO' => ["250 scripted.example\r\n"])
      smtp.esmtp = false
      smtp.start

      assert_equal([HELO_LINE], server.commands)
      refute(smtp.helo_fallback?)
    end

    # ---- callers that explicitly require an extension ---------------------

    def test_auth_requested_after_fallback_fails_without_auth_command
      smtp, server = build(
        'EHLO' => ["500 5.5.1 Error: command not recognized\r\n"],
        'HELO' => ["250 scripted.example\r\n"],
      )
      error = assert_raise(Net::SMTPUnsupportedCommand) do
        smtp.start(user: 'account', secret: 'password', authtype: :plain)
      end
      assert_match(/AUTH/, error.message)

      assert_equal([EHLO_LINE, HELO_LINE], server.commands)
      refute(server.commands.any? { |c| c.start_with?('AUTH') })
      refute(smtp.started?)
    end

    def test_smtputf8_after_fallback_fails_without_mail_command
      smtp, server = build(
        'EHLO' => ["500 5.5.1 Error: command not recognized\r\n"],
        'HELO' => ["250 scripted.example\r\n"],
      )
      smtp.start
      assert_raise(Net::SMTPUnsupportedCommand) do
        smtp.send_message('message', 'sender@example.com', 'rené@example.com')
      end

      assert_equal([EHLO_LINE, HELO_LINE], server.commands)
      refute(server.commands.any? { |c| c.start_with?('MAIL') })
    end

    def test_mailfrom_with_non_ascii_after_fallback_fails
      smtp, _server = build(
        'EHLO' => ["500 5.5.1 Error: command not recognized\r\n"],
        'HELO' => ["250 scripted.example\r\n"],
      )
      smtp.start
      assert_raise(Net::SMTPUnsupportedCommand) do
        smtp.mailfrom('rené@example.com')
      end
    end

    # ---- isolation across STARTTLS and across reconnects ------------------

    def test_post_starttls_fallback_replaces_cleartext_capabilities
      smtp, server = build(
        'EHLO' => [
          ["250-scripted.example\r\n", "250-STARTTLS\r\n", "250 8BITMIME\r\n"],
          "500 5.5.1 Error: command not recognized\r\n",
        ],
        'STARTTLS' => ["220 2.0.0 Ready to start TLS\r\n"],
        'HELO' => ["250 scripted.example\r\n"],
      )
      smtp.enable_starttls
      smtp.start

      assert(smtp.helo_fallback?)
      assert_equal({}, smtp.capabilities)
      refute(smtp.capable?('STARTTLS'))
      assert_equal(
        [EHLO_LINE, "STARTTLS", EHLO_LINE, HELO_LINE],
        server.commands,
      )
    end

    def test_post_starttls_transient_error_does_not_fall_back
      smtp, server = build(
        'EHLO' => [
          ["250-scripted.example\r\n", "250-STARTTLS\r\n", "250 8BITMIME\r\n"],
          "451 4.7.0 Temporary failure after TLS\r\n",
        ],
        'STARTTLS' => ["220 2.0.0 Ready to start TLS\r\n"],
      )
      smtp.enable_starttls
      assert_raise(Net::SMTPServerBusy) { smtp.start }

      assert_equal([EHLO_LINE, "STARTTLS", EHLO_LINE], server.commands)
      refute(server.commands.include?(HELO_LINE))
    end

    def test_post_starttls_500_does_not_reenable_cleartext_extensions
      # Even though a HELO fallback is legitimate here, the negotiated
      # STARTTLS session stays in place and its cleartext capabilities are
      # discarded rather than reused.
      smtp, server = build(
        'EHLO' => [
          ["250-scripted.example\r\n", "250-STARTTLS\r\n", "250-AUTH PLAIN\r\n", "250 8BITMIME\r\n"],
          "502 5.5.1 Command not implemented\r\n",
        ],
        'STARTTLS' => ["220 2.0.0 Ready to start TLS\r\n"],
        'HELO' => ["250 scripted.example\r\n"],
      )
      smtp.enable_starttls
      smtp.start

      assert(smtp.helo_fallback?)
      assert_equal({}, smtp.capabilities)
      refute(smtp.capable_starttls?)
      refute(smtp.capable_plain_auth?)
      assert_equal([EHLO_LINE, "STARTTLS", EHLO_LINE, HELO_LINE], server.commands)
    end

    def test_fallback_does_not_persist_into_next_connection
      smtp, legacy = build(
        'EHLO' => ["500 5.5.1 Error: command not recognized\r\n"],
        'HELO' => ["250 legacy.example\r\n"],
      )
      smtp.start
      assert(smtp.helo_fallback?)
      assert_equal([EHLO_LINE, HELO_LINE], legacy.commands)

      modern = reconnect(
        smtp,
        'EHLO' => [ESMTP_CAPABILITIES],
      )
      smtp.disable_starttls
      smtp.start

      refute(smtp.helo_fallback?)
      assert_equal([EHLO_LINE], modern.commands)
      assert_equal(true, smtp.capable?('STARTTLS'))
      assert(smtp.esmtp?)
    end

    def test_capabilities_are_rebuilt_not_leaked_between_connections
      smtp, first = build(
        'EHLO' => [[
          "250-first.example\r\n",
          "250-AUTH PLAIN\r\n",
          "250 8BITMIME\r\n",
        ]],
      )
      smtp.start
      assert_equal(['PLAIN'], smtp.capabilities['AUTH'])
      smtp.finish
      assert_nil(smtp.capabilities)

      second = reconnect(
        smtp,
        'EHLO' => [[
          "250-second.example\r\n",
          "250-SIZE 10485760\r\n",
          "250 8BITMIME\r\n",
        ]],
      )
      smtp.start

      assert_equal([EHLO_LINE], second.commands)
      assert_nil(smtp.capabilities['AUTH'])
      assert_equal(true, smtp.capable?('SIZE'))
      refute(smtp.helo_fallback?)
    end
  end
end
