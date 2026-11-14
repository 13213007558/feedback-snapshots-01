# frozen_string_literal: true
require 'net/smtp'
require 'test/unit'
require 'socket'

module Net
  # Tests for strict SMTP reply validation: reply line syntax, multiline
  # reply code consistency, and per-command allowed reply codes for
  # EHLO, STARTTLS, AUTH and DATA.
  #
  # The ScriptedServer drives the client over a UNIX socketpair, sends
  # replies in fragments, and records every byte the client writes, so
  # tests can prove that one reply belongs to exactly one command and
  # that no sensitive content is sent after synchronization is lost.
  class TestSMTPResponseValidation < Test::Unit::TestCase
    class ScriptedServer
      # All bytes written by the client, in order.
      attr_reader :received

      def initialize
        @received = +''.b
        @steps = []
        @error = nil
      end

      # Expect one CRLF-terminated command line from the client.
      def expect_command(expected)
        @steps << [:command, expected]
        self
      end

      # Expect a DATA message body up to the ".\r\n" terminator.
      def expect_data
        @steps << [:data]
        self
      end

      # Send a reply, optionally split into fragments of +fragment+ bytes.
      def reply(text, fragment: nil)
        @steps << [:reply, text, fragment]
        self
      end

      def start
        @client_side, @server_side = Socket.pair(:UNIX, :STREAM, 0)
        @thread = Thread.new do
          begin
            run_script
          rescue Exception => error
            @error = error
          ensure
            @server_side.close
          end
        end
        @client_side
      end

      def join
        unless @thread.join(10)
          @thread.kill
          raise 'scripted server did not finish'
        end
        @client_side.close unless @client_side.closed?
        raise @error if @error
      end

      private

      def run_script
        @steps.each do |action, *args|
          case action
          when :command
            line = @server_side.gets("\r\n") or
              raise EOFError, 'client closed the connection'
            @received << line
            expected = args[0]
            unless expected === line
              raise "expected client to send #{expected.inspect}, got #{line.inspect}"
            end
          when :data
            while (line = @server_side.gets("\r\n"))
              @received << line
              break if line == ".\r\n"
            end
          when :reply
            text, fragment = args
            if fragment
              text.scan(/.{1,#{fragment}}/m) { |chunk| @server_side.write(chunk) }
            else
              @server_side.write(text)
            end
          end
        end
      end
    end

    def new_smtp(server, starttls: false)
      sock = server.start
      smtp = Net::SMTP.new('localhost', 25, starttls: starttls, tls_verify: false)
      smtp.define_singleton_method(:tcp_socket) { |*| sock }
      smtp
    end

    def scripted_server
      server = ScriptedServer.new
      yield server
      server
    end

    def test_fragmented_multiline_responses_drive_full_session
      server = scripted_server do |s|
        s.reply("220 ready\r\n", fragment: 1)
        s.expect_command("EHLO localhost\r\n")
        s.reply("250-localhost\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n", fragment: 3)
        s.expect_command("RSET\r\n")
        s.reply("250 2.0.0 Ok\r\n", fragment: 2)
        s.expect_command("QUIT\r\n")
        s.reply("221 2.0.0 Bye\r\n", fragment: 5)
      end
      smtp = new_smtp(server)
      smtp.start
      assert_equal({ 'AUTH' => %w[PLAIN LOGIN], '8BITMIME' => [] }, smtp.capabilities)
      assert_equal(true, smtp.capable_plain_auth?)
      assert_equal('250', smtp.rset.status)
      smtp.finish
      server.join
      assert_equal("EHLO localhost\r\nRSET\r\nQUIT\r\n", server.received)
    end

    def test_multiline_reply_code_jump_is_rejected
      server = scripted_server do |s|
        s.reply("220 ready\r\n")
        s.expect_command("EHLO localhost\r\n")
        s.reply("250-localhost\r\n250-AUTH PLAIN\r\n251 OK\r\n")
      end
      smtp = new_smtp(server)
      err = assert_raise(Net::ProtocolError) { smtp.start }
      assert_match(/250.*251/, err.message)
      server.join
      # synchronization lost: nothing more is sent after the bogus reply
      assert_equal("EHLO localhost\r\n", server.received)
    end

    def test_malformed_reply_line_is_rejected
      server = scripted_server do |s|
        s.reply("220 ready\r\n")
        s.expect_command("EHLO localhost\r\n")
        s.reply("2500-four-digits\r\n")
      end
      smtp = new_smtp(server)
      err = assert_raise(Net::ProtocolError) { smtp.start }
      assert_match(/reply line format/, err.message)
      server.join
      assert_equal("EHLO localhost\r\n", server.received)
    end

    def test_non_digit_reply_line_is_rejected
      server = scripted_server do |s|
        s.reply("220 ready\r\n")
        s.expect_command("EHLO localhost\r\n")
        s.reply("25A-bad\r\n250 OK\r\n")
      end
      smtp = new_smtp(server)
      assert_raise(Net::ProtocolError) { smtp.start }
      server.join
      assert_equal("EHLO localhost\r\n", server.received)
    end

    def test_one_reply_belongs_to_exactly_one_command
      server = scripted_server do |s|
        s.reply("220 ready\r\n")
        s.expect_command("EHLO localhost\r\n")
        s.reply("250 localhost\r\n")
        s.expect_command("RSET\r\n")
        # two complete replies sent back to back for a single command
        s.reply("250 first\r\n250 second\r\n")
        s.expect_command("RSET\r\n")
        s.reply("250 third\r\n")
        s.expect_command("QUIT\r\n")
      end
      smtp = new_smtp(server)
      smtp.start
      first = smtp.rset
      # the reply trailing the terminator is not absorbed into this response
      assert_equal("250 first\n", first.string)
      assert_equal('250', first.status)
      # it is consumed as the reply to the next command instead
      second = smtp.rset
      assert_equal("250 second\n", second.string)
      smtp.finish
      server.join
      assert_equal("EHLO localhost\r\nRSET\r\nRSET\r\nQUIT\r\n", server.received)
    end

    def test_ehlo_requires_250_and_falls_back_to_helo
      server = scripted_server do |s|
        s.reply("220 ready\r\n")
        s.expect_command("EHLO localhost\r\n")
        s.reply("220-servername\r\n220 OK\r\n")
        s.expect_command("HELO localhost\r\n")
        s.reply("250 localhost\r\n")
        s.expect_command("QUIT\r\n")
        s.reply("221 2.0.0 Bye\r\n")
      end
      smtp = new_smtp(server)
      smtp.start
      assert_equal(false, smtp.esmtp?)
      smtp.finish
      server.join
      assert_equal("EHLO localhost\r\nHELO localhost\r\nQUIT\r\n", server.received)
    end

    def test_starttls_requires_220
      server = scripted_server do |s|
        s.reply("220 ready\r\n")
        s.expect_command("EHLO localhost\r\n")
        s.reply("250-localhost\r\n250 STARTTLS\r\n")
        s.expect_command("STARTTLS\r\n")
        s.reply("250 OK\r\n")
      end
      smtp = new_smtp(server, starttls: :always)
      assert_raise(Net::SMTPUnknownError) { smtp.start }
      server.join
      # no second EHLO and no TLS handshake after the wrong reply code
      assert_equal("EHLO localhost\r\nSTARTTLS\r\n", server.received)
    end

    def test_data_rejects_premature_success
      server = scripted_server do |s|
        s.reply("220 ready\r\n")
        s.expect_command("EHLO localhost\r\n")
        s.reply("250 localhost\r\n")
        s.expect_command("MAIL FROM:<a@example.com>\r\n")
        s.reply("250 2.1.0 Ok\r\n")
        s.expect_command("RCPT TO:<b@example.com>\r\n")
        s.reply("250 2.1.5 Ok\r\n")
        s.expect_command("DATA\r\n")
        s.reply("250 2.0.0 Ok: queued as EARLY\r\n")
      end
      smtp = new_smtp(server)
      smtp.start
      err = assert_raise(Net::SMTPUnknownError) do
        smtp.send_message("SECRET BODY\r\n", 'a@example.com', 'b@example.com')
      end
      assert_match(/could not get 354/, err.message)
      smtp.finish
      server.join
      # premature success is not a permission to send the message body
      assert_not_include(server.received, 'SECRET BODY')
      assert_equal(
        "EHLO localhost\r\nMAIL FROM:<a@example.com>\r\n" \
        "RCPT TO:<b@example.com>\r\nDATA\r\n",
        server.received
      )
    end

    def test_data_rejects_wrong_continue_code
      server = scripted_server do |s|
        s.reply("220 ready\r\n")
        s.expect_command("EHLO localhost\r\n")
        s.reply("250 localhost\r\n")
        s.expect_command("MAIL FROM:<a@example.com>\r\n")
        s.reply("250 2.1.0 Ok\r\n")
        s.expect_command("RCPT TO:<b@example.com>\r\n")
        s.reply("250 2.1.5 Ok\r\n")
        s.expect_command("DATA\r\n")
        s.reply("334 go ahead\r\n")
      end
      smtp = new_smtp(server)
      smtp.start
      assert_raise(Net::SMTPUnknownError) do
        smtp.send_message("SECRET BODY\r\n", 'a@example.com', 'b@example.com')
      end
      smtp.finish
      server.join
      assert_not_include(server.received, 'SECRET BODY')
    end

    def test_data_final_reply_requires_250
      server = scripted_server do |s|
        s.reply("220 ready\r\n")
        s.expect_command("EHLO localhost\r\n")
        s.reply("250 localhost\r\n")
        s.expect_command("MAIL FROM:<a@example.com>\r\n")
        s.reply("250 2.1.0 Ok\r\n")
        s.expect_command("RCPT TO:<b@example.com>\r\n")
        s.reply("250 2.1.5 Ok\r\n")
        s.expect_command("DATA\r\n")
        s.reply("354 End data with <CR><LF>.<CR><LF>\r\n")
        s.expect_data
        s.reply("251 2.0.0 Ok-ish\r\n")
        s.expect_command("QUIT\r\n")
        s.reply("221 2.0.0 Bye\r\n")
      end
      smtp = new_smtp(server)
      smtp.start
      assert_raise(Net::SMTPUnknownError) do
        smtp.send_message("hello\r\n", 'a@example.com', 'b@example.com')
      end
      smtp.finish
      server.join
      assert_include(server.received, "hello\r\n.\r\n")
    end

    def test_fragmented_auth_login_success
      server = scripted_server do |s|
        s.reply("220 ready\r\n", fragment: 2)
        s.expect_command("EHLO localhost\r\n")
        s.reply("250-localhost\r\n250 AUTH LOGIN\r\n", fragment: 5)
        s.expect_command("AUTH LOGIN\r\n")
        s.reply("334 VXNlcm5hbWU6\r\n", fragment: 1)
        s.expect_command("YWNjb3VudA==\r\n")
        s.reply("334 UGFzc3dvcmQ6\r\n", fragment: 3)
        s.expect_command("cGFzc3dvcmQ=\r\n")
        s.reply("235 2.7.0 Authentication successful\r\n", fragment: 4)
        s.expect_command("QUIT\r\n")
        s.reply("221 2.0.0 Bye\r\n")
      end
      smtp = new_smtp(server)
      smtp.start(user: 'account', secret: 'password', authtype: :login)
      assert_equal(true, smtp.started?)
      smtp.finish
      server.join
      assert_equal(
        "EHLO localhost\r\nAUTH LOGIN\r\n" \
        "YWNjb3VudA==\r\ncGFzc3dvcmQ=\r\nQUIT\r\n",
        server.received
      )
    end

    def test_fragmented_auth_cram_md5_success
      server = scripted_server do |s|
        s.reply("220 ready\r\n")
        s.expect_command("EHLO localhost\r\n")
        s.reply("250-localhost\r\n250 AUTH CRAM-MD5\r\n", fragment: 6)
        s.expect_command("AUTH CRAM-MD5\r\n")
        s.reply("334 PDEyMzQ1Njc4OTAuMTIzNDVAc2VydmVybmFtZT4=\r\n", fragment: 7)
        s.expect_command("YWNjb3VudCAyYzBjMTgxZjkxOGU2ZGM5Mjg3Zjk3N2E1ODhiMzg1YQ==\r\n")
        s.reply("235 2.7.0 Authentication successful\r\n")
        s.expect_command("QUIT\r\n")
        s.reply("221 2.0.0 Bye\r\n")
      end
      smtp = new_smtp(server)
      smtp.start(user: 'account', secret: 'password', authtype: :cram_md5)
      smtp.finish
      server.join
    end

    def test_auth_login_stops_on_premature_success
      server = scripted_server do |s|
        s.reply("220 ready\r\n")
        s.expect_command("EHLO localhost\r\n")
        s.reply("250-localhost\r\n250 AUTH LOGIN\r\n")
        s.expect_command("AUTH LOGIN\r\n")
        s.reply("235 2.7.0 Authentication successful\r\n")
      end
      smtp = new_smtp(server)
      assert_raise(Net::SMTPUnknownError) do
        smtp.start(user: 'account', secret: 'password', authtype: :login)
      end
      server.join
      # premature 235 is not a success: the user name is never sent
      assert_equal("EHLO localhost\r\nAUTH LOGIN\r\n", server.received)
    end

    def test_auth_login_does_not_send_password_at_wrong_stage
      server = scripted_server do |s|
        s.reply("220 ready\r\n")
        s.expect_command("EHLO localhost\r\n")
        s.reply("250-localhost\r\n250 AUTH LOGIN\r\n")
        s.expect_command("AUTH LOGIN\r\n")
        s.reply("334 VXNlcm5hbWU6\r\n")
        s.expect_command("YWNjb3VudA==\r\n")
        s.reply("250 OK\r\n")
      end
      smtp = new_smtp(server)
      assert_raise(Net::SMTPUnknownError) do
        smtp.start(user: 'account', secret: 'password', authtype: :login)
      end
      server.join
      # 250 is not a continue reply: the password is never sent
      assert_equal(
        "EHLO localhost\r\nAUTH LOGIN\r\nYWNjb3VudA==\r\n",
        server.received
      )
    end

    def test_auth_cram_md5_does_not_send_digest_at_wrong_stage
      server = scripted_server do |s|
        s.reply("220 ready\r\n")
        s.expect_command("EHLO localhost\r\n")
        s.reply("250-localhost\r\n250 AUTH CRAM-MD5\r\n")
        s.expect_command("AUTH CRAM-MD5\r\n")
        s.reply("235 2.7.0 Authentication successful\r\n")
      end
      smtp = new_smtp(server)
      assert_raise(Net::SMTPUnknownError) do
        smtp.start(user: 'account', secret: 'password', authtype: :cram_md5)
      end
      server.join
      # the digest derived from the secret is never sent
      assert_equal("EHLO localhost\r\nAUTH CRAM-MD5\r\n", server.received)
    end

    def test_auth_plain_requires_235
      server = scripted_server do |s|
        s.reply("220 ready\r\n")
        s.expect_command("EHLO localhost\r\n")
        s.reply("250-localhost\r\n250 AUTH PLAIN\r\n")
        s.expect_command("AUTH PLAIN AGFjY291bnQAcGFzc3dvcmQ=\r\n")
        s.reply("250 OK\r\n")
      end
      smtp = new_smtp(server)
      assert_raise(Net::SMTPAuthenticationError) do
        smtp.start(user: 'account', secret: 'password', authtype: :plain)
      end
      server.join
      assert_equal(
        "EHLO localhost\r\nAUTH PLAIN AGFjY291bnQAcGFzc3dvcmQ=\r\n",
        server.received
      )
    end

    def test_no_command_is_sent_after_synchronization_is_lost
      server = scripted_server do |s|
        s.reply("220 ready\r\n")
        s.expect_command("EHLO localhost\r\n")
        s.reply("250-localhost\r\n250-AUTH PLAIN\r\n251 broken\r\n")
      end
      smtp = new_smtp(server)
      assert_raise(Net::ProtocolError) { smtp.start }
      server.join
      assert_equal("EHLO localhost\r\n", server.received)
      # the session is poisoned: further commands raise instead of
      # writing sensitive content to the desynchronized connection
      assert_raise(Net::SMTPAuthenticationError) do
        smtp.authenticate('account', 'password', :plain)
      end
      assert_equal("EHLO localhost\r\n", server.received)
    end
  end
end
