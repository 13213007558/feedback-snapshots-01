# frozen_string_literal: true

require 'net/smtp'
require 'test/unit'
require 'socket'

module Net
  # Unit tests for the structured RFC 3461 DSN value objects. They exercise
  # encoding and validation without opening any network connection.
  class TestDSNValue < Test::Unit::TestCase
    def test_encode_xtext_printable_passthrough
      # "!" through "~" except "+" and "=" are emitted as themselves.
      assert_equal 'ABC-xyz_0123', Net::SMTP::DSN.encode_xtext('ABC-xyz_0123')
    end

    def test_encode_xtext_space_plus_equals
      # The characters the task calls out explicitly: space, "+" and "=".
      assert_equal 'a+20b',       Net::SMTP::DSN.encode_xtext('a b')
      assert_equal 'a+2Bb',       Net::SMTP::DSN.encode_xtext('a+b')
      assert_equal 'a+3Db',       Net::SMTP::DSN.encode_xtext('a=b')
      assert_equal '+20+2B+3D',   Net::SMTP::DSN.encode_xtext(' +=')
    end

    def test_encode_xtext_non_ascii_uses_utf8_octets
      # "ü" is the two UTF-8 octets 0xC3 0xBC, each encoded as a hexchar.
      assert_equal 'g+C3+BCnther', Net::SMTP::DSN.encode_xtext('günther')
    end

    def test_encode_xtext_control_characters
      assert_equal 'a+09b', Net::SMTP::DSN.encode_xtext("a\tb")
      assert_equal '+0D+0A', Net::SMTP::DSN.encode_xtext("\r\n")
      assert_equal '+7F', Net::SMTP::DSN.encode_xtext("\x7F")
    end

    def test_sender_parameters_bound_to_mail
      sender = Net::SMTP::DSN::Sender.new(
        'alice@example.org', envid: 'id 1+2=3', ret: :hdrs
      )
      assert sender.dsn?
      assert_equal ['RET=HDRS', 'ENVID=id+201+2B2+3D3'], sender.parameters
    end

    def test_sender_ret_accepts_string_and_symbol
      assert_equal ['RET=FULL'],
                   Net::SMTP::DSN::Sender.new('a@b', ret: 'full').parameters
      assert_equal ['RET=HDRS'],
                   Net::SMTP::DSN::Sender.new('a@b', ret: :HDRS).parameters
    end

    def test_sender_without_parameters_is_still_dsn
      sender = Net::SMTP::DSN::Sender.new('a@b')
      assert sender.dsn?
      assert_equal [], sender.parameters
    end

    def test_recipient_parameters_bound_to_rcpt
      rcpt = Net::SMTP::DSN::Recipient.new(
        'bob@example.com',
        notify: [:success, :failure],
        orcpt: 'bob@example.com'
      )
      assert rcpt.dsn?
      assert_equal ['NOTIFY=SUCCESS,FAILURE', 'ORCPT=rfc822;bob@example.com'],
                   rcpt.parameters
    end

    def test_recipient_notify_never_alone
      rcpt = Net::SMTP::DSN::Recipient.new('f@x', notify: :never)
      assert_equal ['NOTIFY=NEVER'], rcpt.parameters
    end

    def test_recipient_orcpt_custom_addr_type
      rcpt = Net::SMTP::DSN::Recipient.new(
        'x@y', orcpt: 'original x@y', addr_type: 'rfc822'
      )
      assert_equal ['ORCPT=rfc822;original+20x@y'], rcpt.parameters
    end

    def test_recipient_orcpt_non_ascii
      rcpt = Net::SMTP::DSN::Recipient.new('g@x', orcpt: 'günther@x')
      assert_equal ['ORCPT=rfc822;g+C3+BCnther@x'], rcpt.parameters
    end

    def test_notify_is_case_insensitive
      assert_equal ['NOTIFY=DELAY'],
                   Net::SMTP::DSN::Recipient.new('a@b', notify: 'delay').parameters
    end

    def test_notify_duplicates_are_deduped
      assert_equal ['NOTIFY=FAILURE'],
                   Net::SMTP::DSN::Recipient.new(
                     'a@b', notify: [:failure, :failure]
                   ).parameters
    end

    def test_notify_never_is_mutually_exclusive
      err = assert_raise(ArgumentError) do
        Net::SMTP::DSN::Recipient.new('a@b', notify: [:never, :success])
      end
      assert_match(/NEVER/, err.message)
    end

    def test_notify_rejects_unknown_keyword
      assert_raise(ArgumentError) do
        Net::SMTP::DSN::Recipient.new('a@b', notify: :bogus)
      end
    end

    def test_notify_rejects_empty_list
      assert_raise(ArgumentError) do
        Net::SMTP::DSN::Recipient.new('a@b', notify: [])
      end
    end

    def test_ret_rejects_unknown_value
      assert_raise(ArgumentError) do
        Net::SMTP::DSN::Sender.new('a@b', ret: :bogus)
      end
    end

    def test_envid_rejects_non_printable_control_character
      assert_raise(ArgumentError) do
        Net::SMTP::DSN::Sender.new('a@b', envid: "ab\ncd")
      end
    end

    def test_orcpt_rejects_non_printable_control_character
      assert_raise(ArgumentError) do
        Net::SMTP::DSN::Recipient.new('a@b', orcpt: "ab\rcd")
      end
    end

    def test_orcpt_rejects_bad_addr_type
      assert_raise(ArgumentError) do
        Net::SMTP::DSN::Recipient.new('a@b', orcpt: 'x', addr_type: 'bad;type')
      end
      assert_raise(ArgumentError) do
        Net::SMTP::DSN::Recipient.new('a@b', orcpt: 'x', addr_type: '')
      end
    end

    def test_plain_address_is_not_dsn
      assert !Net::SMTP::Address.new('a@b').dsn?
    end
  end

  # A minimal SMTP peer speaking over a UNIX socketpair. It needs no TCP port
  # (which may be unavailable in a sandbox) and records every raw command line
  # so the tests can parse them independently of the library under test.
  class SocketPairSMTP
    attr_reader :commands, :client_io

    def initialize(caps = ['DSN'])
      @caps = caps
      @commands = []
      @client_io, @server_io = Socket.pair(:UNIX, :STREAM)
      @thread = Thread.start { serve }
    end

    def stop
      @thread.kill
      @thread.join
      @client_io.close unless @client_io.closed?
    end

    private

    def serve
      @server_io.write("220 ready\r\n")
      while (line = @server_io.gets)
        # Socket reads come back as ASCII-8BIT; normalize to UTF-8 so literal
        # comparisons of non-ASCII addresses behave like the project's
        # FakeServer (which records commands via encode('utf-8', 'utf-8')).
        @commands << line.dup.encode('utf-8', 'utf-8')
        case line.chomp
        when /\AEHLO /
          @server_io.write(ehlo_banner)
        when /\AMAIL FROM:/
          @server_io.write("250 2.1.0 Ok\r\n")
        when /\ARCPT TO:/
          @server_io.write("250 2.1.0 Ok\r\n")
        when 'DATA'
          @server_io.write("354 End data with <CR><LF>.<CR><LF>\r\n")
          while (body = @server_io.gets)
            break if body.chomp == '.'
          end
          @server_io.write("250 2.0.0 queued\r\n")
        when 'RSET'
          @server_io.write("250 2.0.0 Ok\r\n")
        when 'QUIT'
          @server_io.write("221 2.0.0 Bye\r\n")
          break
        else
          @server_io.write("502 5.5.2 command not recognized\r\n")
        end
      end
    rescue IOError, Errno::ECONNRESET
      nil
    end

    def ehlo_banner
      lines = ['250-servername', '250-AUTH PLAIN']
      @caps.each { |cap| lines << "250-#{cap}" }
      lines[-1] = lines[-1].sub(/\A250-/, '250 ')
      lines.join("\r\n") + "\r\n"
    end
  end

  # Wire-level tests proving parameter count and ownership on the actual
  # command lines, and the behaviour when the server lacks DSN support.
  class TestDSNWire < Test::Unit::TestCase
    # Splits a raw SMTP command line into [verb, path, [param, ...]] without
    # using any Net::SMTP formatting code, so count and placement are checked
    # independently.
    def parse(line)
      tokens = line.chomp.split(' ')
      [tokens[0], tokens[1], tokens[2..] || []]
    end

    def start_smtp(peer)
      smtp = Net::SMTP.new('localhost', 25, starttls: false)
      smtp.define_singleton_method(:tcp_socket) do |_address, _port|
        peer.client_io
      end
      smtp.start
      smtp
    end

    def with_server(caps = ['DSN'])
      peer = SocketPairSMTP.new(caps)
      smtp = start_smtp(peer)
      yield peer, smtp
    ensure
      smtp&.finish if smtp&.started?
      peer&.stop
    end

    def test_capability_advertised
      with_server(["DSN"]) do |_peer, smtp|
        assert smtp.capable_dsn?
      end
    end

    def test_capability_absent
      with_server(["SIZE"]) do |_peer, smtp|
        assert !smtp.capable_dsn?
      end
    end

    def test_mail_and_rcpt_parameters_count_and_ownership
      with_server(["DSN"]) do |peer, smtp|
        sender = Net::SMTP::DSN::Sender.new(
          'alice@example.org', envid: 'a b+c=d', ret: :hdrs
        )
        r1 = Net::SMTP::DSN::Recipient.new(
          'bob@example.com',
          notify: [:success, :failure], orcpt: 'bob@example.com'
        )
        r2 = Net::SMTP::DSN::Recipient.new('carol@example.org', notify: :never)
        r3 = Net::SMTP::DSN::Recipient.new(
          'dave@example.org', orcpt: 'dave@example.org'
        )
        smtp.send_message('body', sender, [r1, r2, r3])

        mail = peer.commands.find { |c| c.start_with?('MAIL') }
        rcpts = peer.commands.select { |c| c.start_with?('RCPT') }

        assert_equal "MAIL FROM:<alice@example.org> RET=HDRS ENVID=a+20b+2Bc+3Dd\r\n",
                     mail
        m_verb, m_path, m_params = parse(mail)
        assert_equal 'MAIL', m_verb
        assert_equal 'FROM:<alice@example.org>', m_path
        assert_equal ['RET=HDRS', 'ENVID=a+20b+2Bc+3Dd'], m_params

        assert_equal 3, rcpts.size
        assert_equal(
          [
            "RCPT TO:<bob@example.com> NOTIFY=SUCCESS,FAILURE ORCPT=rfc822;bob@example.com\r\n",
            "RCPT TO:<carol@example.org> NOTIFY=NEVER\r\n",
            "RCPT TO:<dave@example.org> ORCPT=rfc822;dave@example.org\r\n"
          ],
          rcpts
        )

        parsed = rcpts.map { |c| parse(c) }
        assert_equal [2, 1, 1], parsed.map { |_, _, params| params.size }
        assert_equal ['NOTIFY=SUCCESS,FAILURE', 'ORCPT=rfc822;bob@example.com'],
                     parsed[0][2]
        assert_equal ['NOTIFY=NEVER'], parsed[1][2]
        assert_equal ['ORCPT=rfc822;dave@example.org'], parsed[2][2]
      end
    end

    def test_orcpt_stays_bound_to_its_own_recipient
      with_server(["DSN"]) do |peer, smtp|
        recipients = [
          Net::SMTP::DSN::Recipient.new('one@x', orcpt: 'one@x'),
          Net::SMTP::DSN::Recipient.new('two@x', notify: :failure),
          Net::SMTP::DSN::Recipient.new('three@x', orcpt: 'three@x')
        ]
        smtp.send_message('body', 'from@x', recipients)
        rcpts = peer.commands.select { |c| c.start_with?('RCPT') }
        orcpts = rcpts.map do |c|
          parse(c)[2].find { |param| param.start_with?('ORCPT=') }
        end
        assert_equal(
          ['ORCPT=rfc822;one@x', nil, 'ORCPT=rfc822;three@x'],
          orcpts
        )
      end
    end

    def test_dsn_sender_unsupported_before_transaction
      with_server(["SIZE"]) do |peer, smtp|
        assert_raise(Net::SMTPUnsupportedCommand) do
          smtp.send_message(
            'body',
            Net::SMTP::DSN::Sender.new('alice@example.org', envid: 'x'),
            Net::SMTP::DSN::Recipient.new('bob@example.com', notify: :failure)
          )
        end
        assert !peer.commands.any? { |c| c.start_with?('MAIL') }
        assert !peer.commands.any? { |c| c.start_with?('RCPT') }
      end
    end

    def test_dsn_recipient_unsupported_before_transaction
      with_server(["SIZE"]) do |peer, smtp|
        assert_raise(Net::SMTPUnsupportedCommand) do
          smtp.rcptto(Net::SMTP::DSN::Recipient.new('z@x', notify: :success))
        end
        assert !peer.commands.any? { |c| c.start_with?('RCPT') }
      end
    end

    def test_invalid_notify_is_rejected_at_construction
      # The invalid combination raises before any SMTP object is even built,
      # so an illegal parameter can never reach the mail transaction.
      assert_raise(ArgumentError) do
        Net::SMTP::DSN::Recipient.new('bad@x', notify: [:never, :success])
      end
    end

    def test_rcptto_list_validates_dsn_before_first_rcpt
      # Even though the unsupported DSN recipient is the second one, every
      # recipient is checked before any RCPT command is emitted.
      with_server(["SIZE"]) do |peer, smtp|
        plain = 'good@example.org'
        unsupported = Net::SMTP::DSN::Recipient.new('bad@example.org',
                                                    notify: :failure)
        assert_raise(Net::SMTPUnsupportedCommand) do
          smtp.send_message('body', 'from@example.org', [plain, unsupported])
        end
        assert !peer.commands.any? { |c| c.start_with?('RCPT') }
      end
    end

    def test_plain_mail_still_works_without_dsn
      with_server(["SIZE"]) do |peer, smtp|
        smtp.send_message('body', 'plain@example.org', 'dest@example.org')
        assert peer.commands.include?("MAIL FROM:<plain@example.org>\r\n")
        assert peer.commands.include?("RCPT TO:<dest@example.org>\r\n")
      end
    end

    def test_mailfrom_and_rcptto_accept_dsn_objects_directly
      with_server(["DSN"]) do |peer, smtp|
        smtp.mailfrom(Net::SMTP::DSN::Sender.new(
          'alice@example.org', ret: :full, envid: 'e1'
        ))
        smtp.rcptto(Net::SMTP::DSN::Recipient.new(
          'bob@example.com', notify: :delay, orcpt: 'bob@example.com'
        ))
        assert_equal "MAIL FROM:<alice@example.org> RET=FULL ENVID=e1\r\n",
                     peer.commands.find { |c| c.start_with?('MAIL') }
        assert_equal "RCPT TO:<bob@example.com> NOTIFY=DELAY ORCPT=rfc822;bob@example.com\r\n",
                     peer.commands.find { |c| c.start_with?('RCPT') }
      end
    end

    def test_dsn_sender_combines_with_smtputf8
      with_server(%w[DSN SMTPUTF8]) do |peer, smtp|
        sender = Net::SMTP::DSN::Sender.new(
          'rené@example.org', envid: 'e1', ret: :full
        )
        smtp.send_message('b', sender, 'dest@example.org')
        assert_equal "MAIL FROM:<rené@example.org> RET=FULL ENVID=e1 SMTPUTF8\r\n",
                     peer.commands.find { |c| c.start_with?('MAIL') }
      end
    end

    def test_non_ascii_orcpt_is_xtext_encoded
      with_server(%w[DSN SMTPUTF8]) do |peer, smtp|
        recipient = Net::SMTP::DSN::Recipient.new(
          'björn@example.org', notify: :failure, orcpt: 'björn@example.org'
        )
        smtp.send_message('b', 'from@example.org', recipient)
        assert_equal(
          "RCPT TO:<björn@example.org> NOTIFY=FAILURE " \
          "ORCPT=rfc822;bj+C3+B6rn@example.org\r\n",
          peer.commands.find { |c| c.start_with?('RCPT') }
        )
      end
    end

    def test_dsn_works_through_open_message_stream
      with_server(["DSN"]) do |peer, smtp|
        smtp.open_message_stream(
          Net::SMTP::DSN::Sender.new('a@b', envid: 'z'),
          Net::SMTP::DSN::Recipient.new('c@d', notify: :never)
        ) { |stream| stream.puts 'hello' }
        assert peer.commands.include?("MAIL FROM:<a@b> ENVID=z\r\n")
        assert peer.commands.include?("RCPT TO:<c@d> NOTIFY=NEVER\r\n")
      end
    end
  end
end
