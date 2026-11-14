# coding: utf-8

require 'net/lmtp'
require 'test/unit'

module Net
  class TestLMTP < Test::Unit::TestCase
    MESSAGE = <<~END_OF_MESSAGE
      From: from@example.com
      To: user@example.com
      Subject: test message

      This is a test message.
    END_OF_MESSAGE

    # In-memory LMTP server.  Replies to RCPT TO according to
    # +rcpt_status+ (address => reply code, default 250) and, after DATA,
    # sends one reply per entry of +final_statuses+ (250 delivers, any
    # other code fails, :drop closes the connection without a reply).
    # +final_statuses+ may intentionally be shorter or longer than the
    # number of accepted recipients.
    class FakeLMTPServer
      attr_reader :port, :commands, :delivered

      def initialize(rcpt_status: {}, final_statuses: [250])
        @rcpt_status = rcpt_status
        @final_statuses = final_statuses
        @commands = []
        @delivered = []
      end

      def start
        @servers = Socket.tcp_server_sockets('localhost', 0)
        @port = @servers[0].local_address.ip_port
        @thread = Thread.start do
          Thread.current.abort_on_exception = true
          @sock = Socket.accept_loop(@servers) { |s, _| break s }
          serve
        end
        self
      end

      def stop
        @thread&.kill
        @thread&.join
        @servers&.each(&:close)
      end

      private

      def serve
        @sock.puts "220 ready\r\n"
        accepted = []
        while (comm = @sock.gets)
          @commands.push comm
          case comm.chomp
          when /\ALHLO /
            @sock.puts "250-servername\r\n250 8BITMIME\r\n"
          when /\AMAIL FROM:/
            accepted = []
            @sock.puts "250 2.1.0 Ok\r\n"
          when /\ARCPT TO:<([^>]*)>/
            addr = $1
            if @rcpt_status.fetch(addr, 250) == 250
              accepted.push addr
              @sock.puts "250 2.1.5 Ok\r\n"
            else
              @sock.puts "#{@rcpt_status[addr]} 5.1.1 Rejected\r\n"
            end
          when "DATA"
            @sock.puts "354 End data with <CR><LF>.<CR><LF>\r\n"
            while (line = @sock.gets)
              break if line.chomp == '.'
            end
            @final_statuses.each_with_index do |code, i|
              addr = accepted[i] || "extra-#{i}@example.com"
              case code
              when 250
                @delivered.push addr
                @sock.puts "250 2.0.0 Delivered\r\n"
              when :drop
                @sock.close
                break
              else
                @sock.puts "#{code} 5.1.1 Failed\r\n"
              end
            end
            accepted = []
          when "RSET"
            accepted = []
            @sock.puts "250 2.0.0 Ok\r\n"
          when "QUIT"
            @sock.puts "221 2.0.0 Bye\r\n"
            @sock.close
            break
          else
            @sock.puts "502 5.5.2 Error: command not recognized\r\n"
          end
        end
      rescue Errno::ECONNRESET, Errno::ECONNABORTED, IOError
        nil
      end
    end

    def teardown
      @server&.stop
    end

    def start_server(**kw)
      @server = FakeLMTPServer.new(**kw).start
    end

    def test_default_port
      assert_equal 24, Net::LMTP.default_port
      assert_equal 24, Net::LMTP.new('localhost').port
      # SMTP defaults are unchanged.
      assert_equal 25, Net::SMTP.default_port
      assert_equal 25, Net::SMTP.new('localhost').port
    end

    def test_lhlo_greeting
      server = start_server
      Net::LMTP.start('localhost', server.port) do |lmtp|
        lmtp.send_message MESSAGE, 'from@example.com', 'user@example.com'
      end
      assert server.commands.any? { |c| c.start_with?('LHLO ') }
      assert server.commands.none? { |c| c.start_with?('EHLO ', 'HELO ') }
    end

    def test_all_recipients_delivered
      server = start_server(final_statuses: [250, 250])
      delivery = nil
      Net::LMTP.start('localhost', server.port) do |lmtp|
        delivery = lmtp.send_message MESSAGE, 'from@example.com',
                                     ['a@example.com', 'b@example.com']
      end
      assert_kind_of Net::LMTP::Delivery, delivery
      assert delivery.success?
      assert_equal ['a@example.com', 'b@example.com'],
                   delivery.delivered.map(&:address)
      assert_empty delivery.failed
      assert_equal ['a@example.com', 'b@example.com'], server.delivered
    end

    def test_partial_rcpt_rejection_and_partial_final_failure
      server = start_server(rcpt_status: { 'carol@example.com' => 550 },
                            final_statuses: [250, 550])
      delivery = nil
      Net::LMTP.start('localhost', server.port) do |lmtp|
        delivery = lmtp.send_message MESSAGE, 'from@example.com',
                                     ['alice@example.com', 'bob@example.com', 'carol@example.com']
      end
      # Order and failure attribution are preserved.
      assert_equal ['alice@example.com', 'bob@example.com', 'carol@example.com'],
                   delivery.recipients.map(&:address)
      assert_equal ['alice@example.com'], delivery.delivered.map(&:address)
      assert_equal ['bob@example.com', 'carol@example.com'],
                   delivery.failed.map(&:address)
      assert_not delivery.success?

      alice, bob, carol = delivery.recipients
      assert alice.delivered?
      assert_equal '250', alice.response.status

      # bob was accepted at RCPT time but his own final reply failed.
      assert bob.accepted?
      assert_equal '550', bob.response.status
      assert_not bob.delivered?

      # carol was rejected at RCPT time and never got a final reply.
      assert_not carol.accepted?
      assert_equal '550', carol.rcpt_response.status
      assert_nil carol.response
      assert_not carol.confirmed?
      assert_not carol.delivered?

      # The server only recorded the confirmed recipient as delivered.
      assert_equal ['alice@example.com'], server.delivered
    end

    def test_all_recipients_rejected_sends_no_data
      server = start_server(rcpt_status: { 'a@example.com' => 550,
                                           'b@example.com' => 550 })
      delivery = nil
      Net::LMTP.start('localhost', server.port) do |lmtp|
        delivery = lmtp.send_message MESSAGE, 'from@example.com',
                                     ['a@example.com', 'b@example.com']
      end
      assert_empty delivery.delivered
      assert_equal 2, delivery.failed.size
      assert server.commands.none? { |c| c.chomp == 'DATA' }
      assert_empty server.delivered
    end

    def test_missing_final_reply_poisons_session
      server = start_server(final_statuses: [250, :drop])
      lmtp = Net::LMTP.new('localhost', server.port)
      lmtp.start
      assert_raise(EOFError) do
        lmtp.send_message MESSAGE, 'from@example.com',
                          ['a@example.com', 'b@example.com']
      end
      # The session is poisoned: no further commands are sent, so no
      # reply can be misattributed to a following message.
      commands_before = server.commands.size
      lmtp.send_message MESSAGE, 'from@example.com', 'c@example.com'
      assert_equal commands_before, server.commands.size
      # Only the confirmed recipient was recorded as delivered.
      assert_equal ['a@example.com'], server.delivered
    ensure
      lmtp.finish if lmtp&.started?
    end

    def test_extra_final_reply_poisons_session
      server = start_server(final_statuses: [250, 250, 250])
      lmtp = Net::LMTP.new('localhost', server.port)
      lmtp.start
      assert_raise(Net::LMTP::ProtocolError) do
        lmtp.send_message MESSAGE, 'from@example.com',
                          ['a@example.com', 'b@example.com']
      end
      # The extra reply must not be consumed as a reply to later commands.
      commands_before = server.commands.size
      lmtp.send_message MESSAGE, 'from@example.com', 'c@example.com'
      assert_equal commands_before, server.commands.size
    ensure
      lmtp.finish if lmtp&.started?
    end
  end
end
