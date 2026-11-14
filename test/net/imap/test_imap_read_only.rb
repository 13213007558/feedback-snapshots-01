# frozen_string_literal: true

require "net/imap"
require "test/unit"

class IMAPReadOnlyTest < Net::IMAP::TestCase

  # An in-memory transport double: the "server" end of a UNIX socket pair.
  # It records every command the client sends and replies with canned
  # responses, so tests can verify exactly what reached the wire.
  class RecordingTransport
    CRLF = "\r\n"

    def initialize
      @client_end, @server_end = UNIXSocket.pair
      @commands  = []
      @lock      = Mutex.new
    end

    def client_socket = @client_end

    def commands = @lock.synchronize { @commands.dup }

    def close
      [@client_end, @server_end].each do _1.close unless _1.closed? end
    end

    def run
      @server_end.print "* PREAUTH [CAPABILITY IMAP4rev1 LITERAL+] " \
                        "in-memory test server#{CRLF}"
      while (command = read_command)
        record(command)
        respond_to(command)
      end
    rescue IOError, SystemCallError
    ensure
      @server_end.close unless @server_end.closed?
    end

    private

    def record(command) = @lock.synchronize { @commands << command }

    def read_command
      line = @server_end.gets or return nil
      while (literal = /\{(\d+)(\+)?\}\r\n\z/.match(line))
        unless literal[2] # synchronizing literal: client waits for "+"
          @server_end.print "+ Ready for additional command text#{CRLF}"
        end
        line += @server_end.read(literal[1].to_i)
        line += @server_end.gets
      end
      line
    end

    def respond_to(command)
      tag, name, = command.split(" ")
      case name&.upcase
      when "LOGOUT"
        @server_end.print "* BYE logging out#{CRLF}"
        @server_end.print "#{tag} OK LOGOUT completed#{CRLF}"
        return # like a real server, close the connection after LOGOUT
      when "SELECT", "EXAMINE"
        @server_end.print "* 1 EXISTS#{CRLF}"
        @server_end.print "#{tag} OK [READ-WRITE] #{name.upcase} " \
                          "completed#{CRLF}"
      else
        @server_end.print "#{tag} OK #{name&.upcase} completed#{CRLF}"
      end
    end
  end

  # A client that connects over the in-memory transport instead of TCP.
  class InMemoryClient < Net::IMAP
    def initialize(socket, **config_options)
      @in_memory_socket = socket
      super("in-memory.test", **config_options)
    end

    private

    def tcp_socket(*) = @in_memory_socket
  end

  # Yields a connected client and its transport.  After the block, the
  # client is logged out (which also verifies that LOGOUT is permitted)
  # and the transport is returned for inspecting the recorded commands.
  def with_imap_client(**config_options)
    transport = RecordingTransport.new
    thread    = Thread.new { transport.run }
    client    = InMemoryClient.new(transport.client_socket, **config_options)
    yield client, transport
    transport
  ensure
    client.logout! if client && !client.disconnected?
    transport.close
    thread&.join(5)
  end

  test "read-only permits normal read commands" do
    transport = with_imap_client(read_only: true) do |imap, _transport|
      imap.select("INBOX")
      imap.examine("Archive")
      imap.noop
      imap.check
      imap.fetch(1, %w[FLAGS ENVELOPE INTERNALDATE RFC822.SIZE BODYSTRUCTURE])
      imap.uid_fetch(1, "BODY.PEEK[]")
      imap.fetch(1, "BINARY.PEEK[1]")
      imap.fetch(1, "RFC822.HEADER")
      imap.search("ALL")
      imap.status("INBOX", %w[MESSAGES UNSEEN])
      imap.list("", "*")
      imap.unselect
    end

    sent = transport.commands.join
    %w[SELECT EXAMINE NOOP CHECK FETCH SEARCH STATUS LIST UNSELECT LOGOUT
    ].each do assert_include sent, _1 end
  end

  test "read-only blocks message and flag writes before sending" do
    with_imap_client(read_only: true) do |imap, transport|
      imap.select("INBOX")
      sent_before = transport.commands.size

      error = assert_raise(Net::IMAP::ReadOnlyError) {
        imap.store(1, "+FLAGS", [:Seen])
      }
      assert_match(/flags/i, error.message)
      assert_raise(Net::IMAP::ReadOnlyError) {
        imap.uid_store(1, "FLAGS", [:Deleted])
      }
      assert_raise(Net::IMAP::ReadOnlyError) { imap.append("INBOX", "msg") }
      assert_raise(Net::IMAP::ReadOnlyError) { imap.copy(1, "Archive") }
      assert_raise(Net::IMAP::ReadOnlyError) { imap.uid_copy(1, "Archive") }
      assert_raise(Net::IMAP::ReadOnlyError) { imap.move(1, "Archive") }
      assert_raise(Net::IMAP::ReadOnlyError) { imap.uid_move(1, "Archive") }
      error = assert_raise(Net::IMAP::ReadOnlyError) { imap.expunge }
      assert_match(/delete/i, error.message)
      assert_raise(Net::IMAP::ReadOnlyError) { imap.uid_expunge(1) }

      assert_equal sent_before, transport.commands.size
    end
  end

  test "read-only blocks mailbox structure changes before sending" do
    with_imap_client(read_only: true) do |imap, transport|
      imap.select("INBOX")
      sent_before = transport.commands.size

      assert_raise(Net::IMAP::ReadOnlyError) { imap.create("Archive") }
      assert_raise(Net::IMAP::ReadOnlyError) { imap.delete("Archive") }
      assert_raise(Net::IMAP::ReadOnlyError) { imap.rename("a", "b") }
      assert_raise(Net::IMAP::ReadOnlyError) { imap.subscribe("INBOX") }
      assert_raise(Net::IMAP::ReadOnlyError) { imap.unsubscribe("INBOX") }
      assert_raise(Net::IMAP::ReadOnlyError) { imap.setquota("root", 512) }
      assert_raise(Net::IMAP::ReadOnlyError) {
        imap.setacl("INBOX", "user", "lr")
      }

      assert_equal sent_before, transport.commands.size
    end
  end

  test "read-only forbids CLOSE but permits UNSELECT and LOGOUT" do
    transport = with_imap_client(read_only: true) do |imap, _transport|
      imap.select("INBOX")
      error = assert_raise(Net::IMAP::ReadOnlyError) { imap.close }
      assert_match(/expunge/i, error.message)
      assert_match(/unselect|logout/i, error.message)
      imap.unselect
      imap.select("INBOX")
    end

    sent = transport.commands.join
    assert_include sent, "UNSELECT"
    assert_include sent, "LOGOUT"
    refute_match(/\bCLOSE\b/, sent)
  end

  test "read-only forbids FETCH items that set \\Seen, permits PEEK" do
    with_imap_client(read_only: true) do |imap, transport|
      imap.select("INBOX")
      sent_before = transport.commands.size

      error = assert_raise(Net::IMAP::ReadOnlyError) {
        imap.fetch(1, "BODY[]")
      }
      assert_match(/\\Seen/, error.message)
      assert_match(/PEEK/, error.message)
      assert_raise(Net::IMAP::ReadOnlyError) { imap.fetch(1, "BODY[TEXT]") }
      assert_raise(Net::IMAP::ReadOnlyError) {
        imap.fetch(1, ["FLAGS", "BODY[HEADER.FIELDS (FROM)]"])
      }
      assert_raise(Net::IMAP::ReadOnlyError) { imap.fetch(1, "RFC822") }
      assert_raise(Net::IMAP::ReadOnlyError) { imap.fetch(1, "RFC822.TEXT") }
      assert_raise(Net::IMAP::ReadOnlyError) { imap.fetch(1, "BINARY[]") }
      assert_raise(Net::IMAP::ReadOnlyError) {
        imap.uid_fetch(1, "UID BODY[1]")
      }

      assert_equal sent_before, transport.commands.size

      imap.fetch(1, "BODY.PEEK[]")
      imap.fetch(1, "BODY.PEEK[HEADER.FIELDS (FROM)]")
      imap.fetch(1, "BINARY.PEEK[1]")
      imap.fetch(1, "RFC822.HEADER")
      imap.fetch(1, "BODY") # non-extended BODY is the bodystructure
      imap.fetch(1, "FULL") # macro: FLAGS INTERNALDATE RFC822.SIZE ENVELOPE
      assert_equal sent_before + 6, transport.commands.size
    end
  end

  test "re-selecting or server READ-WRITE does not lift the constraint" do
    with_imap_client(read_only: true) do |imap, transport|
      imap.select("INBOX") # server claims [READ-WRITE]
      assert_raise(Net::IMAP::ReadOnlyError) {
        imap.store(1, "+FLAGS", [:Seen])
      }
      imap.examine("INBOX")
      imap.select("INBOX") # re-SELECT must not lift the constraint
      assert_raise(Net::IMAP::ReadOnlyError) {
        imap.store(1, "+FLAGS", [:Seen])
      }
      assert_raise(Net::IMAP::ReadOnlyError) { imap.close }

      sent = transport.commands.join
      refute_match(/\bSTORE\b/, sent)
      refute_match(/\bCLOSE\b/, sent)
    end
  end

  test "unclassifiable extension commands are explicitly rejected" do
    with_imap_client(read_only: true) do |imap, transport|
      imap.select("INBOX")
      sent_before = transport.commands.size

      error = assert_raise(Net::IMAP::ReadOnlyError) {
        imap.send(:send_command, "XACME-ARCHIVE", "INBOX")
      }
      assert_match(/cannot be verified/, error.message)

      assert_equal sent_before, transport.commands.size
    end
  end

  test "client without the constraint sends write commands unchanged" do
    with_imap_client do |imap, transport|
      refute imap.config.read_only?
      imap.select("INBOX")
      imap.store(1, "+FLAGS", [:Seen])
      imap.fetch(1, "BODY[]")
      imap.append("INBOX", "hello")
      imap.create("Archive")
      imap.copy(1, "Archive")
      imap.close

      sent = transport.commands.join
      assert_match(/SELECT/, sent)
      assert_match(/STORE 1 \+FLAGS/i, sent)
      assert_match(/FETCH 1 BODY\[\]/i, sent)
      assert_match(/APPEND INBOX/, sent)
      assert_match(/CREATE Archive/, sent)
      assert_match(/COPY 1 Archive/, sent)
      assert_match(/CLOSE/, sent)
    end
  end

end
