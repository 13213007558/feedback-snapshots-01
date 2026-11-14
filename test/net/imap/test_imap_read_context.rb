# frozen_string_literal: true

require "net/imap"
require "test/unit"

class IMAPReadContextTest < Net::IMAP::TestCase

  # A minimal scriptable IMAP server, connected to the client through an
  # in-memory UNIX socketpair.  The client uses the real command path:
  # tagging, encoding, the receiver thread, and the response parser.
  class MemServer
    Command = Struct.new(:tag, :name, :args, :raw)

    attr_reader :received

    def initialize
      @client_sock, @sock = Socket.pair(:UNIX, :STREAM, 0)
      @handlers = {}
      @received = Queue.new
      @thread   = Thread.new { serve }
    end

    def thread; @thread end

    # Returns a Net::IMAP subclass instance wired to this server's socket.
    def client
      sock = @client_sock
      Class.new(Net::IMAP) do
        define_method(:tcp_socket) { |*_args| sock }
      end.new("mem.server")
    end

    def on(command, &block)
      @handlers[command] = block
    end

    # Writes raw (untagged or continuation) lines to the client.
    def write_lines(*lines)
      lines.each { @sock.write(_1 + "\r\n") }
    end

    def close
      @sock.close unless @sock.closed?
      @client_sock.close unless @client_sock.closed?
    end

    private

    def serve
      @sock.write "* OK [CAPABILITY IMAP4rev1] mem server ready\r\n"
      while (line = @sock.gets)
        raw  = line.strip
        tag, name, args = raw.split(" ", 3)
        name = name.upcase
        if name == "UID" # two-word commands, e.g. "UID FETCH"
          name, args = args.split(" ", 2)
          name = "UID #{name.upcase}"
        end
        cmd  = Command.new(tag, name, args, raw)
        @received << cmd
        handler = @handlers[cmd.name] || ->(c) {
          write_lines "#{c.tag} OK #{c.name} completed"
        }
        handler.call(cmd)
      end
    rescue IOError, SystemCallError
      nil
    end
  end

  def with_mem_server
    server = MemServer.new
    @threads << server.thread
    imap = server.client
    yield server, imap
  ensure
    imap.disconnect if imap && !imap.disconnected?
    server.close
  end

  def select_mailbox(server, imap, mailbox, uidvalidity)
    server.on("SELECT") do |cmd|
      server.write_lines(
        "* 2 EXISTS",
        "* OK [UIDVALIDITY #{uidvalidity}] UIDs valid",
        "#{cmd.tag} OK [READ-WRITE] SELECT completed"
      )
    end
    imap.select(mailbox)
    server.received.pop # consume the SELECT command
  end

  def drain_commands(server)
    cmds = []
    cmds << server.received.pop(true) until server.received.empty?
    cmds
  end

  test "read_context requires a finite, non-empty UID set" do
    with_mem_server do |server, imap|
      select_mailbox(server, imap, "INBOX", 777)
      assert_raise(ArgumentError) {
        imap.read_context("INBOX", uidvalidity: 777, uids: [])
      }
      assert_raise(ArgumentError) {
        imap.read_context("INBOX", uidvalidity: 777, uids: 1..)
      }
      assert_raise(ArgumentError) {
        imap.read_context("INBOX", uidvalidity: 777, uids: "5:*")
      }
    end
  end

  test "uid_fetch sends UID FETCH and reuses the context within one selection" do
    with_mem_server do |server, imap|
      select_mailbox(server, imap, "INBOX", 777)
      ctx = imap.read_context("INBOX", uidvalidity: 777, uids: [5, 6])
      server.on("UID FETCH") do |cmd|
        uid = cmd.args[/\A(\d+)/, 1]
        server.write_lines(
          "* 1 FETCH (UID #{uid} FLAGS (\\Seen))",
          "#{cmd.tag} OK UID FETCH completed"
        )
      end

      first  = ctx.uid_fetch(5, %w[FLAGS])
      second = ctx.uid_fetch(6, %w[FLAGS]) # same selection: reuse is allowed

      assert_equal 1, first.size
      assert_equal 5, first.first.uid
      assert_equal [:Seen], first.first.flags
      assert_equal 1, second.size
      assert_equal 6, second.first.uid
      sent = [server.received.pop.raw, server.received.pop.raw]
      assert_equal "RUBY0002 UID FETCH 5 (FLAGS)", sent[0]
      assert_equal "RUBY0003 UID FETCH 6 (FLAGS)", sent[1]
    end
  end

  test "out-of-bounds UIDs are rejected before anything is sent" do
    with_mem_server do |server, imap|
      select_mailbox(server, imap, "INBOX", 777)
      ctx = imap.read_context("INBOX", uidvalidity: 777, uids: [5, 6])
      server.on("UID FETCH") { |cmd| flunk "UID FETCH must not be sent" }

      assert_raise(Net::IMAP::ReadContextError) { ctx.uid_fetch([5, 99], "FLAGS") }
      assert_raise(Net::IMAP::ReadContextError) { ctx.uid_fetch(1..9, "FLAGS") }
      sleep 0.05 # give any (buggy) send a chance to arrive
      assert_empty drain_commands(server)
    end
  end

  test "re-SELECT of the same mailbox invalidates the old context" do
    with_mem_server do |server, imap|
      select_mailbox(server, imap, "INBOX", 777)
      ctx = imap.read_context("INBOX", uidvalidity: 777, uids: [5])
      server.on("UID FETCH") { |cmd| flunk "UID FETCH must not be sent" }

      select_mailbox(server, imap, "INBOX", 777) # same name, same UIDVALIDITY

      assert_raise(Net::IMAP::ReadContextError) { ctx.uid_fetch(5, "FLAGS") }
      sleep 0.05
      assert_empty drain_commands(server)

      # a fresh context bound to the new selection works again
      server.on("UID FETCH") do |cmd|
        server.write_lines("* 1 FETCH (UID 5 FLAGS (\\Seen))",
                           "#{cmd.tag} OK UID FETCH completed")
      end
      fresh = imap.read_context("INBOX", uidvalidity: 777, uids: [5])
      assert_equal [5], fresh.uid_fetch(5, "FLAGS").map(&:uid)
    end
  end

  test "a failed SELECT invalidates the old context" do
    with_mem_server do |server, imap|
      select_mailbox(server, imap, "INBOX", 777)
      ctx = imap.read_context("INBOX", uidvalidity: 777, uids: [5])
      server.on("UID FETCH") { |cmd| flunk "UID FETCH must not be sent" }

      server.on("SELECT") do |cmd|
        server.write_lines("#{cmd.tag} NO no such mailbox")
      end
      assert_raise(Net::IMAP::NoResponseError) { imap.select("Nope") }
      server.received.pop # consume the failed SELECT

      assert_raise(Net::IMAP::ReadContextError) { ctx.uid_fetch(5, "FLAGS") }
      sleep 0.05
      assert_empty drain_commands(server)
    end
  end

  test "an unsolicited CLOSED response invalidates the context" do
    with_mem_server do |server, imap|
      select_mailbox(server, imap, "INBOX", 777)
      ctx = imap.read_context("INBOX", uidvalidity: 777, uids: [5])
      server.on("UID FETCH") { |cmd| flunk "UID FETCH must not be sent" }

      server.write_lines("* OK [CLOSED] mailbox closed by another session")
      imap.noop # round-trip: guarantees the CLOSED line was processed
      server.received.pop # consume the NOOP

      assert_raise(Net::IMAP::ReadContextError) { ctx.uid_fetch(5, "FLAGS") }
      sleep 0.05
      assert_empty drain_commands(server)
    end
  end

  test "a UIDVALIDITY change invalidates the context" do
    with_mem_server do |server, imap|
      select_mailbox(server, imap, "INBOX", 777)
      ctx = imap.read_context("INBOX", uidvalidity: 777, uids: [5])
      server.on("UID FETCH") { |cmd| flunk "UID FETCH must not be sent" }

      server.write_lines("* OK [UIDVALIDITY 999] UIDs have been reassigned")
      imap.noop
      server.received.pop # consume the NOOP

      assert_raise(Net::IMAP::ReadContextError) { ctx.uid_fetch(5, "FLAGS") }
      sleep 0.05
      assert_empty drain_commands(server)
    end
  end

  test "two mailboxes reusing the same UID cannot share a context" do
    with_mem_server do |server, imap|
      select_mailbox(server, imap, "INBOX", 111)
      inbox_ctx = imap.read_context("INBOX", uidvalidity: 111, uids: [5])

      # another request switches the connection to a different mailbox,
      # which happens to use the same UID 5 for different content
      select_mailbox(server, imap, "Archive", 222)

      # the INBOX permit can neither read Archive's UID 5 nor send anything
      assert_raise(Net::IMAP::ReadContextError) {
        inbox_ctx.uid_fetch(5, %w[FLAGS BODY.PEEK[]])
      }
      sleep 0.05
      assert_empty drain_commands(server)

      # a permit for Archive reads Archive's UID 5 content, not INBOX's
      server.on("UID FETCH") do |cmd|
        server.write_lines(
          "* 1 FETCH (UID 5 BODY[] {13}",
          "archive-body!)", # 13 literal bytes, immediately followed by ")"
          "#{cmd.tag} OK UID FETCH completed"
        )
      end
      archive_ctx = imap.read_context("Archive", uidvalidity: 222, uids: [5])
      fetched = archive_ctx.uid_fetch(5, %w[BODY.PEEK[]])
      assert_equal 1, fetched.size
      assert_equal 5, fetched.first.uid
      assert_equal "archive-body!", fetched.first.attr["BODY[]"]

      # and the stale INBOX permit is still unusable afterwards
      assert_raise(Net::IMAP::ReadContextError) { inbox_ctx.uid_fetch(5, "FLAGS") }
    end
  end

  test "piggybacked FETCH results are never returned as authorized content" do
    with_mem_server do |server, imap|
      select_mailbox(server, imap, "INBOX", 777)
      ctx = imap.read_context("INBOX", uidvalidity: 777, uids: [5])
      server.on("UID FETCH") do |cmd|
        server.write_lines(
          "* 1 FETCH (UID 5 FLAGS (\\Seen))",
          "* 2 FETCH (UID 6 FLAGS (\\Deleted))", # UID outside the grant
          "* 3 FETCH (FLAGS (\\Recent))",        # no UID at all
          "#{cmd.tag} OK UID FETCH completed"
        )
      end

      fetched = ctx.uid_fetch(5, %w[FLAGS])
      assert_equal 1, fetched.size
      assert_equal 5, fetched.first.uid
      assert_equal [:Seen], fetched.first.flags
    end
  end

  test "a mailbox switch cannot slip between the check and the send" do
    with_mem_server do |server, imap|
      select_mailbox(server, imap, "INBOX", 111)
      ctx = imap.read_context("INBOX", uidvalidity: 111, uids: [5])
      server.on("UID FETCH") { |cmd| flunk "UID FETCH must not be sent" }

      # Hold the connection lock, then block a fetcher thread on it.  The
      # re-SELECT below (reentrant on this thread) bumps the selection
      # generation before the fetcher can run its check: the fetcher must
      # raise ReadContextError rather than send UID FETCH to "Archive".
      server.on("SELECT") do |cmd|
        server.write_lines(
          "* 1 EXISTS",
          "* OK [UIDVALIDITY 222] UIDs valid",
          "#{cmd.tag} OK [READ-WRITE] SELECT completed"
        )
      end
      error = imap.instance_exec do
        synchronize do
          fetcher = Thread.new {
            begin
              ctx.uid_fetch(5, "FLAGS")
              nil
            rescue Net::IMAP::ReadContextError => e
              e
            end
          }
          sleep 0.01 until fetcher.stop? # fetcher is blocked on the lock
          imap.select("Archive")
          fetcher.value
        end
      end

      assert_instance_of Net::IMAP::ReadContextError, error
      server.received.pop # consume the SELECT
      sleep 0.05
      assert_empty drain_commands(server)
    end
  end

end
