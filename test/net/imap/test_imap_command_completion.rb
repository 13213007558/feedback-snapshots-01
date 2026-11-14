# frozen_string_literal: true

require "delegate"

require_relative "../../lib/helper"

# Short-sequence state tests for the send_command / finish_sending_command /
# get_tagged_response pipeline.
#
# IMAP tags are predictable, so a malicious server can guess the tag of the
# next command and send a tagged OK before the client has finished sending
# that command.  These tests verify that:
#
# * a command only succeeds when its tagged OK belongs to a command that was
#   completely sent (finish_sending_command rejects a premature OK), and
# * stale or foreign tagged responses (duplicate tags, unknown tags, a late
#   OK after NO/BAD) are never attributed to a later command's caller, and
# * rejected sequences never leave a caller thread hanging, and
# * legitimately interleaved commands still each complete by their own tag.
#
# Every test records three logs: send progress (PausableSocket#sent_data),
# response attribution (a response handler queue), and caller results (what
# each send_command call returned or raised).  Shuffles use a fixed SEED so
# response ordering is deterministic.
#
# NOTE: artificially removing the premature-completion guard in
# Net::IMAP#finish_sending_command must make these tests fail, while the
# legitimate interleaving test must keep passing.
class IMAPCommandCompletionTest < Net::IMAP::TestCase
  include Net::IMAP::TestCase::SimpleTCPServerHelper

  # Fixed seed for deterministic response ordering.
  SEED = 20261114

  # Wraps the client socket to record every write ("send progress") and to
  # pause selected writes until the test releases them.
  class PausableSocket < SimpleDelegator
    def initialize(io)
      super
      @sent  = []
      @gates = {}
      @mutex = Thread::Mutex.new
    end

    # The next #print matching +pattern+ blocks until Gate#release is called.
    def pause_on(pattern)
      gate = Gate.new
      @mutex.synchronize { @gates[gate] = pattern }
      gate
    end

    def print(str)
      gate = @mutex.synchronize do
        found = @gates.find { |_gate, pattern| pattern === str }
        @gates.delete(found.first) if found
        found&.first
      end
      gate&.pause
      __getobj__.print(str)
      @mutex.synchronize { @sent << str }
    end

    # Each individual write, in order.
    def sent = @mutex.synchronize { @sent.dup }

    # Everything written so far, as one string.
    def sent_data = @mutex.synchronize { @sent.join }

    class Gate
      def initialize
        @paused   = Thread::Queue.new
        @released = Thread::Queue.new
      end

      def pause
        @paused << true
        @released.pop
      end

      def wait_paused = @paused.pop
      def release     = @released << true
    end
  end

  test "premature tagged OK is rejected before the command is fully sent" do
    server_to_client = Queue.new
    client_to_server = Queue.new
    with_scripted_server(->(sock) {
      client_to_server.pop # wait until the client is ready
      sock.print("RUBY0001 OK forged early\r\n")
      server_to_client << :forged_ok_sent
      sock.gets # wait for the client to disconnect
    }) do |imap, pausable|
      arrivals = tagged_response_arrivals(imap)
      client_to_server << :inject
      assert_equal :forged_ok_sent, server_to_client.pop
      forged = arrivals.pop # proves the forged OK was stored
      assert_equal "RUBY0001", forged.tag
      assert_equal "OK",       forged.name

      # Pause the client before the first byte of the command, proving that
      # nothing of the command was sent while its OK was already waiting.
      gate = pausable.pause_on(/\ARUBY0001 /)
      result = nil
      caller_thread = Thread.new do
        result = begin
          imap.noop
        rescue Exception => error
          error
        end
      end
      @threads << caller_thread
      gate.wait_paused
      assert_equal "", pausable.sent_data
      gate.release
      caller_thread.join

      assert_instance_of Net::IMAP::InvalidTaggedResponseError, result
      assert_equal :incomplete, result.state
      assert imap.disconnected?
      # the command was never completely sent, so it must not succeed
      assert_equal "RUBY0001 NOOP", pausable.sent_data
    end
  end

  test "tagged response reusing an old tag is not attributed to the next command" do
    with_scripted_server(->(sock) {
      if (line = sock.gets)
        sock.print("#{line.split.first} OK first\r\n")
      end
      if sock.gets
        sock.print("RUBY0001 OK duplicate, too late\r\n")
        sock.print("RUBY0002 OK second\r\n")
      end
      sock.gets # wait for the client to disconnect
    }) do |imap, pausable|
      arrivals = tagged_response_arrivals(imap)
      first  = imap.noop
      second = imap.noop
      assert_equal "RUBY0001", first.tag
      assert_equal "first",    first.data.text
      # the duplicate OK for the old tag must not become this command's result
      assert_equal "RUBY0002", second.tag
      assert_equal "second",   second.data.text
      # the duplicate arrived (attribution log) but reached no caller
      assert_equal %w[RUBY0001 RUBY0001 RUBY0002],
                   [arrivals.pop.tag, arrivals.pop.tag, arrivals.pop.tag]
      assert_equal "RUBY0001 NOOP\r\nRUBY0002 NOOP\r\n", pausable.sent_data
    end
  end

  test "tagged response with an unknown tag is ignored by later commands" do
    server_to_client = Queue.new
    client_to_server = Queue.new
    with_scripted_server(->(sock) {
      client_to_server.pop # wait until the client is ready
      sock.print("RUBY9999 OK unknown tag\r\n")
      server_to_client << :unknown_sent
      while (line = sock.gets)
        sock.print("#{line.split.first} OK real reply\r\n")
      end
    }) do |imap, pausable|
      arrivals = tagged_response_arrivals(imap)
      client_to_server << :inject
      assert_equal :unknown_sent, server_to_client.pop
      unknown = arrivals.pop # proves the unknown response was stored
      assert_equal "RUBY9999", unknown.tag

      resp = imap.noop
      assert_equal "RUBY0001",   resp.tag
      assert_equal "real reply", resp.data.text
      assert_equal "RUBY0001 NOOP\r\n", pausable.sent_data
    end
  end

  test "tagged OK while waiting for a literal continuation is not a success" do
    with_scripted_server(->(sock) {
      if (line = sock.gets) # "RUBY0001 TEST {8}"
        sock.print("#{line.split.first} OK forged instead of continuation\r\n")
      end
      while (line = sock.gets)
        sock.print("#{line.split.first} OK real reply\r\n")
      end
    }) do |imap, pausable|
      arrivals = tagged_response_arrivals(imap)
      # the caller is not left hanging, and is not told the command succeeded
      error = assert_raise(Net::IMAP::ResponseError) do
        imap.__send__(:send_command, "TEST", "lit\neral")
      end
      assert_equal "RUBY0001", error.response.tag
      forged = arrivals.pop
      assert_equal "RUBY0001", forged.tag
      # the command was abandoned mid-send: the literal payload and the final
      # CRLF were never written
      assert_equal "RUBY0001 TEST {8}\r\n", pausable.sent_data
      refute_includes pausable.sent_data, "lit\neral"
      # the stored forged OK is not attributed to the next command either
      resp = imap.noop
      assert_equal "RUBY0002",   resp.tag
      assert_equal "real reply", resp.data.text
    end
  end

  data("NO"  => "NO",
       "BAD" => "BAD")
  test "late OK after NO/BAD is not attributed to the next command" do |name|
    server_to_client = Queue.new
    client_to_server = Queue.new
    with_scripted_server(->(sock) {
      if (line = sock.gets)
        tag = line.split.first
        sock.print("#{tag} #{name} rejected\r\n")
        client_to_server.pop # wait until the caller got the NO/BAD
        sock.print("#{tag} OK late duplicate\r\n")
        server_to_client << :late_ok_sent
      end
      while (line = sock.gets)
        sock.print("#{line.split.first} OK next command\r\n")
      end
    }) do |imap, pausable|
      arrivals = tagged_response_arrivals(imap)
      error_class = name == "NO" ? Net::IMAP::NoResponseError
                                 : Net::IMAP::BadResponseError
      assert_raise(error_class) { imap.noop }
      assert_equal "RUBY0001", arrivals.pop.tag

      client_to_server << :send_late_ok
      assert_equal :late_ok_sent, server_to_client.pop
      late = arrivals.pop # stored, but its command already finished
      assert_equal "RUBY0001", late.tag
      assert_equal "OK",       late.name

      resp = imap.noop
      assert_equal "RUBY0002",      resp.tag
      assert_equal "next command",  resp.data.text
      assert_equal "RUBY0001 NOOP\r\nRUBY0002 NOOP\r\n", pausable.sent_data
    end
  end

  test "interleaved commands each complete with their own tag" do
    thread_count = 8
    total        = thread_count
    rng          = Random.new(SEED) # deterministic response order
    with_scripted_server(->(sock) {
      # Each thread sends exactly one command, so every command is already
      # in flight before the first response is sent.  The server buffers
      # them all and replies in a seeded (deterministic) shuffled order.
      lines = []
      while lines.size < total && (line = sock.gets)
        lines << line
      end
      # sort first, so the seeded shuffle is fully deterministic
      lines.sort.shuffle(random: rng).each do |line|
        tag, _cmd, arg = line.chomp.split(" ")
        sock.print("#{tag} OK done-#{arg}\r\n")
      end
      sock.gets # wait for the client to disconnect
    }) do |imap, pausable|
      arrivals = tagged_response_arrivals(imap)
      results  = Thread::Queue.new
      workers  = thread_count.times.map do |t|
        Thread.new do
          arg = "cmd#{t}"
          begin
            resp = imap.__send__(:send_command, "TEST", arg)
            results << [arg, resp.tag, resp.data.text]
          rescue Exception => error
            results << [arg, :error, error]
          end
        end
      end
      workers.each(&:join)

      caller_results = total.times.map { results.pop }
      assert_empty caller_results.select { |_arg, tag, _text| tag == :error }

      # send progress: every command was completely sent (final CRLF included)
      sent_commands = pausable.sent_data.scan(/(RUBY\d{4}) TEST (cmd\d+)\r\n/)
      assert_equal total, sent_commands.size
      tag_by_arg = sent_commands.to_h { |tag, arg| [arg, tag] }

      # caller results: each success carries the tag of its own complete
      # command, and the response text the server addressed to that tag
      caller_results.each do |arg, tag, text|
        assert_equal "done-#{arg}", text
        assert_equal tag_by_arg[arg], tag
      end

      # response attribution: every sent tag got exactly one tagged response
      assert_equal tag_by_arg.values.sort,
                   total.times.map { arrivals.pop.tag }.sort
    end
  end

  private

  # Connects a client and a scripted server over a UNIXSocket.pair, with the
  # client end wrapped by PausableSocket.  The server script runs in a
  # thread.  Yields [imap, pausable].
  def with_scripted_server(server_script, timeout: 10)
    timeout *= EnvUtil.timeout_scale || 1 if defined?(EnvUtil.timeout_scale)
    client_sock, server_sock = UNIXSocket.pair
    start_server do
      begin
        server_sock.print("* OK scripted test server\r\n")
        server_script.call(server_sock)
      ensure
        server_sock.close
      end
    end
    pausable = PausableSocket.new(client_sock)
    imap = Net::IMAP.allocate
    imap.define_singleton_method(:tcp_socket) { |*| pausable }
    imap.__send__(:initialize, "localhost", port: 0)
    Timeout.timeout(timeout) { yield imap, pausable }
  ensure
    imap.disconnect if imap && !imap.disconnected?
  end

  # Returns a Queue that receives every TaggedResponse the client stores, in
  # arrival order (the "response attribution" log).  Popping a response from
  # this queue proves it has already been recorded by the receiver thread.
  def tagged_response_arrivals(imap)
    arrivals = Thread::Queue.new
    imap.add_response_handler do |resp|
      arrivals << resp if resp.is_a?(Net::IMAP::TaggedResponse)
    end
    arrivals
  end

end
