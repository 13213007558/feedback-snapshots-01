# frozen_string_literal: true

require "tmpdir"

require_relative "../../lib/helper"

# Security-focused structured generative tests: untrusted search terms,
# mailbox names, and APPEND message content must never be able to alter IMAP
# command boundaries on the wire, no matter which control characters or
# protocol-looking bytes they contain.
#
# Instead of only asserting that "quoting was used", these tests verify the
# actual bytes written to the socket.  An independent, minimal command reader
# (MiniCommandReader) re-parses everything the client sends and checks the
# argument count and the raw bytes of every command.  The server double
# (RecordingServer) only records the protocol; it does not perform any
# mailbox operations.
#
# The client and server talk over a UNIX socketpair (no TCP listener), so
# these tests also run in sandboxes that forbid binding local ports.
class IMAPCommandInjectionTest < Net::IMAP::TestCase

  # A Net::IMAP client connected over an injected socket instead of TCP.
  class SocketpairIMAP < Net::IMAP
    def initialize(sock, **config)
      @injected_sock = sock
      super("socketpair.invalid", **config)
    end

    private

    def tcp_socket(*) = @injected_sock
  end

  # An independent, minimal IMAP command reader.  It exists to cross-check
  # net-imap's command encoder: every byte the client writes is re-parsed
  # here, strictly, into (tag, name, args, raw).  Any desynchronization of
  # command boundaries (e.g. an unescaped CRLF) raises ParseError or
  # desyncs the following command, which the tests detect.
  class MiniCommandReader
    ParseError = Class.new(StandardError)

    # Raised when the server policy rejects a synchronizing literal.  Carries
    # the raw bytes of the partially received command, so tests can verify
    # that the client stopped sending (the literal content must be absent).
    class LiteralRejected < StandardError
      attr_reader :raw

      def initialize(raw)
        @raw = raw
        super("literal rejected after: %p" % [raw])
      end
    end

    Command = Data.define(:tag, :name, :args, :raw)

    def initialize(io, &literal_policy)
      @io = io
      @literal_policy = literal_policy || ->(_prefix, _size) { true }
    end

    def read_command
      @raw = +"".b
      @peeked = nil
      tag = read_atom
      raise EOFError, "connection closed" if tag.nil?
      expect(" ")
      name = read_atom or raise ParseError, "missing command name"
      args = []
      until peek == "\r"
        expect(" ")
        args << read_arg
      end
      expect("\r\n")
      Command[tag, name, args, @raw]
    end

    private

    def peek
      @peeked ||= @io.getbyte&.chr(Encoding::BINARY)
    end

    def take
      byte = @peeked || @io.getbyte&.chr(Encoding::BINARY)
      @peeked = nil
      raise ParseError, "unexpected EOF inside command" if byte.nil?
      @raw << byte
      byte
    end

    def expect(str)
      str.each_byte do |expected|
        got = take
        got == expected.chr(Encoding::BINARY) or
          raise ParseError, "expected %p, got %p (raw so far: %p)" % [
            str, got, @raw
          ]
      end
    end

    def read_atom
      atom = +""
      while (byte = peek) && ![" ", "\r", "(", ")"].include?(byte)
        atom << take
      end
      atom.empty? ? nil : atom
    end

    def read_arg
      case peek
      when "("  then read_list
      when "\"" then read_quoted
      when "~"  then read_literal(binary: true)
      when "{"  then read_literal(binary: false)
      else
        read_atom or raise ParseError, "missing argument"
      end
    end

    def read_list
      expect("(")
      items = []
      until peek == ")"
        expect(" ") unless items.empty?
        items << read_arg
      end
      expect(")")
      items
    end

    def read_quoted
      expect("\"")
      decoded = +""
      loop do
        case (byte = take)
        when "\""      then return decoded
        when "\\"      then decoded << take # quoted-special
        when "\r", "\n"
          raise ParseError, "bare CR/LF inside quoted string"
        else decoded << byte
        end
      end
    end

    def read_literal(binary:)
      expect("~") if binary
      expect("{")
      digits = +""
      digits << take while peek&.match?(/\d/)
      non_sync = peek == "+" && take
      expect("}")
      expect("\r\n")
      size = Integer(digits, 10)
      if !non_sync && !@literal_policy.call(@raw.dup, size)
        raise LiteralRejected, @raw.dup
      elsif !non_sync
        @io.print("+ Ready for literal data\r\n")
      end
      content = @io.read(size)
      content&.bytesize == size or
        raise ParseError, "EOF inside %d byte literal" % size
      @raw << content
      content
    end
  end

  # A recording-only server double.  It speaks just enough IMAP for the
  # client to proceed (greeting, continuations, tagged OK), records every
  # command with its raw bytes, and performs no mailbox operations at all.
  class RecordingServer
    attr_reader :commands, :aborted, :errors

    def initialize(sock, capabilities: %w[IMAP4rev1], literal_policy: nil)
      @sock = sock
      @capabilities = capabilities
      @reader = MiniCommandReader.new(sock, &literal_policy)
      @commands = Queue.new
      @aborted  = Queue.new # partial raw bytes of literal-rejected commands
      @errors   = Queue.new
    end

    def run
      @sock.print("* OK [CAPABILITY %s] recording-only server\r\n" % [
        @capabilities.join(" ")
      ])
      loop do
        command = @reader.read_command
        @commands << command
        case command.name.upcase
        when "LOGOUT"
          @sock.print("* BYE recording server logging out\r\n")
          @sock.print("#{command.tag} OK LOGOUT completed\r\n")
          break
        when "SEARCH", "UID"
          @sock.print("* SEARCH\r\n")
          @sock.print("#{command.tag} OK #{command.name} completed\r\n")
        when "ENABLE"
          @sock.print("* ENABLED %s\r\n" % [command.args.join(" ")])
          @sock.print("#{command.tag} OK ENABLE completed\r\n")
        else
          @sock.print("#{command.tag} OK #{command.name} completed\r\n")
        end
      end
    rescue MiniCommandReader::LiteralRejected => rejected
      @aborted << rejected.raw
      tag = rejected.raw.split(" ", 2).first
      @sock.print("#{tag} NO literal rejected by server policy\r\n")
      retry
    rescue EOFError, IOError, SystemCallError
      # client went away
    rescue MiniCommandReader::ParseError => error
      @errors << error
    end
  end

  # -- structured generation -------------------------------------------------

  # Fragments chosen to stress command boundaries: protocol markers, control
  # characters, quoting characters, literal framings, tag lookalikes, and
  # multibyte/invalid byte sequences.
  FRAGMENTS = [
    "plain", "INBOX", " ", "  ", "\t",
    "\"", "\\", "\\\"", "\"\"", "\\\\",
    "\r", "\n", "\r\n", "\r\n\r\n",
    "{", "}", "{0}", "{5}", "{3}\r\n", "~{2}", "{7+}\r\n",
    "(", ")", "[", "]", "%", "*",
    "\x01", "\x1f", "\x7f",
    "\x80".b, "\xff".b, "\xc3".b, "\xc3\xa9",
    "αβγ", "邮箱", "📧",
    "a1 OK injected", "RUBY0001 NO bad", "RUBY0002 BAD x",
    "* OK fake-untagged", "* BYE fake", "+ fake-continuation",
    "NIL", "OK", "\r\nRUBY0001 OK smuggled\r\n",
  ].freeze

  def generate_untrusted_string(rng, max_fragments: 6)
    fragments = Array.new(rng.rand(0..max_fragments)) do
      FRAGMENTS[rng.rand(FRAGMENTS.size)]
    end
    string = fragments.map(&:b).join
    string.force_encoding([Encoding::UTF_8, Encoding::BINARY,
                           Encoding::US_ASCII][rng.rand(3)])
    string
  end

  # Mirrors the documented encoding rules of Net::IMAP's send_string_data,
  # so tests can assert the *exact* expected bytes for each argument.
  ASTRING_SPECIALS = /[(){ \x00-\x1f\x7f%*"\\]/
  UNQUOTABLE_CHARS = /[\0\r\n]/

  def expected_string_wire(string, utf8:, non_sync_max:)
    if string.empty?
      '""'
    elsif string.ascii_only? && !string.match?(ASTRING_SPECIALS)
      string
    elsif text_encodable?(string, utf8:) && !string.match?(UNQUOTABLE_CHARS)
      '"%s"' % [string.gsub(/["\\]/) { "\\" + $& }]
    else
      literal_wire(string.b, non_sync_max:)
    end
  end

  def text_encodable?(string, utf8:)
    string.ascii_only? ||
      (utf8 && string.encoding == Encoding::UTF_8 && string.valid_encoding?)
  end

  def literal_wire(bytes, non_sync_max:, binary: false)
    plus = bytes.bytesize <= non_sync_max ? "+" : ""
    "%s{%d%s}\r\n%s" % [binary ? "~" : "", bytes.bytesize, plus, bytes]
  end

  def expected_arg_wire(arg, utf8:, non_sync_max:)
    case arg
    when String then expected_string_wire(arg, utf8:, non_sync_max:)
    when Array
      "(%s)" % arg.map { expected_arg_wire(_1, utf8:, non_sync_max:) }.join(" ")
    when Symbol then "\\#{arg}"
    else raise ArgumentError, "unsupported arg: %p" % [arg]
    end
  end

  # -- test harness ------------------------------------------------------------

  def with_socketpair_client(capabilities: %w[IMAP4rev1], literal_policy: nil,
                             **config)
    client_sock, server_sock = Socket.pair(:UNIX, :STREAM, 0)
    server = RecordingServer.new(server_sock, capabilities:, literal_policy:)
    @threads << Thread.new { server.run }
    client = SocketpairIMAP.new(client_sock, **config)
    # If the client ever desynchronizes the protocol (that's what these
    # tests are looking for), it may wait for a tagged response forever.
    # Fail the test instead of hanging the suite.
    Timeout.timeout(20) { yield server, client }
  ensure
    begin
      Timeout.timeout(5) { client.logout! } if client && !client.disconnected?
    rescue StandardError, Timeout::Error
      client&.disconnect
    end
    client_sock&.close
    server_sock&.close
  end

  def pop_command(server)
    Timeout.timeout(10) { server.commands.pop }
  end

  # -- targeted encoding tests -------------------------------------------------

  def test_quoted_strings_escape_exactly
    with_socketpair_client do |server, client|
      samples = [
        "", "simple-atom", "with space", "quote\"inside", "back\\slash",
        "\\\"", "specials(){} %*", "ctrl\x01\x1f\x7f", "del=\x7f",
        "a1 OK looks-like-a-tag", "* OK looks-untagged", "+ looks-like-cont",
        "{5}", "{3}\r", "NIL", "]", "[resp-specials]",
      ]
      samples.each do |sample|
        next if sample.match?(/[\r\n\0]/) # those must become literals
        client.create(sample)
        command = pop_command(server)
        assert_equal 1, command.args.size
        assert_equal sample.b, command.args.first.b
        expected = "%s CREATE %s\r\n" % [
          command.tag,
          expected_string_wire(sample, utf8: false, non_sync_max: -1)
        ]
        assert_equal expected.b, command.raw
      end
      assert server.commands.empty?
    end
  end

  def test_synchronizing_literal_waits_for_continuation
    continuations = []
    policy = ->(prefix, size) { continuations << [prefix, size]; true }
    with_socketpair_client(literal_policy: policy,
                           max_non_synchronizing_literal: -1) do |server, client|
      samples = [
        "has\rcr", "has\nlf", "has\r\ncrlf",
        "RUBY0001 OK fake tagged response\r\n",
        "line1\r\n{5}\r\nline2 looks like literal framing\r\n",
        "\xDE\xAD\xBE\xEF".b,
      ]
      samples.each do |sample|
        client.create(sample)
        command = pop_command(server)
        assert_equal 1, command.args.size
        assert_equal sample.b, command.args.first.b
        expected = "%s CREATE {%d}\r\n%s\r\n" % [
          command.tag, sample.bytesize, sample.b
        ]
        assert_equal expected.b, command.raw
      end
      # every literal was synchronizing: the server was asked first
      assert_equal samples.size, continuations.size
      continuations.each_with_index do |(prefix, size), i|
        assert_equal samples[i].bytesize, size
        assert_match(/\A\w+ CREATE \{\d+\}\r\n\z/n, prefix)
      end
    end
  end

  def test_literal_plus_non_synchronizing
    with_socketpair_client(capabilities: %w[IMAP4rev1 LITERAL+],
                           max_non_synchronizing_literal: 16) do |server, client|
      small = "ab\r\ncd" # 6 bytes, fits LITERAL+ window
      client.create(small)
      command = pop_command(server)
      assert_equal "%s CREATE {6+}\r\n%s\r\n".b % [command.tag, small.b],
                   command.raw
      assert_equal small.b, command.args.first.b

      large = "x\r\n" * 10 # 30 bytes, exceeds the 16 byte window
      client.create(large)
      command = pop_command(server)
      assert_equal "%s CREATE {30}\r\n%s\r\n".b % [command.tag, large.b],
                   command.raw
      assert_equal large.b, command.args.first.b
    end
  end

  def test_multibyte_literal_lengths_count_bytes
    with_socketpair_client(max_non_synchronizing_literal: -1) do |server, client|
      samples = ["αβγδε", "邮箱📧", "é\r\nü", "\xc3\xa9".b]
      samples.each do |sample|
        client.create(sample)
        command = pop_command(server)
        assert_equal sample.b, command.args.first.b
        expected = "%s CREATE {%d}\r\n%s\r\n" % [
          command.tag, sample.bytesize, sample.b
        ]
        assert_equal expected.b, command.raw
        # the length prefix counts bytes, not characters
        assert_includes command.raw, "{%d}\r\n" % [sample.bytesize]
      end
    end
  end

  def test_quoted_utf8_after_enable
    with_socketpair_client(capabilities: %w[IMAP4rev1 ENABLE UTF8=ACCEPT],
                           max_non_synchronizing_literal: -1) do |server, client|
      client.enable(:utf8)
      pop_command(server)
      assert client.utf8_enabled?

      sample = "邮箱📧"
      client.create(sample)
      command = pop_command(server)
      assert_equal '"邮箱📧"'.b, command.raw[/(?<=\s)"[^"]*"(?=\r\n\z)/]
      assert_equal sample, command.args.first.force_encoding(Encoding::UTF_8)
      expected = "%s CREATE \"邮箱📧\"\r\n" % [command.tag]
      assert_equal expected, command.raw.force_encoding(Encoding::UTF_8)
    end
  end

  def test_nested_lists_preserve_structure_and_boundaries
    with_socketpair_client(max_non_synchronizing_literal: -1) do |server, client|
      args = ["OR",
              ["FROM", "untrusted\r\n{4}\r\nfake"],
              ["NOT", ["SUBJECT", "quote\"and\\slash", "plain"]],
              :Seen]
      client.__send__(:send_command, "TEST", *args)
      command = pop_command(server)
      expected_args_wire = args.map {
        expected_arg_wire(_1, utf8: false, non_sync_max: -1)
      }.join(" ")
      assert_equal "%s TEST %s\r\n".b % [command.tag, expected_args_wire],
                   command.raw
      # the independent reader reconstructs the identical tree
      assert_equal ["OR",
                    ["FROM", "untrusted\r\n{4}\r\nfake".b],
                    ["NOT", ["SUBJECT", "quote\"and\\slash".b, "plain"]],
                    "\\Seen"],
                   command.args
    end
  end

  def test_append_content_with_crlf_and_tag_lookalikes_is_verbatim
    with_socketpair_client(max_non_synchronizing_literal: -1) do |server, client|
      messages = [
        "Subject: hi\r\n\r\nRUBY0001 OK injected\r\n{3}\r\nend\r\n",
        "* BYE fake logout\r\n+ fake continuation\r\n",
        "null\x00byte inside",
        "multibyte 邮箱📧\r\nbody",
      ]
      messages.each do |message|
        client.append("INBOX", message)
        command = pop_command(server)
        assert_equal 2, command.args.size
        assert_equal "INBOX", command.args[0]
        assert_equal message.b, command.args[1].b
        binary = message.include?("\0")
        expected = "%s APPEND INBOX %s\r\n" % [
          command.tag, literal_wire(message.b, non_sync_max: -1, binary:)
        ]
        assert_equal expected.b, command.raw
      end
      # every message arrived as exactly one command; the tag-lookalike and
      # marker-lookalike content did not create extra commands
      assert server.commands.empty?
    end
  end

  def test_rejected_continuation_stops_literal_and_later_args
    policy = ->(_prefix, _size) { false } # reject every synchronizing literal
    with_socketpair_client(literal_policy: policy,
                           max_non_synchronizing_literal: -1) do |server, client|
      secret  = "SECRET-BODY-MUST-NOT-LEAK\r\n"
      later   = "LATER-ARG-MUST-NOT-BE-SENT\r\n"
      assert_raise(Net::IMAP::NoResponseError) do
        client.search(["SUBJECT", secret, "TEXT", later])
      end
      partial = Timeout.timeout(10) { server.aborted.pop }
      # the client stopped at the literal boundary: no content, no later args
      assert_equal "RUBY0001 SEARCH SUBJECT {%d}\r\n".b % secret.bytesize,
                   partial
      refute_includes partial, "SECRET"
      refute_includes partial, "LATER"
      assert server.commands.empty?

      # the connection is still usable and the next command is well-formed
      client.noop
      command = pop_command(server)
      assert_equal "NOOP", command.name
      assert_equal "RUBY0002 NOOP\r\n".b, command.raw
    end
  end

  def test_raw_data_is_caller_trusted_but_strings_are_not
    with_socketpair_client(max_non_synchronizing_literal: -1) do |server, client|
      # A plain string is always safely encoded: the literal-looking text
      # becomes literal *content*, and the wire bytes stay length-delimited.
      client.create("{5}\r\nhello")
      command = pop_command(server)
      assert_equal "%s CREATE {10}\r\n{5}\r\nhello\r\n".b % command.tag,
                   command.raw
      assert_equal "{5}\r\nhello".b, command.args.first.b

      # RawData is sent verbatim: it can express multiple atoms and raw
      # literals.  This is a deliberate trust boundary -- callers who pass
      # RawData are responsible for what it contains.
      client.__send__(:send_command, "TEST", Net::IMAP::RawData.new("1 2 3"))
      command = pop_command(server)
      assert_equal "%s TEST 1 2 3\r\n".b % command.tag, command.raw
      assert_equal 3, command.args.size # one arg became three on the wire

      client.__send__(:send_command, "TEST",
                      Net::IMAP::RawData.new("{5}\r\nhello"))
      command = pop_command(server)
      assert_equal "%s TEST {5}\r\nhello\r\n".b % command.tag, command.raw
      assert_equal ["hello"], command.args

      # ...but RawData still validates: no NUL, no bare CR/LF, no dangling
      # literal prefix, and no truncated literals.
      [
        "with \0 NULL",
        "with \r\n bare CRLF",
        "{1234}\r\nliteral is too small",
        "dangling literal prefix {3}\r\n",
      ].each do |data|
        assert_raise(Net::IMAP::DataFormatError) do
          client.__send__(:send_command, "TEST", Net::IMAP::RawData.new(data))
        end
      end
      assert server.commands.empty?
    end
  end

  # -- structured generative (fuzz) tests --------------------------------------

  def fuzz_seed
    (ENV["SEED"] || Random.new_seed).to_i
  end

  def fuzz_iterations
    (ENV["FUZZ_ITERATIONS"] || 50).to_i
  end

  def test_fuzz_untrusted_data_cannot_break_command_boundaries
    seed = fuzz_seed
    $stderr.puts "#{self.class} fuzz seed: #{seed} " \
                 "(reproduce with SEED=#{seed})"
    rng = Random.new(seed)
    fuzz_iterations.times do |iteration|
      mailbox = generate_untrusted_string(rng)
      term    = generate_untrusted_string(rng)
      message = generate_untrusted_string(rng, max_fragments: 12)
      begin
        run_boundary_trial(mailbox:, term:, message:)
      rescue Exception => error # rubocop:disable Lint/RescueException
        minimal = shrink_counterexample(mailbox:, term:, message:)
        file = save_counterexample(seed:, iteration:, **minimal, error:)
        flunk "command boundary violation (seed=#{seed} " \
              "iteration=#{iteration}): #{error.class}: #{error.message}\n" \
              "minimal counterexample saved to #{file}\n" \
              "mailbox=%p term=%p message=%p" % minimal.values_at(
                :mailbox, :term, :message
              )
      end
    end
  end

  # One fuzz trial: send the untrusted values as a mailbox name, a search
  # term, and an APPEND message over a fresh connection, verifying the exact
  # wire bytes and the decoded round-trip of every argument.
  def run_boundary_trial(mailbox:, term:, message:)
    # A broken encoder can desynchronize the protocol and leave the client
    # waiting for a tagged response forever; fail the trial instead.
    Timeout.timeout(5) do
      with_socketpair_client(capabilities: %w[IMAP4rev1 LITERAL+],
                             max_non_synchronizing_literal: 64) do |server, client|
      # 1. mailbox name (CREATE)
      if mailbox.include?("\0")
        assert_raise(Net::IMAP::DataFormatError) { client.create(mailbox) }
      else
        client.create(mailbox)
        command = pop_command(server)
        assert_equal 1, command.args.size
        assert_equal mailbox.b, command.args.first.b
        expected = "%s CREATE %s\r\n" % [
          command.tag,
          expected_string_wire(mailbox, utf8: false, non_sync_max: 64)
        ]
        assert_equal expected.b, command.raw
      end

      # 2. search term (SEARCH SUBJECT <term>)
      if term.include?("\0")
        assert_raise(Net::IMAP::DataFormatError) do
          client.search(["SUBJECT", term])
        end
      else
        client.search(["SUBJECT", term])
        command = pop_command(server)
        assert_equal 2, command.args.size
        assert_equal "SUBJECT", command.args[0]
        assert_equal term.b, command.args[1].b
        expected = "%s SEARCH SUBJECT %s\r\n" % [
          command.tag,
          expected_string_wire(term, utf8: false, non_sync_max: 64)
        ]
        assert_equal expected.b, command.raw
      end

      # 3. APPEND message content (NUL bytes allowed, via literal8)
      client.append("INBOX", message)
      command = pop_command(server)
      assert_equal 2, command.args.size
      assert_equal "INBOX", command.args[0]
      assert_equal message.b, command.args[1].b
      expected = "%s APPEND INBOX %s\r\n" % [
        command.tag,
        literal_wire(message.b, non_sync_max: 64,
                     binary: message.include?("\0"))
      ]
      assert_equal expected.b, command.raw

      # exactly three commands arrived; nothing was injected between them
      assert server.commands.empty?
      assert server.errors.empty?
      end
    end
  end

  # Shrinks failing inputs by deleting chunks, re-running each candidate on
  # a fresh connection, keeping only candidates that still fail.
  def shrink_counterexample(mailbox:, term:, message:)
    inputs = {mailbox:, term:, message:}
    inputs.to_h do |name, value|
      shrunk = value.b
      chunk = shrunk.bytesize / 2
      while chunk.positive?
        offset = 0
        while offset < shrunk.bytesize
          candidate = shrunk.byteslice(0, offset) +
                      (shrunk.byteslice(offset + chunk..) || +"")
          if candidate.bytesize < shrunk.bytesize &&
             trial_fails?(**inputs.merge(name => candidate))
            shrunk = candidate
          else
            offset += chunk
          end
        end
        chunk /= 2
      end
      [name, shrunk]
    end
  end

  def trial_fails?(**inputs)
    run_boundary_trial(**inputs)
    false
  rescue Exception # rubocop:disable Lint/RescueException
    true
  end

  def save_counterexample(seed:, iteration:, error:, **inputs)
    dir = ENV["NET_IMAP_COUNTEREXAMPLE_DIR"] ||
          Dir.mktmpdir("net-imap-counterexample")
    file = File.join(dir, "counterexample-seed#{seed}-iter#{iteration}.txt")
    File.write(file, <<~TEXT)
      seed: #{seed} (reproduce with SEED=#{seed})
      iteration: #{iteration}
      error: #{error.class}: #{error.message}
      #{inputs.map { |name, value| "#{name}: #{value.inspect}" }.join("\n")}
    TEXT
    file
  end

end
