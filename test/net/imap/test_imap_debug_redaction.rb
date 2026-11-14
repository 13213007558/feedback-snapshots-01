# frozen_string_literal: true

require "net/imap"
require "stringio"
require "base64"
require "delegate"
require "test/unit"

# These integration tests drive a real Net::IMAP client against a minimal
# scripted peer over a UNIX socket pair.  A socket pair is used because the
# test environment forbids binding to a local TCP port; it is byte-stream
# compatible with the TCP sockets Net::IMAP uses in production.
class IMAPDebugRedactionTest < Net::IMAP::TestCase

  PASSWORD   = "fake-login-password-4f8a"
  OAUTH      = "fake-oauth-bearer-token-9d2c"
  BODY       = "Subject: fake\r\n\r\nfake-body-secret-3b7e\r\n"

  # The OAUTHBEARER initial response wraps the token in an SASL string which is
  # then base64 encoded on the wire.  Both forms must stay out of safe logs.
  OAUTH_SASL  = "n,,\x01auth=Bearer #{OAUTH}\x01\x01"
  OAUTH_B64   = [OAUTH_SASL].pack("m0")

  # Yields [imap, debug_io, wire_io] connected to a scripted IMAP peer.
  def connected_client(debug_mode)
    client_io, server_io = Socket.pair(:UNIX, :STREAM)
    wire = StringIO.new
    server = Thread.new do
      yield_script(server_io, wire)
    rescue => error
      @server_error = error
    end
    debug_io = StringIO.new
    # The tee records every raw byte the client receives from the peer, proving
    # redaction only affects logging, never the bytes on the connection.
    tee = TeeIO.new(client_io, wire)
    klass = Class.new(Net::IMAP) do
      define_method(:tcp_socket) { |_host, _port| tee }
    end
    imap = klass.new("localhost", debug: true, debug_mode: debug_mode)
    imap.instance_variable_get(:@debug_logger)
      .instance_variable_set(:@output, debug_io)
    [imap, debug_io, wire, server, client_io, server_io]
  end

  def shutdown(imap, server, *ios)
    imap.logout
  rescue IOError, EOFError, Errno::ENOTCONN
  ensure
    server.join(2)
    ios.each { |io| io.close unless io.closed? }
  end

  # Scripted peer: greeting, an optional CAPABILITY probe, LOGIN,
  # OAUTHBEARER (failure), PLAIN (no IR), FETCH with a multi-line body
  # literal, LOGOUT.  Tags are parsed from each command so the peer does not
  # depend on the client's tag numbering.
  def yield_script(io, wire)
    capabilities = "IMAP4rev1 SASL-IR AUTH=PLAIN AUTH=OAUTHBEARER"
    io.print "* OK [CAPABILITY #{capabilities}] ready\r\n"

    while (line = read_frame(io, wire))
      tag = line[/\A(\S+)/, 1]
      case line
      when /\sCAPABILITY\b/
        io.print "* CAPABILITY #{capabilities}\r\n#{tag} OK CAPABILITY done\r\n"
      when /\sLOGIN\b/
        io.print "#{tag} OK LOGIN completed\r\n"
      when /\sOAUTHBEARER\b/
        io.print "#{tag} NO [AUTHENTICATIONFAILED] " \
                 "do not LOGIN with a bad token\r\n"
      when /\sAUTHENTICATE PLAIN\b/
        io.print "+ \r\n" # empty server challenge
        read_frame(io, wire) # client continuation response
        io.print "#{tag} OK authenticated\r\n"
      when /\sFETCH\b/
        io.print "* 1 FETCH (BODY[] {#{BODY.bytesize}}\r\n"
        io.write BODY
        io.print ")\r\n#{tag} OK FETCH done\r\n"
      when /\sLOGOUT\b/
        io.print "* BYE logged out\r\n#{tag} OK LOGOUT completed\r\n"
        break
      end
    end
  end

  def read_frame(io, wire)
    line = io.gets("\r\n") or return nil
    wire << "C: #{line}"
    if (match = line.match(/\{(\d+)\+?\}\r\n\z/n))
      payload = io.read(Integer(match[1]))
      wire << "C: #{payload}"
    end
    line
  end

  # Delegates to a socket while teeing every byte read (server -> client)
  # into a recorder, preserving the exact byte boundaries Net::IMAP reads.
  class TeeIO < SimpleDelegator
    def initialize(io, recorder)
      super(io)
      @recorder = recorder
    end

    def gets(*args, **kwargs)
      super.tap { |data| @recorder << "S: #{data}" if data }
    end

    def read(*args, **kwargs)
      super.tap { |data| @recorder << "S: #{data}" if data }
    end
  end

  def run_exchange(debug_mode)
    imap, debug_io, wire, server, *ios = connected_client(debug_mode) { }
    imap.login("alice", PASSWORD)
    assert_raise(Net::IMAP::NoResponseError) do
      imap.authenticate("OAUTHBEARER", OAUTH)
    end
    imap.authenticate("PLAIN", "alice", PASSWORD, sasl_ir: false)
    imap.fetch(1, "BODY[]")
    shutdown(imap, server, *ios)
    [debug_io.string, wire.string]
  end

  test "safe mode never writes the secrets to the debug log" do
    debug, wire = run_exchange(:safe)
    refute_includes debug, PASSWORD
    refute_includes debug, OAUTH
    refute_includes debug, OAUTH_B64
    refute_includes debug, BODY
    refute_includes debug, "fake-body-secret-3b7e"
    # Structural troubleshooting data is retained.
    assert_match(/C: RUBY0001 LOGIN alice <REDACTED \d+ bytes>/, debug)
    assert_match(/AUTHENTICATE OAUTHBEARER <REDACTED \d+ bytes>/, debug)
    assert_match(/S: \+ <REDACTED 0 bytes>/, debug)
    assert_match(/BODY\[\] \{#{BODY.bytesize}\}/, debug)
    assert_match(/S: <REDACTED #{BODY.bytesize} bytes>/, debug)
    assert_includes debug, "RUBY0005"
    # The pseudo-command in the failure text is emitted verbatim.
    assert_includes debug, "do not LOGIN with a bad token"
    # The actual wire bytes are untouched and still carry every secret.
    assert_includes wire, PASSWORD
    assert_includes wire, OAUTH_B64
    assert_equal OAUTH_SASL, Base64.decode64(OAUTH_B64)
    assert_includes wire, BODY
  end

  test "raw mode retains the historical verbatim output" do
    debug, wire = run_exchange(:raw)
    assert_includes debug, PASSWORD
    assert_includes debug, OAUTH_B64
    # The body is printed verbatim (line prefixes are inserted at newlines).
    assert_includes debug, "fake-body-secret-3b7e"
    # Same secrets reach the wire in both modes.
    assert_includes wire, PASSWORD
    assert_includes wire, OAUTH_B64
  end

  test "the caller can switch back to raw mode explicitly" do
    config = Net::IMAP::Config.new(debug: true)
    assert_equal :safe, config.debug_mode
    config.debug_mode = :raw
    assert_equal :raw, config.debug_mode
    assert_raise(ArgumentError) { config.debug_mode = :bogus }
  end

end
