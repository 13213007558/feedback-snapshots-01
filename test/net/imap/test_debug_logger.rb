# frozen_string_literal: true

require "net/imap"
require "stringio"
require "test/unit"

class DebugLoggerTest < Net::IMAP::TestCase

  SECRET_PASSWORD = "fake-password-secret-9f3k"
  OAUTH_TOKEN     = "fake-oauth-bearer-token-7q2z"
  BODY_SECRET     = "fake-message-body-secret-5w8y"

  def new_logger(mode: :safe)
    output = StringIO.new
    config = Net::IMAP::Config.new(debug: true, debug_mode: mode)
    [output, Net::IMAP::DebugLogger.new(config, output: output)]
  end

  def feed_in_chunks(logger, string, size = 3)
    string.b.each_char.each_slice(size).map(&:join).each do |chunk|
      logger.client_write(chunk)
    end
  end

  # ----- LOGIN -------------------------------------------------------------

  test "redacts a LOGIN password sent as an atom, across chunked writes" do
    output, logger = new_logger
    feed_in_chunks(logger, "RUBY0001 LOGIN alice #{SECRET_PASSWORD}\r\n")
    logger.server_read("RUBY0001 OK LOGIN completed\r\n")
    refute_includes output.string, SECRET_PASSWORD
    assert_match(/RUBY0001 LOGIN alice <REDACTED \d+ bytes>/, output.string)
    assert_includes output.string, "C: "
    assert_includes output.string, "S: "
  end

  test "redacts a quoted LOGIN password but keeps the username" do
    output, logger = new_logger
    logger.client_write("RUBY0001 LOGIN \"alice\" \"#{SECRET_PASSWORD}\"\r\n")
    refute_includes output.string, SECRET_PASSWORD
    assert_includes output.string, '"alice"'
    assert_match(/<REDACTED \d+ bytes>/, output.string)
  end

  test "keeps a literal LOGIN username visible but hides the literal password" do
    output, logger = new_logger
    logger.client_write("RUBY0001 LOGIN {5}\r\n")
    logger.server_read("+ continue\r\n")
    logger.client_write("alice\r\n")
    logger.client_write(" {#{SECRET_PASSWORD.bytesize}}\r\n")
    logger.server_read("+ continue\r\n")
    logger.client_write("#{SECRET_PASSWORD}\r\n")
    logger.server_read("RUBY0001 OK\r\n")
    assert_includes output.string, "alice"
    refute_includes output.string, SECRET_PASSWORD
    assert_includes output.string, "{#{SECRET_PASSWORD.bytesize}}"
    assert_match(/<REDACTED #{SECRET_PASSWORD.bytesize} bytes>/, output.string)
  end

  # ----- SASL --------------------------------------------------------------

  test "redacts an OAUTHBEARER SASL-IR initial response" do
    output, logger = new_logger
    response = ["n,\x01auth=Bearer #{OAUTH_TOKEN}\x01\x01"].pack("m0")
    logger.client_write("RUBY0002 AUTHENTICATE OAUTHBEARER #{response}\r\n")
    logger.server_read("RUBY0002 NO [AUTHENTICATIONFAILED] bad token\r\n")
    refute_includes output.string, OAUTH_TOKEN
    refute_includes output.string, response
    assert_match(/AUTHENTICATE OAUTHBEARER <REDACTED \d+ bytes>/, output.string)
  end

  test "redacts a multi-step SASL challenge/response exchange in both directions" do
    output, logger = new_logger
    logger.client_write("RUBY0003 AUTHENTICATE PLAIN\r\n")
    logger.server_read("+ \r\n") # empty server challenge
    response = ["\x00alice\x00#{SECRET_PASSWORD}"].pack("m0")
    feed_in_chunks(logger, "#{response}\r\n")
    logger.server_read("RUBY0003 OK success\r\n")
    refute_includes output.string, SECRET_PASSWORD
    refute_includes output.string, response
    assert_includes output.string, "<REDACTED 0 bytes>"
    assert_match(/C: <REDACTED \d+ bytes>/, output.string)
    # the tag tying the exchange together is retained
    assert_includes output.string, "RUBY0003"
  end

  test "redacts a non-empty server SASL challenge" do
    output, logger = new_logger
    logger.client_write("RUBY0004 AUTHENTICATE SCRAM-SHA-256\r\n")
    challenge = ["server-challenge-#{OAUTH_TOKEN}"].pack("m0")
    logger.server_read("+ #{challenge}\r\n")
    logger.client_write("c2NhbQ==\r\n")
    logger.server_read("RUBY0004 OK\r\n")
    refute_includes output.string, OAUTH_TOKEN
    refute_includes output.string, challenge
    assert_match(/S: \+ <REDACTED \d+ bytes>/, output.string)
  end

  test "emits a literal continuation request verbatim when no SASL exchange is active" do
    output, logger = new_logger
    logger.client_write("RUBY0005 APPEND INBOX {5}\r\n")
    logger.server_read("+ Ready for literal data\r\n")
    assert_includes output.string, "S: + Ready for literal data\r\n"
  end

  # ----- literals / message bodies ----------------------------------------

  test "redacts a synchronizing client literal even when chunked" do
    output, logger = new_logger
    logger.client_write("RUBY0006 APPEND INBOX {#{BODY_SECRET.bytesize}}\r\n")
    logger.server_read("+ go\r\n")
    feed_in_chunks(logger, BODY_SECRET)
    logger.client_write("\r\n")
    logger.server_read("RUBY0006 OK APPEND done\r\n")
    refute_includes output.string, BODY_SECRET
    assert_includes output.string, "{#{BODY_SECRET.bytesize}}"
    assert_match(/<REDACTED #{BODY_SECRET.bytesize} bytes>/, output.string)
  end

  test "redacts a non-synchronizing LITERAL+ payload" do
    output, logger = new_logger
    logger.client_write("RUBY0007 APPEND INBOX {5+}\r\n")
    logger.client_write("#{BODY_SECRET[0, 5]}\r\n")
    refute_includes output.string, BODY_SECRET[0, 5]
    assert_match(/<REDACTED 5 bytes>/, output.string)
  end

  test "redacts a multi-line server FETCH body literal" do
    output, logger = new_logger
    body = "line one\r\nline two #{BODY_SECRET}\r\n"
    response = "* 1 FETCH (BODY[] {#{body.bytesize}}\r\n#{body})\r\n"
    logger.server_read(response)
    refute_includes output.string, BODY_SECRET
    refute_includes output.string, "line one"
    assert_includes output.string, "{#{body.bytesize}}"
    assert_match(/S: <REDACTED #{body.bytesize} bytes>/, output.string)
    assert_includes output.string, "S: )\r\n"
  end

  test "handles a zero-length literal" do
    output, logger = new_logger
    logger.client_write("RUBY0008 APPEND INBOX {0}\r\n")
    logger.server_read("RUBY0008 OK\r\n")
    assert_includes output.string, "{0}"
    assert_includes output.string, "<REDACTED 0 bytes>"
  end

  # ----- protocol correctness ---------------------------------------------

  test "never interprets pseudo-command text inside a server response" do
    output, logger = new_logger
    decoy = "RUBY9999 LOGIN hacker #{SECRET_PASSWORD}"
    logger.server_read("* NO #{decoy}\r\n")
    # The decoy is response data: it must be emitted verbatim and must not
    # start a (non-existent) SASL exchange or corrupt later state.
    assert_includes output.string, decoy
    logger.client_write("RUBY0009 NOOP\r\n")
    logger.server_read("RUBY0009 OK\r\n")
    assert_includes output.string, "C: RUBY0009 NOOP\r\n"
  end

  test "ends the SASL exchange on authentication failure" do
    output, logger = new_logger
    logger.client_write("RUBY0010 AUTHENTICATE PLAIN\r\n")
    logger.server_read("RUBY0010 NO auth failed\r\n")
    # After failure, an untagged continuation is no longer treated as SASL.
    logger.server_read("+ not a sasl challenge\r\n")
    assert_includes output.string, "S: + not a sasl challenge\r\n"
  end

  test "preserves ordering, direction, tags, and declared lengths" do
    output, logger = new_logger
    logger.client_write("RUBY0011 LOGIN alice #{SECRET_PASSWORD}\r\n")
    logger.server_read("RUBY0011 OK\r\n")
    lines = output.string.lines
    assert_equal "C: RUBY0011 LOGIN alice <REDACTED #{SECRET_PASSWORD.bytesize} bytes>\r\n",
                 lines.first
    assert_equal "S: RUBY0011 OK\r\n", lines.last
  end

  # ----- raw mode ----------------------------------------------------------

  test "raw mode prints every byte verbatim" do
    output, logger = new_logger(mode: :raw)
    logger.client_write("RUBY0012 LOGIN alice #{SECRET_PASSWORD}\r\n")
    body = "body #{BODY_SECRET}"
    logger.server_read("* 1 FETCH (BODY[] {#{body.bytesize}}\r\n#{body})\r\n")
    assert_includes output.string, SECRET_PASSWORD
    assert_includes output.string, BODY_SECRET
  end

  test "raw mode preserves the original chunked client line prefixing" do
    output, logger = new_logger(mode: :raw)
    logger.client_write("RUBY00")
    logger.client_write("13 NOOP\r\n")
    assert_equal "C: RUBY00C: 13 NOOP\r\n", output.string
  end

  test "debug disabled logs nothing" do
    output = StringIO.new
    config = Net::IMAP::Config.new(debug: false)
    logger = Net::IMAP::DebugLogger.new(config, output: output)
    logger.client_write("RUBY0014 LOGIN alice #{SECRET_PASSWORD}\r\n")
    logger.server_read("RUBY0014 OK\r\n")
    assert_empty output.string
  end

end
