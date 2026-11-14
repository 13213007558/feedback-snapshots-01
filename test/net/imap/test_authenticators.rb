# frozen_string_literal: true

require "net/imap"
require "test/unit"

class AuthenticatorsTest < Net::IMAP::TestCase

  test "SASL::Authenticators.normalize_name" do
    authenticators = Net::IMAP::SASL::Authenticators
    assert_equal "FOO-BAR-BAZ", authenticators.normalize_name(:foo_bar_baz)
    assert_equal "SCRAM-SHA1-PLUS", authenticators.normalize_name(:scram_sha1_plus)
    assert_equal "PLAIN", authenticators.normalize_name("pLAin")
  end

  def test_net_imap_authenticator_deprecated
    assert_warn(/Net::IMAP\.authenticator .+deprecated./) do
      Net::IMAP.authenticator("PLAIN", "user", "pass")
    end
  end

  test ".authenticator mechanism name is case insensitive" do
    assert_kind_of(Net::IMAP::SASL::PlainAuthenticator,
                   Net::IMAP::SASL.authenticator("PLAIN", "user", "pass"))
    assert_kind_of(Net::IMAP::SASL::PlainAuthenticator,
                   Net::IMAP::SASL.authenticator("plain", "user", "pass"))
    assert_kind_of(Net::IMAP::SASL::PlainAuthenticator,
                   Net::IMAP::SASL.authenticator("pLaIn", "user", "pass"))
  end

  test ".authenticator mechanism name can be a symbol" do
    assert_kind_of(Net::IMAP::SASL::PlainAuthenticator,
                   Net::IMAP::SASL.authenticator(:PLAIN, "user", "pass"))
    assert_kind_of(Net::IMAP::SASL::PlainAuthenticator,
                   Net::IMAP::SASL.authenticator(:plain, "user", "pass"))
    assert_kind_of(Net::IMAP::SASL::PlainAuthenticator,
                   Net::IMAP::SASL.authenticator(:pLaIN, "user", "pass"))
  end

  # ----------------------
  # PLAIN
  # ----------------------

  def plain(...) Net::IMAP::SASL.authenticator("PLAIN", ...) end

  def test_plain_authenticator_matches_mechanism
    assert_kind_of(Net::IMAP::SASL::PlainAuthenticator, plain("user", "pass"))
  end

  def test_plain_supports_initial_response
    assert plain("foo", "bar").initial_response?
  end

  def test_plain_response
    assert_equal("\0authc\0passwd", plain("authc", "passwd").process(nil))
  end

  def test_plain_authzid
    assert_equal("authz\0user\0pass",
                 plain("user", "pass", authzid: "authz").process(nil))
  end

  def test_plain_kw_params
    assert_equal(
      "zid\0cid\0p",
      plain(authcid: "cid", password: "p", authzid: "zid").process(nil)
    )
    assert_equal(
      "zid\0cid\0p",
      plain(username: "cid", secret: "p", authzid: "zid").process(nil)
    )
  end

  def test_plain_username_kw_sets_both_authcid_and_authzid
    assert_equal(
      "\0uname\0passwd",
      plain(username: "uname", password: "passwd").process(nil)
    )
  end

  def test_plain_no_null_chars
    assert_raise(ArgumentError) { plain("bad\0user", "pass") }
    assert_raise(ArgumentError) { plain("user", "bad\0pass") }
    assert_raise(ArgumentError) { plain(authcid: "bad\0user", password: "p") }
    assert_raise(ArgumentError) { plain(username: "bad\0user", password: "p") }
    assert_raise(ArgumentError) { plain(username: "u", password: "bad\0pass") }
    assert_raise(ArgumentError) { plain("u", "p", authzid: "bad\0authz") }
    assert_raise(ArgumentError) { plain("u", "p", authzid: "bad\0authz") }
  end

  # ----------------------
  # OAUTHBEARER
  # ----------------------

  def test_oauthbearer_authenticator_matches_mechanism
    assert_kind_of(Net::IMAP::SASL::OAuthBearerAuthenticator,
                   Net::IMAP::SASL.authenticator("OAUTHBEARER", "tok"))
  end

  def oauthbearer(*args, **kwargs, &block)
    Net::IMAP::SASL.authenticator("OAUTHBEARER", *args, **kwargs, &block)
  end

  def test_oauthbearer_response
    assert_equal(
      "n,a=user@example.com,\1host=server.example.com\1port=587\1" \
      "auth=Bearer mF_9.B5f-4.1JqM\1\1",
      oauthbearer("mF_9.B5f-4.1JqM", authzid: "user@example.com",
                  host: "server.example.com", port: 587).process(nil)
    )
    assert_equal(
      "n,a=user@example.com,\1host=server.example.com\1port=587\1" \
      "auth=Bearer sssssssss\1\1",
      oauthbearer(secret: "sssssssss", username: "user@example.com",
                  host: "server.example.com", port: 587).process(nil)
    )
    assert_equal(
      "n,a=user,\1auth=Bearer tok\1\1", oauthbearer("user", "tok").process(nil)
    )
  end

  # An independent, finite reader for the RFC7628 §3.1 grammar:
  #
  #   client-resp = (gs2-header kvsep *kvpair kvsep) / kvsep
  #   gs2-header  = gs2-cb-flag "," [ gs2-authzid ] ","
  #   gs2-cb-flag = ("p=" cb-name) / "n" / "y"
  #   gs2-authzid = "a=" saslname
  #   kvpair      = key "=" value kvsep
  #
  # Returns [gs2_cb_flag, decoded_authzid (or nil), {key => value}].
  # Raises ArgumentError for anything outside the grammar.
  def parse_oauthbearer_response(msg)
    raise ArgumentError, "invalid UTF-8" unless msg.valid_encoding?
    pos = 0
    read = ->(pattern) {
      match = pattern.match(msg, pos) or
        raise ArgumentError, "parse error at offset #{pos}"
      pos = match.end(0)
      match[0]
    }
    cb_flag = read[/\G(?:n|y|p=[A-Za-z0-9._-]+)/]
    read[/\G,/]
    saslname = read[/\G[^,\x01]*/]
    authzid = nil
    unless saslname.empty?
      saslname.match?(/\Aa=(?:[^,=\x00]|=2C|=3D)+\z/u) or
        raise ArgumentError, "invalid gs2-authzid: #{saslname.inspect}"
      authzid = saslname[2..].gsub("=2C", ",").gsub("=3D", "=")
    end
    read[/\G,/]
    read[/\G\x01/]
    pairs = {}
    until msg[pos] == "\x01"
      key   = read[/\G[A-Za-z]+/]
      read[/\G=/]
      value = read[/\G[^\x01]*/]
      value.match?(/\A(?:[^\x00-\x08\x0B\x0C\x0E-\x1F\x7F])*\z/u) or
        raise ArgumentError, "invalid kvpair value"
      pairs.key?(key) and raise ArgumentError, "duplicate key: #{key}"
      pairs[key] = value
      read[/\G\x01/]
    end
    read[/\G\x01/]
    pos == msg.length or raise ArgumentError, "trailing data"
    [cb_flag, authzid, pairs]
  end

  def test_oauthbearer_response_parses_back_to_original_fields
    cb_flag, authzid, pairs = parse_oauthbearer_response(
      oauthbearer("mF_9.B5f-4.1JqM", authzid: "user@example.com",
                  host: "server.example.com", port: 587).process(nil)
    )
    assert_equal "n", cb_flag
    assert_equal "user@example.com", authzid
    assert_equal({ "host" => "server.example.com", "port" => "587",
                   "auth" => "Bearer mF_9.B5f-4.1JqM" }, pairs)
  end

  def test_oauthbearer_unicode_authzid_survives_roundtrip
    _cb, authzid, pairs = parse_oauthbearer_response(
      oauthbearer("tok", authzid: "用户@example.com").process(nil)
    )
    assert_equal "用户@example.com", authzid
    assert_equal({ "auth" => "Bearer tok" }, pairs)
  end

  def test_oauthbearer_authzid_gs2_delimiters_are_escaped
    response = oauthbearer("tok", authzid: "weird,=name").process(nil)
    assert_equal "n,a=weird=2C=3Dname,\1auth=Bearer tok\1\1", response
    _cb, authzid, pairs = parse_oauthbearer_response(response)
    assert_equal "weird,=name", authzid
    assert_equal({ "auth" => "Bearer tok" }, pairs)
  end

  def test_oauthbearer_authzid_escape_looking_input_is_not_double_decoded
    # "=" is encoded first, so a literal "=2C" becomes "=3D2C" and a
    # compliant reader must get back the literal string, not a comma.
    _cb, authzid, pairs = parse_oauthbearer_response(
      oauthbearer("tok", authzid: "a=2Cb").process(nil)
    )
    assert_equal "a=2Cb", authzid
    assert_equal({ "auth" => "Bearer tok" }, pairs)
  end

  def test_oauthbearer_kv_value_escape_looking_input_stays_literal
    # The kvpair region is not saslname-encoded; "=2C" there is literal data.
    _cb, _authzid, pairs = parse_oauthbearer_response(
      oauthbearer("tok", host: "ho=2Cst").process(nil)
    )
    assert_equal({ "host" => "ho=2Cst", "auth" => "Bearer tok" }, pairs)
  end

  def test_oauthbearer_empty_and_nil_authzid_are_preserved
    assert_equal "n,,\1auth=Bearer tok\1\1",
                 oauthbearer("tok").process(nil)
    assert_equal "n,,\1auth=Bearer tok\1\1",
                 oauthbearer("tok", authzid: "").process(nil)
    _cb, authzid, pairs = parse_oauthbearer_response(
      oauthbearer("tok", authzid: "").process(nil)
    )
    assert_nil authzid
    assert_equal({ "auth" => "Bearer tok" }, pairs)
  end

  def test_oauthbearer_kv_value_may_contain_equals_and_commas
    # "=" and "," are legal inside an RFC7628 value and cannot start a new
    # kvpair, because kvpairs are separated only by %x01.
    _cb, _authzid, pairs = parse_oauthbearer_response(
      oauthbearer("tok", qs: "a=b,c=d").process(nil)
    )
    assert_equal({ "qs" => "a=b,c=d", "auth" => "Bearer tok" }, pairs)
  end

  def test_oauthbearer_kv_value_may_contain_unicode
    _cb, _authzid, pairs = parse_oauthbearer_response(
      oauthbearer("tok", path: "/üñíçødé/路径").process(nil)
    )
    assert_equal "/üñíçødé/路径", pairs["path"]
  end

  def test_oauthbearer_kvsep_injection_is_rejected_before_any_response
    # Each of these raises from .new, so no part of a client response can
    # ever be sent for a crafted field.
    inject = "x\1auth=Bearer fake-token"
    assert_raise(ArgumentError) { oauthbearer("tok", host: inject) }
    assert_raise(ArgumentError) { oauthbearer("tok", port: "993\1auth=Bearer fake-token") }
    assert_raise(ArgumentError) { oauthbearer("tok", mthd: inject) }
    assert_raise(ArgumentError) { oauthbearer("tok", path: inject) }
    assert_raise(ArgumentError) { oauthbearer("tok", post: inject) }
    assert_raise(ArgumentError) { oauthbearer("tok", qs: inject) }
    assert_raise(ArgumentError) { oauthbearer("tok\1auth=Bearer fake-token") }
    assert_raise(ArgumentError) { oauthbearer("tok", authzid: "user\1auth=Bearer fake-token") }
  end

  def test_oauthbearer_fields_reject_other_control_characters
    assert_raise(ArgumentError) { oauthbearer("tok", host: "ex\0ample") }
    assert_raise(ArgumentError) { oauthbearer("tok", host: "ex\x7Fample") }
    assert_raise(ArgumentError) { oauthbearer("tok", path: "a\x02b") }
    assert_raise(ArgumentError) { oauthbearer("tok", authzid: "u\0ser") }
    assert_raise(ArgumentError) { oauthbearer("tok", authzid: "u\1ser") }
  end

  def test_oauthbearer_token_must_be_an_rfc6750_b64token
    assert_raise(ArgumentError) { oauthbearer("tok en") }
    assert_raise(ArgumentError) { oauthbearer("tok,en") }
    assert_raise(ArgumentError) { oauthbearer("tok=en") }
    assert_raise(ArgumentError) { oauthbearer("") }
    # trailing "=" padding is legal
    assert_equal "n,,\1auth=Bearer tok==\1\1",
                 oauthbearer("tok==").process(nil)
  end

  # ----------------------
  # SCRAM-SHA-1
  # SCRAM-SHA-256
  # SCRAM-SHA-* (etc)
  # ----------------------

  def test_scram_sha1_authenticator_matches_mechanism
    authenticator = Net::IMAP::SASL.authenticator("SCRAM-SHA-1", "user", "pass")
    assert_kind_of(Net::IMAP::SASL::ScramAuthenticator,     authenticator)
    assert_kind_of(Net::IMAP::SASL::ScramSHA1Authenticator, authenticator)
  end

  def test_scram_sha256_authenticator_matches_mechanism
    authenticator = Net::IMAP::SASL.authenticator("SCRAM-SHA-256", "user", "pass")
    assert_kind_of(Net::IMAP::SASL::ScramAuthenticator,       authenticator)
    assert_kind_of(Net::IMAP::SASL::ScramSHA256Authenticator, authenticator)
  end

  def scram_sha1(*args, **kwargs, &block)
    Net::IMAP::SASL.authenticator("SCRAM-SHA-1", *args, **kwargs, &block)
  end

  def scram_sha256(*args, **kwargs, &block)
    Net::IMAP::SASL.authenticator("SCRAM-SHA-256", *args, **kwargs, &block)
  end

  def test_scram_sha1_authenticator
    authenticator = scram_sha1("user", "pencil",
                               cnonce: "fyko+d2lbbFgONRv9qkxdawL")
    # n = no channel binding
    # a = authzid
    # n = authcid
    # r = random nonce (client)
    assert_equal("n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL",
                 authenticator.process(nil))
    refute authenticator.done?
    assert_equal(
      # c = b64 of gs2 header and channel binding data
      # r = random nonce (client + server)
      # p = b64 client proof
      # s = salt
      # i = iteration count
      "c=biws," \
      "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j," \
      "p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=",
      authenticator.process(
        "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j," \
        "s=QSXCR+Q6sek8bf92," \
        "i=4096")
    )
    refute authenticator.done?
    assert_empty authenticator.process("v=rmF9pqV8S7suAoZWja4dJRkFsKQ=")
    assert authenticator.done?
  end

  def test_scram_kwargs
    authenticator = scram_sha1(authcid: "user", password: "pass")
    assert_equal "user", authenticator.authcid
    assert_equal "pass", authenticator.password
    authenticator = scram_sha1(username: "user", secret: "pass")
    assert_equal "user", authenticator.authcid
    assert_equal "pass", authenticator.password
  end

  def test_scram_sha256_authenticator
    authenticator = scram_sha256("user", "pencil",
                                 cnonce: "rOprNGfwEbeRWgbNEkqO")
    # n = no channel binding
    # a = authzid
    # n = authcid
    # r = random nonce (client)
    assert_equal("n,,n=user,r=rOprNGfwEbeRWgbNEkqO",
                 authenticator.process(nil))
    refute authenticator.done?
    assert_equal(
      # c = b64 of gs2 header and channel binding data
      # r = random nonce (client + server)
      # p = b64 client proof
      # s = salt
      # i = iteration count
      "c=biws," \
      "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0," \
      "p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=",
      authenticator.process(
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0," \
        "s=W22ZaJ0SNY7soEsUEjb6gQ==," \
        "i=4096")
    )
    refute authenticator.done?
    assert_empty authenticator.process(
      "v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4="
    )
    assert authenticator.done?
  end

  def test_scram_min_iterations
    # i=1000, below default of 4096
    authenticator = scram_sha1("user", "pencil",
                               cnonce: "fyko+d2lbbFgONRv9qkxdawL")
    assert_equal         4_096, authenticator.min_iterations
    assert_equal 2_147_483_647, authenticator.max_iterations
    authenticator.process(nil)
    assert_raise_with_message(Net::IMAP::SASL::Error, /too few iterations/) do
      authenticator.process(
        "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j," \
        "s=QSXCR+Q6sek8bf92," \
        "i=1000")
    end

    # i=4096, below configured 100,000
    authenticator = scram_sha256("user", "pencil",
                                 cnonce: "rOprNGfwEbeRWgbNEkqO",
                                 min_iterations: 100_000)
    assert_equal       100_000, authenticator.min_iterations
    assert_equal 2_147_483_647, authenticator.max_iterations
    authenticator.process(nil)
    assert_raise_with_message(Net::IMAP::SASL::Error, /too few iterations/) do
      authenticator.process(
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0," \
        "s=W22ZaJ0SNY7soEsUEjb6gQ==," \
        "i=4096")
    end
  end

  def test_scram_max_iterations
    # i=1000, below default of 4096
    authenticator = scram_sha1("user", "pencil",
                               cnonce: "fyko+d2lbbFgONRv9qkxdawL",
                               max_iterations: 1_000_000)
    assert_equal     4_096, authenticator.min_iterations
    assert_equal 1_000_000, authenticator.max_iterations
    authenticator.process(nil)
    assert_raise_with_message(Net::IMAP::SASL::Error, /too many iterations/) do
      authenticator.process(
        "r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j," \
        "s=QSXCR+Q6sek8bf92," \
        "i=2147483647")
    end

    # i=4096, below configured 100,000
    authenticator = scram_sha256("user", "pencil",
                                 cnonce: "rOprNGfwEbeRWgbNEkqO",
                                 max_iterations: 100_000)
    assert_equal   4_096, authenticator.min_iterations
    assert_equal 100_000, authenticator.max_iterations
    authenticator.process(nil)
    assert_raise_with_message(Net::IMAP::SASL::Error, /too many iterations/) do
      authenticator.process(
        "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0," \
        "s=W22ZaJ0SNY7soEsUEjb6gQ==," \
        "i=2147483647")
    end
  end

  # ----------------------
  # XOAUTH2
  # ----------------------

  def xoauth2(...) Net::IMAP::SASL.authenticator("XOAUTH2", ...) end

  def test_xoauth2_authenticator_matches_mechanism
    assert_kind_of(Net::IMAP::SASL::XOAuth2Authenticator, xoauth2("user", "tok"))
  end

  def test_xoauth2_response
    assert_equal(
      "user=username\1auth=Bearer token\1\1",
      xoauth2("username", "token").process(nil)
    )
  end

  def test_xoauth2_kwargs
    assert_equal(
      "user=arg\1auth=Bearer kwarg\1\1",
      xoauth2("arg", oauth2_token: "kwarg").process(nil)
    )
    assert_equal(
      "user=user\1auth=Bearer kwarg\1\1",
      xoauth2(username: "user", oauth2_token: "kwarg").process(nil)
    )
    assert_equal(
      "user=user\1auth=Bearer kwarg\1\1",
      xoauth2(authzid: "user", secret: "kwarg").process(nil)
    )
  end

  def test_xoauth2_supports_initial_response
    assert xoauth2("foo", "bar").initial_response?
  end

  # ----------------------
  # ANONYMOUS
  # ----------------------

  def anonymous(*args, **kwargs, &block)
    Net::IMAP::SASL.authenticator("ANONYMOUS", *args, **kwargs, &block)
  end

  def test_anonymous_matches_mechanism
    assert_kind_of(Net::IMAP::SASL::AnonymousAuthenticator, anonymous)
  end

  def test_anonymous_response
    assert_equal("", anonymous.process(nil))
    assert_equal("hello world", anonymous("hello world").process(nil))
    assert_equal("kwargs",
                 anonymous(anonymous_message: "kwargs").process(nil))
  end

  def test_anonymous_stringprep
    assert_raise(Net::IMAP::SASL::ProhibitedCodepoint) {
      anonymous("no\ncontrol\rchars").process(nil)
    }
    assert_raise(Net::IMAP::SASL::ProhibitedCodepoint) {
      anonymous("regional flags use tagging chars: e.g." \
                "🏴󠁧󠁢󠁥󠁮󠁧󠁿 England, " \
                "🏴󠁧󠁢󠁳󠁣󠁴󠁿 Scotland, " \
                "🏴󠁧󠁢󠁷󠁬󠁳󠁿 Wales.").process(nil)
    }
  end

  def test_anonymous_length_over_255
    assert_raise(ArgumentError) { anonymous("a" * 256).process(nil) }
  end

  # ----------------------
  # EXTERNAL
  # ----------------------

  def external(...)
    Net::IMAP::SASL.authenticator("EXTERNAL", ...)
  end

  def test_external_matches_mechanism
    assert_kind_of(Net::IMAP::SASL::ExternalAuthenticator, external)
  end

  def test_external_response
    assert_equal("", external.process(nil))
    assert_equal("", external.process(""))
    assert_equal("kwarg", external(authzid: "kwarg").process(nil))
    assert_equal("username", external(username: "username").process(nil))
    assert_equal("z", external("p", authzid: "z", username: "u").process(nil))
    assert_equal("positional", external("positional").process(nil))
  end

  def test_external_utf8
    assert_equal("", external.process(nil))
    assert_equal("🏴󠁧󠁢󠁥󠁮󠁧󠁿 England",
                 external(authzid: "🏴󠁧󠁢󠁥󠁮󠁧󠁿 England").process(nil))
  end

  def test_external_invalid
    assert_raise(ArgumentError) { external(authzid: "bad\0contains NULL") }
    assert_raise(ArgumentError) { external(authzid: "invalid utf8\x80") }
  end

  # ----------------------
  # LOGIN (obsolete)
  # ----------------------

  def login(*args, warn_deprecation: false, **kwargs, &block)
    Net::IMAP::SASL.authenticator(
      "LOGIN", *args, warn_deprecation: warn_deprecation, **kwargs, &block
    )
  end

  def test_login_authenticator_matches_mechanism
    assert_kind_of(Net::IMAP::SASL::LoginAuthenticator, login("n", "p"))
  end

  def test_login_does_not_support_initial_response
    refute login("foo", "bar").initial_response?
  end

  def test_login_authenticator_deprecated
    assert_warn(/LOGIN.+deprecated.+PLAIN/) do
      Net::IMAP::SASL.authenticator("LOGIN", "user", "pass")
    end
  end

  def test_login_responses
    auth_session = login("username", "password")
    assert_equal("username", auth_session.process("username?"))
    assert_equal("password", auth_session.process("password?"))
  end

  # ----------------------
  # CRAM-MD5 (obsolete)
  # ----------------------

  def cram_md5(*args, warn_deprecation: false, **kwargs, &block)
    Net::IMAP::SASL.authenticator(
      "CRAM-MD5", *args, warn_deprecation: warn_deprecation, **kwargs, &block
    )
  end

  def test_cram_md5_authenticator_matches_mechanism
    assert_kind_of(Net::IMAP::SASL::CramMD5Authenticator, cram_md5("n", "p"))
  end

  def test_cram_md5_does_not_support_initial_response
    refute cram_md5("foo", "bar").initial_response?
  end

  def test_cram_md5_authenticator_deprecated
    assert_warn(/CRAM-MD5.+deprecated./) do
      Net::IMAP::SASL.authenticator("CRAM-MD5", "user", "pass")
    end
  end

  def test_cram_md5_authenticator
    auth = cram_md5("username", "password")
    assert_match("username e2ce8ff3d1b914ddf339aa9f55198f86",
                 auth.process("fake-server-challence-string"))
  end

  # ----------------------
  # DIGEST-MD5 (obsolete)
  # ----------------------

  def digest_md5(*args, warn_deprecation: false, **kwargs, &block)
    Net::IMAP::SASL.authenticator(
      "DIGEST-MD5", *args, warn_deprecation: warn_deprecation, **kwargs, &block
    )
  end

  def test_digest_md5_authenticator_matches_mechanism
    assert_kind_of(Net::IMAP::SASL::DigestMD5Authenticator,
                   digest_md5("n", "p", "z"))
  end

  def test_digest_md5_authenticator_deprecated
    assert_warn(/DIGEST-MD5.+deprecated.+RFC6331/) do
      Net::IMAP.authenticator("DIGEST-MD5", "user", "pass")
    end
  end

  def test_digest_md5_does_not_support_initial_response
    refute digest_md5("foo", "bar").initial_response?
  end

  def test_digest_md5_authenticator
    auth = digest_md5("cid", "password", "zid")
    assert_match(
      %r{\A
        nonce="OA6MG9tEQGm2hh",
        username="cid",
        realm="somerealm",
        cnonce="[a-zA-Z0-9+/]{12,}={0,3}", # RFC2831: >= 64 bits of entropy
        digest-uri="imap/somerealm",
        qop="auth",
        maxbuf=65535,
        nc=00000001,
        charset=utf-8,
        authzid="zid",
        response=[a-f0-9]+
      \Z}x,
      auth.process(
        %w[
          realm="somerealm"
          nonce="OA6MG9tEQGm2hh"
          qop="auth"
          charset=utf-8
          algorithm=md5-sess
        ].join(",")
      )
    )
  end

  def test_digest_md5_authenticator_realm_and_digest_uri
    auth = digest_md5(authcid: "authc",
                      authzid: "authz",
                      password: "pass",
                      realm: "myrealm",
                      service: "smtp",
                      host: "mail.example.com",
                      service_name: "example.com")
    assert_match(
      %r{\A
        nonce="OA6MG9tEQGm2hh",
        username="authc",
        realm="myrealm",
        cnonce="[a-zA-Z0-9+/]{12,}={0,3}",
        digest-uri="smtp/mail\.example\.com/example\.com",
        qop="auth",
        maxbuf=65535,
        nc=00000001,
        charset=utf-8,
        authzid="authz",
        response=[a-f0-9]+
      \Z}x,
      auth.process(
        %w[
          realm="somerealm"
          nonce="OA6MG9tEQGm2hh"
          qop="auth"
          charset=utf-8
          algorithm=md5-sess
        ].join(",")
      )
    )
  end

  def test_digest_md5_authenticator_empty_challenge
    auth = digest_md5("user", "pass")
    assert_raise(Net::IMAP::DataFormatError) do
      auth.process("   ")
    end
  end

  def test_digest_md5_authenticator_empty_challenge_commas
    auth = digest_md5("user", "pass")
    assert_raise_with_message(Net::IMAP::DataFormatError, /empty challenge/i) do
      auth.process(" ,  ,  ")
    end
  end

  def test_digest_md5_authenticator_garbage_no_equal_sign
    auth = digest_md5("user", "pass")
    assert_raise_with_message(Net::IMAP::DataFormatError, /unparsable/i) do
      auth.process('nonce=required,algorithm=md5-sess,foo')
    end
  end

  def test_digest_md5_authenticator_qdstr_with_comma
    auth = digest_md5("user", "pass")
    assert_raise_with_message(Net::IMAP::DataFormatError, /unparsable/i) do
      auth.process('nonce=required,algorithm=md5-sess,.')
    end
  end

  def test_digest_md5_authenticator_garbage
    auth = digest_md5("user", "pass")
    assert_raise_with_message(Net::IMAP::DataFormatError, /unparsable/i) do
      auth.process('.')
    end
  end

  def test_digest_md5_authenticator_empty_qop
    auth = digest_md5("user", "pass")
    assert_raise_with_message(Net::IMAP::DataFormatError, /bad challenge/i) do
      auth.process('Qop=""')
    end
  end

  def test_digest_md5_authenticator_missing_nonce
    auth = digest_md5("user", "pass")
    assert_raise_with_message(Net::IMAP::DataFormatError, /didn't send nonce/i) do
      auth.process('Qop="auth"')
    end
  end

  def test_digest_md5_authenticator_illinear
    pre = ->(n) {'qop="a' + ',x'*n}
    assert_linear_performance([5, 10, 15, 20], pre: pre) do |challenge|
      auth = digest_md5("user", "pass")
      assert_raise(Net::IMAP::DataFormatError) do
        auth.process(challenge)
      end
    end
  end
end
