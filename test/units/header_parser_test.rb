# frozen_string_literal: true

require_relative "../test_helper"

# Grammar-driven tests for the shared OAuth Authorization / WWW-Authenticate
# header parser. The cases below are organized around the header grammar
# (auth-param / quoted-string / percent-encoding) rather than the old
# split-based implementation, and assert that punctuation, escaping and
# malformed encoding cannot change the credential that ends up being verified.
class HeaderParserTest < Minitest::Test
  # Fixed seed so the randomized "minimally different header" fuzzing is
  # reproducible across machines and CI runs.
  FUZZ_SEED = 20_261_114

  def parser
    OAuth::HeaderParser
  end

  def assert_rejected(header)
    assert_raises(OAuth::Problem, "expected rejection of #{header.inspect}") do
      parser.parse(header)
    end
  end

  def assert_parses(header, expected_hash)
    assert_equal expected_hash, parser.parse(header), "header: #{header.inspect}"
  end

  # ---- scheme / overall structure ---------------------------------------

  def test_parses_well_formed_header
    header = "OAuth " \
             'realm="http://example.com/method", ' \
             'oauth_consumer_key="vince_clortho", ' \
             'oauth_token="token_value", ' \
             'oauth_signature_method="HMAC-SHA1", ' \
             'oauth_signature="signature_here", ' \
             'oauth_timestamp="1240004133", oauth_nonce="nonce", ' \
             'oauth_version="1.0" '

    assert_parses header, {
      "realm" => "http://example.com/method",
      "oauth_consumer_key" => "vince_clortho",
      "oauth_token" => "token_value",
      "oauth_signature_method" => "HMAC-SHA1",
      "oauth_signature" => "signature_here",
      "oauth_timestamp" => "1240004133",
      "oauth_nonce" => "nonce",
      "oauth_version" => "1.0"
    }
  end

  def test_accepts_leading_and_trailing_linear_whitespace
    assert_parses "OAuth\toauth_nonce=\"n\" ", { "oauth_nonce" => "n" }
    assert_parses "OAuth oauth_nonce=\"n\"\t", { "oauth_nonce" => "n" }
    assert_parses "OAuth oauth_nonce = \"n\"", { "oauth_nonce" => "n" }
  end

  def test_empty_parameter_list_yields_empty_hash
    assert_parses "OAuth ", {}
    assert_parses "OAuth", {}
  end

  def test_rejects_wrong_or_missing_scheme
    assert_rejected("Bearer oauth_nonce=\"n\"")
    assert_rejected("oauth oauth_nonce=\"n\"")
    assert_rejected("XOAuth oauth_nonce=\"n\"")
    assert_rejected("oauth_nonce=\"n\"")
    assert_rejected("")
  end

  def test_rejects_non_string_input
    assert_rejected(nil)
    assert_rejected(42)
  end

  # ---- quotes -------------------------------------------------------------

  def test_quotes_delimited_value_keeps_internal_punctuation
    header = 'OAuth oauth_signature="a,b=c&d\"e", oauth_nonce="n"'
    assert_parses header, { "oauth_signature" => 'a,b=c&d"e', "oauth_nonce" => "n" }
  end

  def test_empty_quoted_value_is_preserved
    assert_parses 'OAuth oauth_token=""', { "oauth_token" => "" }
  end

  def test_rejects_unterminated_quote
    assert_rejected 'OAuth oauth_token="abc'
    assert_rejected 'OAuth oauth_token="abc, oauth_nonce="n"'
  end

  def test_rejects_quote_inside_bare_token
    assert_rejected 'OAuth oauth_token=ab"c'
  end

  def test_preserves_spaces_inside_quotes
    assert_parses 'OAuth realm="a b c"', { "realm" => "a b c" }
  end

  # ---- commas -------------------------------------------------------------

  def test_comma_inside_quotes_is_data_not_a_separator
    assert_parses 'OAuth oauth_token="one,two", oauth_nonce="n"',
                  { "oauth_token" => "one,two", "oauth_nonce" => "n" }
  end

  def test_rejects_encoded_comma_then_bare_comma_ambiguity
    # %2C decodes to "," inside the value while the structural commas stay
    # outside the quotes; both must be distinguishable and stable.
    assert_parses 'OAuth oauth_token="a%2Cb", oauth_nonce="n"',
                  { "oauth_token" => "a,b", "oauth_nonce" => "n" }
    # A bare comma cannot appear in an unquoted value.
    assert_rejected 'OAuth oauth_token=a,b'
  end

  def test_rejects_dangling_and_doubled_commas
    assert_rejected 'OAuth oauth_nonce="n",'
    assert_rejected 'OAuth oauth_nonce="n",, oauth_consumer_key="k"'
    assert_rejected 'OAuth , oauth_nonce="n"'
  end

  # ---- equals -------------------------------------------------------------

  def test_equals_inside_quotes_is_data_not_a_pair_separator
    assert_parses 'OAuth oauth_signature="sig=with=equals", oauth_nonce="n"',
                  { "oauth_signature" => "sig=with=equals", "oauth_nonce" => "n" }
  end

  def test_rejects_missing_equals
    assert_rejected 'OAuth oauth_nonce'
    assert_rejected 'OAuth oauth_nonce "n"'
  end

  # ---- escaping (quoted-pair and percent) --------------------------------

  def test_decodes_percent_escaped_separators_inside_quotes
    assert_parses 'OAuth oauth_signature="a%2Cb%3Dc%26d"',
                  { "oauth_signature" => "a,b=c&d" }
  end

  def test_decodes_quoted_pair_backslash_escapes
    # RFC 7235 quoted-pair: backslash only quotes the next octet, so both
    # \" and \\ collapse to the bare character.
    assert_parses 'OAuth oauth_token="a\"b\\c"',
                  { "oauth_token" => 'a"bc' }
    assert_parses 'OAuth oauth_token="a\\\\"',
                  { "oauth_token" => 'a\\' }
  end

  def test_rejects_orphan_backslash
    assert_rejected 'OAuth oauth_token="abc\\'
  end

  def test_rejects_malformed_percent_encoding
    %w[ab%ZZ ab%2 ab% 100%done a%2G].each do |bad|
      assert_rejected %Q{OAuth oauth_token="#{bad}"}
    end
  end

  def test_rejects_malformed_percent_encoding_in_bare_value
    %w[ab%ZZ 100%done].each do |bad|
      assert_rejected "OAuth oauth_token=#{bad}"
    end
  end

  def test_valid_percent_sequence_with_literal_percent
    assert_parses 'OAuth oauth_token="100%25done"',
                  { "oauth_token" => "100%done" }
  end

  def test_decodes_multibyte_percent_sequences
    # U+2713 CHECK MARK encoded as UTF-8 bytes E2 9C 93.
    assert_parses 'OAuth oauth_token="%E2%9C%93"',
                  { "oauth_token" => "✓" }
  end

  # ---- repeated fields ----------------------------------------------------

  def test_rejects_repeated_parameter_name
    # A Hash would otherwise keep the *last* value; refusing removes the
    # ambiguity that lets an extra field override the verified credential.
    assert_rejected 'OAuth oauth_nonce="first", oauth_nonce="last"'
    assert_rejected 'OAuth oauth_signature="s1", oauth_signature="s2"'
  end

  def test_repeated_field_is_rejected_for_realm_too
    assert_rejected 'OAuth realm="r1", realm="r2"'
  end

  def test_single_field_is_not_treated_as_duplicate
    assert_parses 'OAuth oauth_nonce="only"', { "oauth_nonce" => "only" }
  end

  # ---- bare (unquoted) token values --------------------------------------

  def test_accepts_bare_token_values
    assert_parses "OAuth oauth_version=1.0", { "oauth_version" => "1.0" }
  end

  def test_rejects_bare_value_with_structural_character
    assert_rejected 'OAuth oauth_version=1,0'
    assert_rejected 'OAuth oauth_version=1=0'
  end

  # ---- deterministic fuzzing with a fixed seed ---------------------------

  def test_fuzzed_headers_are_accepted_or_rejected_never_misparsed
    rng = Random.new(FUZZ_SEED)
    base = {
      "oauth_consumer_key" => "key",
      "oauth_nonce" => "nonce",
      "oauth_signature" => "sig%2C%3D%26",
      "oauth_timestamp" => "1240004133"
    }

    200.times do
      header = mutate(build_header(base), rng)
      begin
        result = parser.parse(header)
      rescue OAuth::Problem
        next # stable rejection is an acceptable outcome
      end

      # Whenever parsing succeeds it must yield a well-formed, duplicate-free
      # hash whose values contain no undecoded escape artifacts.
      refute(result.any? { |_k, v| v.include?("%2C") || v.include?("%3D") },
             "escaped delimiter left undecoded in #{header.inspect}")
      assert_equal result.keys.size, result.keys.uniq.size,
                   "duplicate keys survived parsing #{header.inspect}"
    end
  end

  def test_documented_seed_round_trips
    # The exact seed-driven case is pinned so reviewers can reproduce it.
    srand(FUZZ_SEED)
    header = 'OAuth oauth_nonce="abc%2Cdef", oauth_signature="x%3Dy"'
    assert_parses header, { "oauth_nonce" => "abc,def", "oauth_signature" => "x=y" }
  end

  private

  def build_header(params)
    "OAuth " + params.map { |k, v| "#{k}=\"#{v}\"" }.join(", ")
  end

  # Single-token mutations producing "minimally different" headers: insert,
  # delete or swap a structural character. Most outputs stay valid; the parser
  # must either accept them faithfully or reject them, never mis-parse.
  def mutate(header, rng)
    chars = header.dup.chars
    spot = rng.rand(chars.length)
    case rng.rand(4)
    when 0 then chars.insert(spot, [",", "=", '"', "%", "\\"].sample(random: rng))
    when 1 then chars.delete_at(spot)
    when 2 then chars[spot] = [",", "=", '"', " "].sample(random: rng)
    else chars[spot] = chars[spot]
    end
    chars.join
  end
end
