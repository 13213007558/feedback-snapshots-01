# frozen_string_literal: true

require_relative "../test_helper"

require "oauth/request_proxy/rack_request"

# Demonstrates the concrete attack the grammar-driven parser closes: an
# attacker appends a second auth-param whose name duplicates a field that
# participates in the signature. A naive Hash/ split parser keeps the *last*
# value, so the verified credential silently changes. These tests pin that the
# override attempt is rejected deterministically at every shared entry point,
# and include the exact "minimally different" headers plus a replayable seed.
class HeaderFieldOverrideTest < Minitest::Test
  # Pinned so the demonstration is replayable; kept identical to the fuzz
  # seed (FUZZ_SEED) in header_parser_test.rb.
  DEMO_SEED = 20_261_114

  SIGNED_FIELDS = %w[
    oauth_consumer_key oauth_token oauth_signature_method
    oauth_timestamp oauth_nonce oauth_version oauth_signature
  ].freeze

  def benign_header
    'OAuth oauth_consumer_key="key", oauth_nonce="nonce", ' \
      'oauth_signature="sig", oauth_timestamp="1240004133"'
  end

  def test_minimally_different_header_adds_one_duplicate_field
    benign = benign_header
    # The attack differs from the benign header by a single appended param.
    attack = benign + ', oauth_signature="forged"'

    assert_equal 1, attack.split(", ").size - benign.split(", ").size
    assert OAuth::HeaderParser.parse(benign).is_a?(Hash)
    assert_raises(OAuth::Problem) { OAuth::HeaderParser.parse(attack) }
  end

  def test_duplicate_signature_field_is_rejected_not_last_wins
    attack = 'OAuth oauth_signature="legit", oauth_signature="forged"'

    assert_raises(OAuth::Problem) { OAuth::Helper.parse_header(attack) }
  end

  def test_duplicate_field_cannot_change_verified_credential_in_rack_proxy
    attack = benign_header + ', oauth_consumer_key="attacker-key"'

    assert_raises(OAuth::Problem) do
      env = Rack::MockRequest.env_for("http://example.com/r", "HTTP_AUTHORIZATION" => attack)
      OAuth::RequestProxy.proxy(Rack::Request.new(env), uri: "http://example.com/r").parameters
    end
  end

  def test_duplicate_field_cannot_change_credential_in_www_authenticate
    challenge = 'OAuth oauth_problem="token_expired", oauth_problem="signature_invalid"'

    assert_raises(OAuth::Problem) { OAuth::Helper.parse_header(challenge) }
  end

  def test_legacy_split_parser_would_have_been_vulnerable
    # Reproduces the pre-fix Hash[*split] semantics (strip, unescape and
    # quote removal included) purely inside the test to document why the
    # override was possible: the last duplicate wins.
    legacy = lambda do |header|
      params = header[6, header.length].split(/[,=&]/)
      raise OAuth::Problem if params.size.odd?

      params = params.map { |v| OAuth::Helper.unescape(v.strip).sub(/\A"(.*)"\z/, '\1') }
      Hash[*params]
    end

    result = legacy.call('OAuth oauth_signature="legit", oauth_signature="forged"')
    assert_equal "forged", result["oauth_signature"]

    # The shipped parser refuses the same header instead.
    assert_raises(OAuth::Problem) do
      OAuth::Helper.parse_header('OAuth oauth_signature="legit", oauth_signature="forged"')
    end
  end

  def test_demo_seed_is_stable_and_documented
    srand(DEMO_SEED)
    header = benign_header + ", oauth_nonce=\"#{rand}\""

    # Different nonce value, same field name -> always a duplicate, always
    # rejected regardless of the random value the seed produces.
    assert_raises(OAuth::Problem) { OAuth::HeaderParser.parse(header) }
  end

  def test_each_signed_field_duplicate_is_rejected
    SIGNED_FIELDS.each do |field|
      header = "OAuth #{field}=\"a\", #{field}=\"b\""
      assert_raises(OAuth::Problem, "duplicate #{field} must be rejected") do
        OAuth::HeaderParser.parse(header)
      end
    end
  end
end
