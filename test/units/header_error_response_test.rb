# frozen_string_literal: true

require_relative "../test_helper"

# Covers the WWW-Authenticate error-response entry point (OAuth Problem
# Reporting). A provider rejects a request by returning an OAuth challenge
# header carrying oauth_problem; that header goes through the same shared
# parser as Authorization, so malformed or ambiguous challenges must surface
# as OAuth::Problem rather than being misread.
class HeaderErrorResponseTest < Minitest::Test
  def build_consumer
    consumer = OAuth::Consumer.new("consumer_key", "consumer_secret", site: "http://example.com")
    # Minimal stand-in for Net::HTTP covering only the surface touched while
    # building and dispatching a signed request.
    consumer.http = stub(
      "address" => "example.com",
      "port" => 80,
      "use_ssl?" => false
    )
    consumer
  end

  def challenge_response(header)
    response = stub
    response.stubs(:to_hash).returns("www-authenticate" => Array(header))
    response.stubs(:code).returns(401)
    response.stubs(:message).returns("Unauthorized")
    response.stubs(:body).returns("")
    response
  end

  # Stub the network round-trip so consumer#request runs its real challenge
  # detection and parsing logic without constructing a live connection.
  def stub_round_trip(consumer, response)
    consumer.http.stubs(:request).returns(response)
  end

  def test_oauth_problem_header_raises_problem_with_decoded_params
    consumer = build_consumer
    response = challenge_response(
      'OAuth realm="http://example.com", oauth_problem="token_expired", ' \
      'oauth_acceptable_timestamps="1240004133-1240004999"'
    )
    stub_round_trip(consumer, response)

    error = assert_raises(OAuth::Problem) do
      consumer.request(:get, "/protected", nil, {})
    end

    assert_equal "token_expired", error.problem
    assert_equal response, error.request
    # realm is retained as context; the problem key itself is consumed.
    assert_equal "http://example.com", error.params["realm"]
    assert_equal "1240004133-1240004999", error.params["oauth_acceptable_timestamps"]
    refute error.params.key?("oauth_problem")
  end

  def test_encoded_separators_in_challenge_round_trip
    consumer = build_consumer
    response = challenge_response(
      'OAuth oauth_problem="parameter_absent", oauth_parameters_absent="oauth_token%2Coauth_nonce"'
    )
    stub_round_trip(consumer, response)

    error = assert_raises(OAuth::Problem) do
      consumer.request(:get, "/protected", nil, {})
    end

    assert_equal "parameter_absent", error.problem
    assert_equal "oauth_token,oauth_nonce", error.params["oauth_parameters_absent"]
  end

  def test_malformed_challenge_header_is_not_swallowed
    consumer = build_consumer
    response = challenge_response('OAuth oauth_problem="token_expired", oauth_problem="nonce_used"')
    stub_round_trip(consumer, response)

    # A duplicated oauth_problem is ambiguous and must raise rather than pick
    # one of the two values.
    assert_raises(OAuth::Problem) do
      consumer.request(:get, "/protected", nil, {})
    end
  end

  def test_non_oauth_challenge_is_ignored
    consumer = build_consumer
    response = challenge_response('Basic realm="example.com"')
    stub_round_trip(consumer, response)

    # Only "OAuth " challenges drive Problem handling; other schemes pass the
    # raw response back to the caller.
    assert_same response, consumer.request(:get, "/protected", nil, {})
  end

  def test_oauth_challenge_without_problem_key_returns_response
    consumer = build_consumer
    response = challenge_response('OAuth realm="http://example.com"')
    stub_round_trip(consumer, response)

    assert_same response, consumer.request(:get, "/protected", nil, {})
  end

  def test_helper_rejects_malformed_www_authenticate_directly
    [
      'OAuth oauth_problem="bad%zz"',
      'OAuth oauth_problem="unterminated',
      'OAuth oauth_problem="x",, realm="r"'
    ].each do |header|
      assert_raises(OAuth::Problem, "expected rejection of #{header.inspect}") do
        OAuth::Helper.parse_header(header)
      end
    end
  end
end
