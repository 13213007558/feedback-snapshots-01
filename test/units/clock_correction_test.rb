# frozen_string_literal: true

require_relative "../test_helper"

class ClockCorrectionTest < Minitest::Test
  def setup
    @site = "http://api.example.com"
    @path = "/resource"
    @url = @site + @path
    @now = Time.now.to_i
    @requests = []
  end

  def build_consumer(evidence: nil, **options)
    config = {trusted_time_source: evidence}.merge(options).compact
    OAuth::Consumer.new(
      "consumer_key",
      "consumer_secret",
      {site: @site, clock_correction: config}
    )
  end

  def build_token(consumer)
    OAuth::ConsumerToken.new(consumer, "token", "token_secret")
  end

  def post(consumer, token, body: "a=1", headers: {"Idempotency-Key" => "same-key"})
    consumer.request(:post, @path, token, {clock_correction: true}, body, headers)
  end

  def stub_sequence(responses)
    stub_request(:post, @url).to_return do |request|
      @requests << {
        authorization: request.headers["Authorization"],
        body: request.body,
        idempotency_key: request.headers["Idempotency-Key"],
        uri: request.uri.to_s
      }
      responses[[@requests.length - 1, responses.length - 1].min].call(request)
    end
  end

  def timestamp_refused_response
    lambda do |_request|
      {
        status: 401,
        headers: {"WWW-Authenticate" => 'OAuth oauth_problem="timestamp_refused", oauth_problem_advice="clock skew"'},
        body: ""
      }
    end
  end

  def success_response
    lambda { |_request| {status: 200, body: "ok"} }
  end

  def consumer_problem(response)
    OAuth::Problem.new("timestamp_refused", response)
  end

  def auth_parameter(authorization, name)
    match = authorization.to_s.match(/oauth_#{Regexp.escape(name)}="([^"]+)"/)
    match && CGI.unescape(match[1])
  end

  def test_corrects_clock_with_trusted_same_service_evidence
    consumer = build_consumer(evidence: ->(_response, _context) { @now + 30 }, max_offset_seconds: 60)
    token = build_token(consumer)
    stub_sequence([timestamp_refused_response, success_response])

    response = post(consumer, token)

    assert_equal "200", response.code
    outcome = consumer.last_clock_correction_outcome
    assert_equal :corrected, outcome.result
    assert_equal 2, outcome.request_count
    assert_equal 30, outcome.offset_seconds
    assert_in_delta @now + 30, outcome.attempts[1][:oauth_timestamp].to_i, 2
    assert_nil outcome.reason, "successful correction has no failure reason"
    refute outcome.manual_retry?
    assert_equal 2, @requests.length

    first = @requests[0]
    second = @requests[1]
    assert_equal "same-key", first[:idempotency_key]
    assert_equal "same-key", second[:idempotency_key]
    assert_equal first[:body], second[:body]
    refute_equal auth_parameter(first[:authorization], "nonce"), auth_parameter(second[:authorization], "nonce")
    refute_equal auth_parameter(first[:authorization], "timestamp"), auth_parameter(second[:authorization], "timestamp")
    assert_equal "consumer_key", auth_parameter(second[:authorization], "consumer_key")
  end

  def test_rejects_maliciously_large_offset_without_replay
    consumer = build_consumer(evidence: ->(_response, _context) { @now + 100_000 }, max_offset_seconds: 60)
    token = build_token(consumer)
    stub_sequence([timestamp_refused_response])

    error = assert_raises(OAuth::Problem) { post(consumer, token) }

    assert_equal "timestamp_refused", error.problem
    outcome = consumer.last_clock_correction_outcome
    assert_equal :offset_rejected, outcome.result
    assert_equal :offset_exceeds_limit, outcome.reason
    assert_equal 1, outcome.request_count
    assert_operator outcome.observed_offset_seconds, :>, 60
    assert outcome.manual_retry?
    assert_equal 1, @requests.length
    assert_empty consumer.clock_correction_offsets
  end

  def test_does_not_replay_when_outcome_is_unknown_after_timeout
    consumer = build_consumer(evidence: ->(_response, _context) { @now + 30 }, max_offset_seconds: 60)
    token = build_token(consumer)
    stub_sequence([->(_request) { raise Net::ReadTimeout.new("read timed out") }])

    assert_raises(Net::ReadTimeout) { post(consumer, token) }

    outcome = consumer.last_clock_correction_outcome
    assert_equal :unknown_outcome, outcome.result
    assert_equal 1, outcome.request_count
    assert outcome.manual_retry?
    assert_equal 1, @requests.length
  end

  def test_does_not_adjust_without_trusted_evidence
    consumer = build_consumer
    token = build_token(consumer)
    stub_sequence([timestamp_refused_response])

    assert_raises(OAuth::Problem) { post(consumer, token) }

    outcome = consumer.last_clock_correction_outcome
    assert_equal :evidence_unavailable, outcome.result
    assert_equal 1, outcome.request_count
    assert outcome.manual_retry?
    assert_equal 1, @requests.length
  end

  def test_does_not_trust_cross_origin_rejection
    correction = OAuth::Client::ClockCorrection.new(
      {trusted_time_source: ->(_response, _context) { @now + 30 }, max_offset_seconds: 60}
    )
    cross_origin_response = Net::HTTPUnauthorized.new("1.1", "401", "Unauthorized")
    cross_origin_response.uri = URI.parse("https://evil.example/oauth")
    cross_origin_response["WWW-Authenticate"] = 'OAuth oauth_problem="timestamp_refused"'
    cross_origin_response.instance_variable_set(:@body, "")

    request = Object.new
    request.define_singleton_method(:method) { "POST" }
    request.define_singleton_method(:path) { @path }
    request.define_singleton_method(:body) { "a=1" }

    outcome = correction.execute(
      target_origin: @site,
      http_method: :post,
      build_request: ->(_options) { request },
      transport: ->(_req) { cross_origin_response },
      problem_for: ->(response) { consumer_problem(response) }
    )

    assert_equal :cross_origin_rejected, outcome.result
    assert_equal 1, outcome.request_count
    assert outcome.manual_retry?
    assert_empty correction.offsets
  end

  def test_retry_count_is_bounded_and_uses_fresh_timestamp_and_nonce
    consumer = build_consumer(evidence: ->(_response, _context) { @now + 5 }, max_offset_seconds: 60,
                             max_retries: 2)
    token = build_token(consumer)
    stub_sequence([timestamp_refused_response])

    assert_raises(OAuth::Problem) { post(consumer, token) }

    outcome = consumer.last_clock_correction_outcome
    assert_equal :timestamp_refused, outcome.result
    assert_equal 3, outcome.request_count
    assert_equal 2, outcome.max_retries
    assert_equal 3, @requests.length
    timestamps = outcome.attempts.map { |attempt| attempt[:oauth_timestamp] }
    nonces = outcome.attempts.map { |attempt| attempt[:oauth_nonce] }
    assert_equal 3, timestamps.uniq.length
    assert_equal 3, nonces.uniq.length
  end

  def test_offset_is_scoped_to_the_service_and_not_global_clock
    consumer = build_consumer(evidence: ->(_response, _context) { @now + 30 }, max_offset_seconds: 60)
    token = build_token(consumer)
    stub_sequence([timestamp_refused_response, success_response])
    actual_time = Time.now.to_i
    post(consumer, token)
    assert_operator consumer.clock_correction_offsets[@site], :>, 0
    assert_in_delta actual_time, Time.now.to_i, 2

    other_site = "http://other.example.com"
    other_consumer = OAuth::Consumer.new("consumer_key", "consumer_secret", {site: other_site})
    stub_request(:get, "#{other_site}/ping").to_return(body: "ok")
    token_two = build_token(other_consumer)
    other_consumer.request(:get, "/ping", token_two)

    assert_empty other_consumer.clock_correction_offsets
    assert_in_delta actual_time, Time.now.to_i, 2
  end

  def test_refuses_non_timestamp_oauth_problems
    consumer = build_consumer(evidence: ->(_response, _context) { @now + 30 }, max_offset_seconds: 60)
    token = build_token(consumer)
    stub_sequence([lambda do |_request|
      {status: 401, headers: {"WWW-Authenticate" => 'OAuth oauth_problem="token_rejected"'}, body: ""}
    end])

    error = assert_raises(OAuth::Problem) { post(consumer, token) }

    assert_equal "token_rejected", error.problem
    outcome = consumer.last_clock_correction_outcome
    assert_equal :oauth_problem, outcome.result
    assert_equal 1, outcome.request_count
    refute outcome.manual_retry?
    assert_equal 1, @requests.length
  end

  def test_consumer_can_disable_correction_for_a_single_request
    consumer = build_consumer(evidence: ->(_response, _context) { @now + 30 }, max_offset_seconds: 60)
    token = build_token(consumer)
    stub_sequence([timestamp_refused_response])

    assert_raises(OAuth::Problem) do
      consumer.request(:post, @path, token, {clock_correction: false}, "a=1", {"Idempotency-Key" => "k"})
    end

    assert_nil consumer.last_clock_correction_outcome, "opt-out must not run correction"
    assert_equal 1, @requests.length
  end

  def test_non_rewindable_write_body_is_not_replayed
    consumer = build_consumer(evidence: ->(_response, _context) { @now + 30 }, max_offset_seconds: 60)
    token = build_token(consumer)
    stub_sequence([timestamp_refused_response])
    stream = Object.new
    stream.define_singleton_method(:read) { |*_args| "a=1" }
    stream.define_singleton_method(:length) { 3 }

    assert_raises(OAuth::Problem) do
      consumer.request(:post, @path, token, {clock_correction: true}, stream, {"Idempotency-Key" => "k"})
    end

    outcome = consumer.last_clock_correction_outcome
    assert_equal :body_not_replayable, outcome.result
    assert_equal 1, outcome.request_count
    assert outcome.manual_retry?
    assert_equal 1, @requests.length
  end

  def test_rewindable_stream_body_is_replayed_without_duplication
    consumer = build_consumer(evidence: ->(_response, _context) { @now + 30 }, max_offset_seconds: 60)
    token = build_token(consumer)
    stub_sequence([timestamp_refused_response, success_response])
    stream = StringIO.new("payload-data")
    consumer.stubs(:replayable_request_body?).returns(true)

    response = consumer.request(:post, @path, token, {clock_correction: true}, stream,
                                {"Idempotency-Key" => "same-key"})

    assert_equal "200", response.code
    assert_equal ["payload-data", "payload-data"], @requests.map { |request| request[:body] }
    outcome = consumer.last_clock_correction_outcome
    assert_equal :corrected, outcome.result
    assert_nil outcome.attempts[0][:body_fingerprint], "stream bodies are not fingerprinted"
    assert_nil outcome.attempts[1][:body_fingerprint]
  end

  def test_caller_block_can_stop_before_sending
    consumer = build_consumer(evidence: ->(_response, _context) { @now + 30 }, max_offset_seconds: 60)
    token = build_token(consumer)

    result = consumer.request(:post, @path, token, {clock_correction: true}, "a=1", {}) { |_request| :done }

    assert_nil result, "the halt path returns nil"
    assert_equal :halted, consumer.last_clock_correction_outcome.result
    assert_equal 0, consumer.last_clock_correction_outcome.request_count
    assert_nil consumer.last_clock_correction_outcome.error
  end

  def test_body_scheme_retry_keeps_business_body_but_refreshes_oauth_parameters
    consumer = build_consumer(evidence: ->(_response, _context) { @now + 30 }, max_offset_seconds: 60,
                             scheme: :body)
    token = build_token(consumer)
    stub_sequence([timestamp_refused_response, success_response])

    response = consumer.request(:post, @path, token, {clock_correction: true, scheme: :body}, "biz=1",
                                {"Idempotency-Key" => "same-key"})

    assert_equal "200", response.code
    outcome = consumer.last_clock_correction_outcome
    assert_equal :corrected, outcome.result
    assert_equal 2, @requests.length
    assert_equal "same-key", @requests[0][:idempotency_key]
    assert_equal "same-key", @requests[1][:idempotency_key]
    assert_equal outcome.attempts[0][:body_fingerprint], outcome.attempts[1][:body_fingerprint]
    refute_equal outcome.attempts[0][:body_sha256], outcome.attempts[1][:body_sha256]
    refute_equal @requests[0][:body], @requests[1][:body]
  end

  def test_outcome_exposes_signature_parameters_for_audit
    consumer = build_consumer(evidence: ->(_response, _context) { @now + 30 }, max_offset_seconds: 60)
    token = build_token(consumer)
    stub_sequence([timestamp_refused_response, success_response])
    post(consumer, token)

    outcome = consumer.last_clock_correction_outcome
    assert_equal 2, outcome.attempts.length
    outcome.attempts.each do |attempt|
      assert_equal "consumer_key", attempt[:oauth_parameters]["oauth_consumer_key"]
      assert attempt[:oauth_parameters]["oauth_signature"]
      assert attempt[:oauth_parameters]["oauth_timestamp"]
      assert attempt[:oauth_parameters]["oauth_nonce"]
      assert_equal "same-key", attempt[:idempotency_key]
    end
    assert_equal outcome.attempts[0][:body_sha256], outcome.attempts[1][:body_sha256]
  end
end
