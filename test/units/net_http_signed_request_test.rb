# frozen_string_literal: true

require_relative "../test_helper"

class NetHTTPSignedRequestTest < Minitest::Test
  def setup
    @consumer = OAuth::Consumer.new("consumer_key_86cad9", "5888bf0345e5d237")
    @token = OAuth::Token.new("token_411a7f", "3196ffd991c8ebdb")
    @nonce = 225_579_211_881_198_842_005_988_698_334_675_835_446
    @timestamp = "1199645624"
    @http = RecordingHttpDouble.new("example.com", 80)
  end

  def test_wrapping_an_unsigned_request_is_rejected
    request = Net::HTTP::Get.new("/test")

    assert_raises(ArgumentError) { OAuth::Client::SignedRequest.new(request, http: @http) }
  end

  def test_perform_sends_the_signed_request_and_records_actual_bytes
    signed = signed_post_data_request

    response = signed.perform

    assert_equal "200", response.code
    assert_equal 1, @http.recorded.size
    recorded = @http.recorded.last
    assert_equal "POST", recorded.method
    assert_equal "/test", recorded.target
    assert_equal "data", recorded.body
    assert_matching_headers "oauth_nonce=\"225579211881198842005988698334675835446\", oauth_body_hash=\"oXyaqmHoChv3HQ2FCvTluqmAC70%3D\", oauth_signature_method=\"HMAC-SHA1\", oauth_token=\"token_411a7f\", oauth_timestamp=\"1199645624\", oauth_consumer_key=\"consumer_key_86cad9\", oauth_signature=\"0DA6pGTapdHSqC15RZelY5rNLDw%3D\", oauth_version=\"1.0\"",
                            recorded.headers["authorization"]
    assert_includes recorded.raw_bytes, "POST /test HTTP/1.1\r\n"
    assert_includes recorded.raw_bytes, "\r\n\r\ndata"
  end

  def test_changing_the_query_after_signing_is_rejected
    request = Net::HTTP::Get.new("/test?key=value")
    signed = OAuth::Client::SignedRequest.new(request, http: @http, consumer: @consumer, token: @token,
                                              nonce: @nonce, timestamp: @timestamp)

    # business code appends a query parameter after signing
    request.instance_variable_set(:@path, "/test?key=value&extra=1")

    assert_equal %i[target parameters], signed.changes
    error = assert_raises(OAuth::Client::SignedRequest::SignatureInvalidatedError) { signed.perform }
    assert_includes error.changes, :target
    assert_includes error.changes, :parameters
    assert_empty @http.recorded
  end

  def test_changing_the_body_after_signing_is_rejected
    signed = signed_post_data_request

    # business code replaces the body after signing
    signed.request.body = "tampered"

    assert_equal %i[body], signed.changes
    error = assert_raises(OAuth::Client::SignedRequest::SignatureInvalidatedError) { signed.perform }
    assert_includes error.changes, :body
    assert_empty @http.recorded
  end

  def test_changing_form_parameters_after_signing_is_rejected
    request = Net::HTTP::Post.new("/test")
    request.set_form_data("key" => "value")
    signed = OAuth::Client::SignedRequest.new(request, http: @http, consumer: @consumer, token: @token,
                                              nonce: @nonce, timestamp: @timestamp)

    request.set_form_data("key" => "other")

    error = assert_raises(OAuth::Client::SignedRequest::SignatureInvalidatedError) { signed.perform }
    assert_includes error.changes, :parameters
    assert_empty @http.recorded
  end

  def test_changing_the_content_type_of_a_body_after_signing_is_rejected
    request = Net::HTTP::Post.new("/test")
    request.set_form_data("key" => "value")
    signed = OAuth::Client::SignedRequest.new(request, http: @http, consumer: @consumer, token: @token,
                                              nonce: @nonce, timestamp: @timestamp)

    # Content-Type decides whether the body is signed as parameters or via oauth_body_hash
    request.content_type = "text/plain"

    error = assert_raises(OAuth::Client::SignedRequest::SignatureInvalidatedError) { signed.perform }
    assert_includes error.changes, :content_type
    assert_empty @http.recorded
  end

  def test_adding_an_unrelated_transport_header_after_signing_is_allowed
    signed = signed_post_data_request
    original_authorization = signed.request["Authorization"]

    signed["Accept"] = "application/json"
    signed["User-Agent"] = "MyApp"

    assert signed.valid?
    response = signed.perform
    assert_equal "200", response.code

    recorded = @http.recorded.last
    assert_equal "application/json", recorded.headers["accept"]
    assert_equal "MyApp", recorded.headers["user-agent"]
    assert_equal original_authorization, recorded.headers["authorization"]
    assert_includes recorded.raw_bytes, "accept: application/json\r\n"
  end

  def test_resign_after_a_mutation_sends_with_a_fresh_nonce
    request = Net::HTTP::Get.new("/test?key=value")
    signed = OAuth::Client::SignedRequest.new(request, http: @http, consumer: @consumer, token: @token,
                                              nonce: @nonce, timestamp: @timestamp)
    request.instance_variable_set(:@path, "/test?key=value&extra=1")
    assert_raises(OAuth::Client::SignedRequest::SignatureInvalidatedError) { signed.perform }

    signed.resign!

    assert signed.valid?
    signed.perform
    recorded = @http.recorded.last
    assert_equal "/test?key=value&extra=1", recorded.target
    oauth_params = OAuth::Helper.parse_header(recorded.headers["authorization"])
    refute_equal @nonce.to_s, oauth_params["oauth_nonce"]
    refute_equal @timestamp, oauth_params["oauth_timestamp"]
  end

  def test_resign_accepts_explicit_nonce_and_timestamp
    signed = signed_post_data_request
    signed.request.body = "changed"

    signed.resign!(nonce: "explicit-nonce", timestamp: "999")

    signed.perform
    oauth_params = OAuth::Helper.parse_header(@http.recorded.last.headers["authorization"])
    assert_equal "explicit-nonce", oauth_params["oauth_nonce"]
    assert_equal "999", oauth_params["oauth_timestamp"]
  end

  def test_a_performed_request_cannot_be_resent_without_resigning
    signed = signed_post_data_request
    signed.perform

    assert_raises(OAuth::Client::SignedRequest::AlreadyPerformedError) { signed.perform }
    assert_equal 1, @http.recorded.size

    # a retry after a signature failure is an explicit, freshly-signed request
    signed.resign!
    signed.perform

    assert_equal 2, @http.recorded.size
    nonces = @http.recorded.map { |recorded| OAuth::Helper.parse_header(recorded.headers["authorization"])["oauth_nonce"] }
    assert_equal 2, nonces.uniq.size
  end

  def test_body_stream_is_buffered_reread_and_bound
    request = Net::HTTP::Post.new("/test")
    request.content_type = "application/octet-stream"
    request.body_stream = StringIO.new("stream-bytes")
    signed = OAuth::Client::SignedRequest.new(request, http: @http, consumer: @consumer, token: @token,
                                              nonce: @nonce, timestamp: @timestamp)

    signed.perform

    assert_equal "stream-bytes", @http.recorded.last.body

    # the stream was consumed by the transport, but a re-sign rewinds the
    # buffer so the retry sends the same bytes with a fresh nonce
    signed.resign!
    signed.perform

    assert_equal 2, @http.recorded.size
    assert_equal "stream-bytes", @http.recorded.last.body
  end

  def test_replacing_the_body_stream_after_signing_is_rejected
    request = Net::HTTP::Post.new("/test")
    request.content_type = "application/octet-stream"
    request.body_stream = StringIO.new("stream-bytes")
    signed = OAuth::Client::SignedRequest.new(request, http: @http, consumer: @consumer, token: @token,
                                              nonce: @nonce, timestamp: @timestamp)

    request.body_stream = StringIO.new("tampered-bytes")

    error = assert_raises(OAuth::Client::SignedRequest::SignatureInvalidatedError) { signed.perform }
    assert_includes error.changes, :body
    assert_empty @http.recorded
  end

  def test_wrapping_an_externally_signed_request
    request = Net::HTTP::Get.new("/test?key=value")
    request.oauth!(@http, @consumer, @token, { nonce: @nonce, timestamp: @timestamp })

    signed = OAuth::Client::SignedRequest.new(request, http: @http)

    assert signed.valid?
    signed.perform
    assert_equal 1, @http.recorded.size
  end

  def test_plain_net_http_request_interface_still_completes_normal_requests
    stub_request(:post, "http://example.com/test").to_return(status: 200, body: "ok")
    http = Net::HTTP.new("example.com", 80)
    request = Net::HTTP::Post.new("/test")
    request.set_form_data("key" => "value")
    request.oauth!(http, @consumer, @token, { nonce: @nonce, timestamp: @timestamp })

    response = http.request(request)

    assert_equal "200", response.code
    assert_equal "ok", response.body
  end

  def test_plain_signed_request_also_works_through_the_double
    request = Net::HTTP::Get.new("/test?key=value")
    request.oauth!(@http, @consumer, @token, { nonce: @nonce, timestamp: @timestamp })

    response = @http.request(request)

    assert_equal "200", response.code
    assert_equal "GET", @http.recorded.last.method
    assert_equal "/test?key=value", @http.recorded.last.target
  end

  protected

  def signed_post_data_request
    request = Net::HTTP::Post.new("/test")
    request.body = "data"
    request.content_type = "text/ascii"
    OAuth::Client::SignedRequest.new(request, http: @http, consumer: @consumer, token: @token,
                                     nonce: @nonce, timestamp: @timestamp)
  end
end
