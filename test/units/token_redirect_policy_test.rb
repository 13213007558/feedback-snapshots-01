# frozen_string_literal: true

require_relative "../test_helper"

# Verifies the token_request redirect policy with a local HTTP double.
#
# The double records every request that reaches a server (WebMock stubs fail
# the test if an unapproved destination is contacted), so the tests can show
# that rejected targets never receive OAuth credentials.
class TokenRedirectPolicyTest < Minitest::Test
  include OAuth::MinitestHelpers

  CONSUMER_KEY = "consumer_key"
  CONSUMER_SECRET = "consumer_secret"
  TOKEN_SECRET = "token_secret"

  def setup
    @requests = Hash.new { |hash, key| hash[key] = [] }
    @consumer = OAuth::Consumer.new(
      CONSUMER_KEY,
      CONSUMER_SECRET,
      site: "http://provider.example",
      request_token_path: "/oauth/request_token",
      access_token_path: "/oauth/access_token"
    )
    @token = OAuth::ConsumerToken.new(@consumer, "token_value", TOKEN_SECRET)
  end

  ## Default policy

  def test_cross_origin_redirect_is_rejected_without_sending_credentials
    stub_record(:get, "http://provider.example/oauth/request_token",
                status: 302, headers: { "Location" => "https://attacker.example/oauth/token" })

    error = assert_raises(OAuth::RedirectNotAllowed) do
      @consumer.token_request(:get, "/oauth/request_token", nil, {}) { |body| body }
    end

    assert_equal "https://attacker.example/oauth/token", error.location
    assert_empty @requests["attacker.example"]
    assert_equal 1, @requests["provider.example"].size
  end

  def test_rejected_cross_origin_redirect_does_not_modify_consumer_site
    stub_record(:get, "http://provider.example/oauth/request_token",
                status: 302, headers: { "Location" => "https://attacker.example/oauth/token" })

    assert_raises(OAuth::RedirectNotAllowed) do
      @consumer.token_request(:get, "/oauth/request_token", nil, {})
    end

    assert_equal "http://provider.example", @consumer.site
    assert_equal "http://provider.example", @consumer.options[:site]
    assert_equal "provider.example", @consumer.http.address
  end

  def test_consumer_still_usable_after_rejected_redirect
    stub_record(:get, "http://provider.example/oauth/request_token",
                status: 302, headers: { "Location" => "https://attacker.example/oauth/token" })
    stub_record(:get, "http://provider.example/oauth/request_token",
                status: 200, body: "oauth_token=new&oauth_token_secret=new_secret")

    assert_raises(OAuth::RedirectNotAllowed) do
      @consumer.token_request(:get, "/oauth/request_token", nil, {})
    end

    hash = @consumer.token_request(:get, "/oauth/request_token", nil, {})

    assert_equal "new", hash[:oauth_token]
    assert_equal "new_secret", hash[:oauth_token_secret]
    assert_equal "http://provider.example", @consumer.site
    assert_equal 2, @requests["provider.example"].size
    assert_empty @requests["attacker.example"]
  end

  def test_same_origin_redirect_is_followed_and_resigned
    endpoint = "http://provider.example/oauth/request_token"
    redirected = "http://provider.example/oauth/request_token_v2"

    stub_record(:get, endpoint, status: 302, headers: { "Location" => redirected })
    stub_record(:get, redirected, status: 200, body: "oauth_token=redirected&oauth_token_secret=redirected_secret")

    result = @consumer.token_request(:get, "/oauth/request_token", @token,
                                     { redirect_allowlist: [redirected] }) { |body| body }

    assert_equal "oauth_token=redirected&oauth_token_secret=redirected_secret", result
    assert_equal 2, @requests["provider.example"].size

    first = @requests["provider.example"][0]
    second = @requests["provider.example"][1]
    assert_equal "/oauth/request_token", first.path
    assert_equal "/oauth/request_token_v2", second.path

    refute_equal first.authorization, second.authorization
    refute_equal first.nonce, second.nonce
    assert first.valid_signature?, "first hop should be signed for its own URL"
    assert second.valid_signature?, "redirect hop should carry a signature for the new URL"
  end

  def test_redirect_signature_binds_to_new_path_and_never_reuses_nonce
    endpoint = "http://provider.example/oauth/request_token"
    redirected = "http://provider.example/other/request_token"

    stub_record(:get, endpoint, status: 307, headers: { "Location" => redirected })
    stub_record(:get, redirected, status: 200, body: "ok")

    @consumer.token_request(:get, "/oauth/request_token", @token,
                            { redirect_allowlist: [redirected] })

    first = @requests["provider.example"][0]
    second = @requests["provider.example"][1]

    refute_equal first.nonce, second.nonce
    assert first.nonce_reused_in?(second) == false
    assert second.signed_for?("http://provider.example/other/request_token")
    refute second.signed_for?("http://provider.example/oauth/request_token")
  end

  ## Allowlist

  def test_allowlisted_cross_origin_redirect_is_followed
    redirect_uri = "https://approved.example/oauth/request_token"
    stub_record(:get, "http://provider.example/oauth/request_token",
                status: 302, headers: { "Location" => redirect_uri })
    stub_record(:get, redirect_uri, status: 200, body: "oauth_token=approved")

    result = @consumer.token_request(:get, "/oauth/request_token", @token,
                                     { redirect_allowlist: [redirect_uri] })

    assert_equal "approved", result[:oauth_token]
    assert_equal 1, @requests["approved.example"].size
    hop = @requests["approved.example"][0]
    assert hop.signed_for?(redirect_uri)
    assert_equal "approved.example", hop.host
  end

  def test_cross_origin_same_path_redirect_is_rejected_by_default
    stub_record(:get, "https://provider.example/oauth/request_token",
                status: 302, headers: { "Location" => "https://attacker.example/oauth/request_token" })

    consumer = OAuth::Consumer.new(CONSUMER_KEY, CONSUMER_SECRET, site: "https://provider.example")
    assert_raises(OAuth::RedirectNotAllowed) do
      consumer.token_request(:get, "/oauth/request_token", @token, {})
    end

    assert_empty @requests["attacker.example"]
  end

  def test_supplied_nonce_is_not_reused_on_a_followed_hop
    endpoint = "http://provider.example/oauth/request_token"
    redirected = "http://provider.example/oauth/request_token_v2"
    stub_record(:get, endpoint, status: 302, headers: { "Location" => redirected })
    stub_record(:get, redirected, status: 200, body: "oauth_token=ok")

    @consumer.token_request(:get, "/oauth/request_token", @token,
                            { nonce: "fixed_nonce",
                              redirect_allowlist: [redirected] })

    assert_equal "fixed_nonce", @requests["provider.example"][0].nonce
    refute_equal "fixed_nonce", @requests["provider.example"][1].nonce
    assert @requests["provider.example"][1].valid_signature?
  end

  def test_allowlist_entry_without_path_permits_any_path_on_origin
    stub_record(:get, "http://provider.example/oauth/request_token",
                status: 302, headers: { "Location" => "https://approved.example/any/path" })
    stub_record(:get, "https://approved.example/any/path", status: 200, body: "oauth_token=approved")

    result = @consumer.token_request(:get, "/oauth/request_token", @token,
                                     { redirect_allowlist: ["https://approved.example"] })

    assert_equal "approved", result[:oauth_token]
  end

  def test_allowlist_entry_with_path_only_permits_that_path
    stub_record(:get, "http://provider.example/oauth/request_token",
                status: 302, headers: { "Location" => "https://approved.example/oauth/other" })

    assert_raises(OAuth::RedirectNotAllowed) do
      @consumer.token_request(:get, "/oauth/request_token", @token,
                              { redirect_allowlist: ["https://approved.example/oauth/token"] })
    end

    assert_empty @requests["approved.example"]
  end

  def test_allowlist_port_must_match
    stub_record(:get, "http://provider.example/oauth/request_token",
                status: 302, headers: { "Location" => "https://approved.example:8443/oauth/token" })

    assert_raises(OAuth::RedirectNotAllowed) do
      @consumer.token_request(:get, "/oauth/request_token", @token,
                              { redirect_allowlist: ["https://approved.example/oauth/token"] })
    end

    assert_empty @requests["approved.example"]
  end

  def test_allowlist_hash_without_path_matches_origin
    stub_record(:get, "http://provider.example/oauth/request_token",
                status: 302, headers: { "Location" => "https://approved.example/deep/path" })
    stub_record(:get, "https://approved.example/deep/path", status: 200, body: "oauth_token=hash_origin")

    result = @consumer.token_request(
      :get, "/oauth/request_token", @token,
      { redirect_allowlist: [{ scheme: "https", host: "approved.example", port: 443 }] }
    )

    assert_equal "hash_origin", result[:oauth_token]
  end

  def test_allowlist_hash_entry
    stub_record(:get, "http://provider.example/oauth/request_token",
                status: 302, headers: { "Location" => "https://approved.example/oauth/token" })
    stub_record(:get, "https://approved.example/oauth/token", status: 200, body: "oauth_token=ok")

    result = @consumer.token_request(
      :get, "/oauth/request_token", @token,
      { redirect_allowlist: [{ scheme: "https", host: "approved.example", port: 443, path: "/oauth/token" }] }
    )

    assert_equal "ok", result[:oauth_token]
    assert_equal 1, @requests["approved.example"].size
  end

  def test_ipv6_allowlist_entry_matches
    stub_record(:get, "http://provider.example/oauth/request_token",
                status: 302, headers: { "Location" => "http://[::1]:8080/oauth/token" })
    stub_record(:get, "http://[::1]:8080/oauth/token", status: 200, body: "oauth_token=ipv6")

    result = @consumer.token_request(:get, "/oauth/request_token", @token,
                                     { redirect_allowlist: ["http://[::1]:8080/oauth/token"] })

    assert_equal "ipv6", result[:oauth_token]
  end

  def test_redirect_target_with_userinfo_is_rejected
    stub_record(:get, "http://provider.example/oauth/request_token",
                status: 302, headers: { "Location" => "http://user:pass@approved.example/oauth/token" })

    assert_raises(OAuth::RedirectNotAllowed) do
      @consumer.token_request(:get, "/oauth/request_token", @token,
                              { redirect_policy: :any })
    end

    assert_empty @requests["approved.example"]
  end

  def test_control_characters_in_location_are_rejected
    stub_record(:get, "http://provider.example/oauth/request_token",
                status: 302, headers: { "Location" => "http://approved.example/oauth/token\tX" })

    assert_raises(OAuth::RedirectNotAllowed) do
      @consumer.token_request(:get, "/oauth/request_token", @token,
                              { redirect_policy: :any })
    end

    assert_empty @requests["approved.example"]
  end

  def test_invalid_location_is_rejected
    stub_record(:get, "http://provider.example/oauth/request_token",
                status: 302, headers: { "Location" => "http://[not-a-host/oauth/token" })

    assert_raises(OAuth::RedirectNotAllowed) do
      @consumer.token_request(:get, "/oauth/request_token", @token,
                              { redirect_policy: :any })
    end

    assert_equal 1, @requests["provider.example"].size
  end

  ## HTTPS downgrade

  def test_https_to_http_redirect_is_rejected_even_when_allowlisted
    consumer = OAuth::Consumer.new(CONSUMER_KEY, CONSUMER_SECRET, site: "https://provider.example")
    stub_record(:get, "https://provider.example/oauth/request_token",
                status: 302, headers: { "Location" => "http://approved.example/oauth/token" })

    error = assert_raises(OAuth::RedirectNotAllowed) do
      consumer.token_request(:get, "/oauth/request_token", @token,
                             { redirect_allowlist: ["http://approved.example/oauth/token"] })
    end

    assert_match(/HTTPS/, error.message)
    assert_empty @requests["approved.example"]
  end

  def test_https_to_http_redirect_is_rejected_under_any_policy
    consumer = OAuth::Consumer.new(CONSUMER_KEY, CONSUMER_SECRET, site: "https://provider.example")
    stub_record(:get, "https://provider.example/oauth/request_token",
                status: 302, headers: { "Location" => "http://approved.example/oauth/token" })

    assert_raises(OAuth::RedirectNotAllowed) do
      consumer.token_request(:get, "/oauth/request_token", @token, { redirect_policy: :any })
    end

    assert_empty @requests["approved.example"]
  end

  ## Relative Location and loops

  def test_relative_location_is_resolved_against_the_hop_uri
    stub_record(:get, "http://provider.example/oauth/request_token",
                status: 302, headers: { "Location" => "/oauth/request_token_v2" })
    stub_record(:get, "http://provider.example/oauth/request_token_v2",
                status: 200, body: "oauth_token=relative")

    result = @consumer.token_request(:get, "/oauth/request_token", @token,
                                     { redirect_allowlist: ["http://provider.example/oauth/request_token_v2"] })

    assert_equal "relative", result[:oauth_token]
    assert_equal "/oauth/request_token_v2", @requests["provider.example"][1].path
  end

  def test_dot_segments_in_relative_location_are_canonicalized
    stub_record(:get, "http://provider.example/oauth/token",
                status: 302, headers: { "Location" => "../oauth/./token_v2" })
    stub_record(:get, "http://provider.example/oauth/token_v2", status: 200, body: "oauth_token=canonical")

    result = @consumer.token_request(:get, "/oauth/token", @token,
                                     { redirect_allowlist: ["http://provider.example/oauth/token_v2"] })

    assert_equal "canonical", result[:oauth_token]
  end

  def test_redirect_loop_is_detected
    stub_record(:get, "http://provider.example/oauth/request_token",
                status: 302, headers: { "Location" => "http://provider.example/oauth/request_token" })

    assert_raises(Net::HTTPRetriableError) do
      @consumer.token_request(:get, "/oauth/request_token", nil, {})
    end

    assert_equal 1, @requests["provider.example"].size
  end

  def test_two_hop_loop_is_detected
    first = "http://provider.example/oauth/request_token"
    second = "http://provider.example/oauth/request_token_v2"
    stub_record(:get, first, status: 302, headers: { "Location" => second })
    stub_record(:get, second, status: 302, headers: { "Location" => first })

    assert_raises(Net::HTTPRetriableError) do
      @consumer.token_request(:get, "/oauth/request_token", nil,
                              { redirect_allowlist: [second] })
    end

    assert_equal 2, @requests["provider.example"].size
  end

  def test_redirect_limit_is_enforced
    stub_record(:get, "http://provider.example/oauth/request_token",
                status: 302, headers: { "Location" => "http://provider.example/a" })
    stub_record(:get, "http://provider.example/a",
                status: 302, headers: { "Location" => "http://provider.example/b" })

    assert_raises(Net::HTTPRetriableError) do
      @consumer.token_request(:get, "/oauth/request_token", nil,
                              { redirect_limit: 1,
                                redirect_allowlist: ["http://provider.example/a", "http://provider.example/b"] })
    end
  end

  ## Method changes

  def test_303_changes_post_to_get_and_drops_body
    stub_record(:post, "http://provider.example/oauth/request_token",
                status: 303, headers: { "Location" => "http://provider.example/result" })
    stub_record(:get, "http://provider.example/result", status: 200, body: "oauth_token=ok")

    result = @consumer.token_request(:post, "/oauth/request_token", @token,
                                     { oauth_callback: "oob",
                                       redirect_allowlist: ["http://provider.example/result"] },
                                     { foo: "bar" })

    assert_equal "ok", result[:oauth_token]
    second = @requests["provider.example"][1]
    assert_equal :get, second.method
    assert_nil second.body
  end

  def test_307_preserves_post_method_and_body
    stub_record(:post, "http://provider.example/oauth/request_token",
                status: 307, headers: { "Location" => "http://provider.example/request_token_v2" })
    stub_record(:post, "http://provider.example/request_token_v2", status: 200, body: "oauth_token=ok")

    result = @consumer.token_request(:post, "/oauth/request_token", @token,
                                     { oauth_callback: "oob",
                                       redirect_allowlist: ["http://provider.example/request_token_v2"] },
                                     { foo: "bar" })

    assert_equal "ok", result[:oauth_token]
    second = @requests["provider.example"][1]
    assert_equal :post, second.method
    assert_equal "foo=bar", second.body
  end

  def test_302_post_becomes_get_without_body
    stub_record(:post, "http://provider.example/oauth/request_token",
                status: 302, headers: { "Location" => "http://provider.example/request_token_v2" })
    stub_record(:get, "http://provider.example/request_token_v2", status: 200, body: "oauth_token=ok")

    result = @consumer.token_request(:post, "/oauth/request_token", @token,
                                     { oauth_callback: "oob",
                                       redirect_allowlist: ["http://provider.example/request_token_v2"] },
                                     { foo: "bar" })

    assert_equal "ok", result[:oauth_token]
    assert_equal :get, @requests["provider.example"][1].method
  end

  def test_308_preserves_method
    stub_record(:post, "http://provider.example/oauth/request_token",
                status: 308, headers: { "Location" => "http://provider.example/request_token_v2" })
    stub_record(:post, "http://provider.example/request_token_v2", status: 200, body: "oauth_token=ok")

    @consumer.token_request(:post, "/oauth/request_token", @token,
                            { oauth_callback: "oob",
                              redirect_allowlist: ["http://provider.example/request_token_v2"] },
                            { foo: "bar" })

    assert_equal :post, @requests["provider.example"][1].method
  end

  ## Deny and any policies

  def test_deny_policy_never_follows
    stub_record(:get, "http://provider.example/oauth/request_token",
                status: 301, headers: { "Location" => "http://provider.example/other" })

    assert_raises(OAuth::RedirectNotAllowed) do
      @consumer.token_request(:get, "/oauth/request_token", nil,
                              { redirect_policy: :deny })
    end

    assert_equal 1, @requests["provider.example"].size
  end

  def test_any_policy_follows_approved_shape_without_allowlist
    stub_record(:get, "http://provider.example/oauth/request_token",
                status: 302, headers: { "Location" => "https://elsewhere.example/token" })
    stub_record(:get, "https://elsewhere.example/token", status: 200, body: "oauth_token=any")

    result = @consumer.token_request(:get, "/oauth/request_token", nil,
                                     { redirect_policy: :any })

    assert_equal "any", result[:oauth_token]
    assert_equal 1, @requests["elsewhere.example"].size
  end

  def test_unsupported_3xx_without_location_is_not_followed
    stub_record(:get, "http://provider.example/oauth/request_token",
                status: 304, headers: {})

    assert_raises(OAuth::RedirectNotAllowed) do
      @consumer.token_request(:get, "/oauth/request_token", nil, {})
    end

    assert_equal 1, @requests["provider.example"].size
  end

  def test_unknown_policy_is_rejected_before_any_request
    assert_raises(ArgumentError) do
      @consumer.token_request(:get, "/oauth/request_token", nil,
                              { redirect_policy: :sometimes })
    end

    assert_empty @requests["provider.example"]
  end

  def test_body_stream_is_rewound_for_307_replay
    stream = StringIO.new("payload=stream")
    stub_record(:post, "http://provider.example/oauth/request_token",
                status: 307, headers: { "Location" => "http://provider.example/request_token_v2" })
    stub_record(:post, "http://provider.example/request_token_v2", status: 200, body: "oauth_token=ok")

    @consumer.token_request(:post, "/oauth/request_token", @token,
                            { redirect_allowlist: ["http://provider.example/request_token_v2"] },
                            stream)

    assert_equal "payload=stream", @requests["provider.example"][1].body
  end

  def test_unrewindable_body_stream_is_not_replayed
    stream = Class.new do
      def length
        7
      end

      def read(*)
        "payload"
      end
    end.new

    stub_record(:post, "http://provider.example/oauth/request_token",
                status: 307, headers: { "Location" => "http://provider.example/request_token_v2" })

    assert_raises(OAuth::RedirectNotAllowed) do
      @consumer.token_request(:post, "/oauth/request_token", @token,
                              { redirect_allowlist: ["http://provider.example/request_token_v2"] },
                              stream)
    end

    assert_equal 1, @requests["provider.example"].size
  end

  ## Failure recovery

  def test_hop_does_not_use_configured_request_endpoint_for_signing
    @consumer = OAuth::Consumer.new(
      CONSUMER_KEY, CONSUMER_SECRET,
      site: "http://provider.example",
      request_endpoint: "http://api.provider.example",
      request_token_path: "/oauth/request_token"
    )
    stub_record(:get, "http://api.provider.example/oauth/request_token",
                status: 302, headers: { "Location" => "http://provider.example/oauth/request_token_v2" })
    stub_record(:get, "http://provider.example/oauth/request_token_v2",
                status: 200, body: "oauth_token=ok")

    @consumer.token_request(:get, "/oauth/request_token", @token,
                            { redirect_allowlist: ["http://provider.example/oauth/request_token_v2"] })

    hop = @requests["provider.example"][0]
    assert hop.signed_for?("http://provider.example/oauth/request_token_v2")
    assert_equal "http://api.provider.example", @consumer.request_endpoint
    assert_equal "api.provider.example", @consumer.http.address
  end

  def test_rejected_redirect_keeps_original_request_endpoint_config
    @consumer = OAuth::Consumer.new(
      CONSUMER_KEY, CONSUMER_SECRET,
      site: "http://provider.example",
      request_endpoint: "http://api.provider.example",
      request_token_path: "/oauth/request_token"
    )
    stub_record(:get, "http://api.provider.example/oauth/request_token",
                status: 302, headers: { "Location" => "https://attacker.example/token" })

    assert_raises(OAuth::RedirectNotAllowed) do
      @consumer.token_request(:get, "/oauth/request_token", nil, {})
    end

    assert_equal "http://api.provider.example", @consumer.request_endpoint
    assert_equal "http://provider.example", @consumer.site
    assert_equal "api.provider.example", @consumer.http.address
  end

  def test_failed_redirect_hop_leaves_http_connection_unchanged
    stub_record(:get, "http://provider.example/oauth/request_token",
                status: 302, headers: { "Location" => "http://provider.example/request_token_v2" })
    stub_record(:get, "http://provider.example/request_token_v2", status: 500, body: "boom")

    original_http = @consumer.http

    assert_raises(Net::HTTPFatalError) do
      @consumer.token_request(:get, "/oauth/request_token", nil,
                              { redirect_allowlist: ["http://provider.example/request_token_v2"] })
    end

    assert_same original_http, @consumer.http
    assert_equal "http://provider.example", @consumer.site
  end

  private

  RemoteRequest = Struct.new(:method, :path, :host, :authorization, :body, :uri, :content_type, keyword_init: true) do
    def nonce
      oauth_parameters["oauth_nonce"]
    end

    def signed_for?(url)
      oauth_parameters["oauth_signature"] == signature_for(url)
    end

    def valid_signature?
      signed_for?(uri)
    end

    def signature_for(url)
      parameters = oauth_parameters.reject { |key, _| key == "oauth_signature" }
      if %i[post put].include?(method) && content_type.to_s.downcase.start_with?("application/x-www-form-urlencoded")
        CGI.parse(body.to_s).each do |key, values|
          parameters[key] = values.first
        end
      end
      proxy = OAuth::RequestProxy.proxy(
        "method" => method.to_s.upcase,
        "uri" => url,
        "parameters" => parameters
      )
      OAuth::Signature.sign(proxy, consumer_secret: CONSUMER_SECRET, token_secret: TOKEN_SECRET)
    end

    def nonce_reused_in?(other)
      !nonce.nil? && nonce == other.nonce
    end

    def oauth_parameters
      @oauth_parameters ||= if authorization.nil?
                              {}
                            else
                              OAuth::Helper.parse_header(authorization)
                            end
    end
  end

  # Record a request/response on the local double. Calling this repeatedly
  # for the same destination queues responses; the last one repeats.
  def stub_record(method, url, status: 200, headers: {}, body: nil)
    key = [method, url]
    @responses ||= {}
    @stubbed ||= {}
    responses = (@responses[key] ||= [])
    responses << { status: status, headers: headers, body: body || "" }

    return if @stubbed[key]

    @stubbed[key] = true
    stub_request(method, url).to_return do |request|
      record(request, url)
      responses.length > 1 ? responses.shift : responses.first
    end
  end

  def record(request, url)
    uri = URI.parse(url)
    entry = RemoteRequest.new(
      method: request.method.to_s.downcase.to_sym,
      path: request.uri.path,
      host: uri.host,
      authorization: request.headers["Authorization"],
      body: request.body,
      uri: url,
      content_type: request.headers["Content-Type"]
    )
    @requests[uri.host] << entry
    entry
  end
end
