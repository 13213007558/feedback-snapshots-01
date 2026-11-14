# frozen_string_literal: true

require_relative "../test_helper"

require "oauth/request_proxy/rack_request"
require "net/http"

# End-to-end coverage for the query-string -> Authorization header migration:
# the signing side (Net::HTTP) and the verifying side (Rack request proxy) are
# exercised together, proving both legal carriers authenticate, business data
# is preserved, the header-mode URL carries no credentials, and any request
# that splits protocol parameters across carriers is rejected.
class RackHeaderMigrationTest < Minitest::Test
  ENDPOINT = URI("http://api.example.com/v1/orders").freeze
  BUSINESS_QUERY = { "status" => "open", "page" => "2" }.freeze
  BUSINESS_FORM = { "note" => "urgent" }.freeze
  SIGN_OPTIONS = { nonce: "fixed-nonce-0001", timestamp: "1700000000" }.freeze

  def setup
    @consumer = OAuth::Consumer.new("consumer-key", "consumer-secret",
                                    site: "http://api.example.com", body_hash_enabled: false)
    @token = OAuth::Token.new("token-key", "token-secret")
  end

  # --- signing-side helpers -------------------------------------------------

  def build_signed_request(scheme)
    request = Net::HTTP::Post.new("#{ENDPOINT.path}?#{OAuth::Helper.normalize(BUSINESS_QUERY)}")
    request.set_form_data(BUSINESS_FORM)
    request["Content-Type"] = "application/x-www-form-urlencoded"
    request.oauth!(@consumer.http, @consumer, @token, SIGN_OPTIONS.merge(scheme: scheme))
    request
  end

  # Turn an outbound Net::HTTP request into the Rack env a provider would see.
  def rack_env_for(request, path_override: nil)
    Rack::MockRequest.env_for(
      "http://api.example.com#{path_override || request.path}",
      method: request.method,
      "HTTP_AUTHORIZATION" => request["Authorization"],
      "CONTENT_TYPE" => request["Content-Type"],
      input: request.body
    )
  end

  def proxy_for(env)
    OAuth::RequestProxy.proxy(Rack::Request.new(env), consumer: @consumer, token: @token)
  end

  def expected_business
    { "status" => "open", "page" => "2", "note" => "urgent" }
  end

  # --- legal carriers -------------------------------------------------------

  def test_legacy_query_string_mode_authenticates
    request = build_signed_request(:query_string)

    assert_match(/oauth_signature=/, request.path)
    assert_nil request["Authorization"]

    proxy = proxy_for(rack_env_for(request))
    assert OAuth::Signature.verify(proxy, consumer: @consumer, token: @token)
    assert_equal expected_business, proxy.non_oauth_parameters
    assert_equal %i[query], proxy.oauth_parameters_by_location.reject { |_k, v| v.empty? }.keys
  end

  def test_header_mode_authenticates_and_keeps_credentials_out_of_the_url
    request = build_signed_request(:header)

    refute_match(/oauth_/, request.path)
    refute_nil request["Authorization"]
    # No residual protocol parameters may survive on the URL.
    %w[oauth_token oauth_signature oauth_nonce].each do |name|
      refute_match(/#{name}/, request.path)
    end

    proxy = proxy_for(rack_env_for(request))
    assert OAuth::Signature.verify(proxy, consumer: @consumer, token: @token)
    assert_equal expected_business, proxy.non_oauth_parameters
    assert_equal %i[header], proxy.oauth_parameters_by_location.reject { |_k, v| v.empty? }.keys
  end

  def test_business_parameters_are_identical_across_modes
    legacy = proxy_for(rack_env_for(build_signed_request(:query_string)))
    modern = proxy_for(rack_env_for(build_signed_request(:header)))

    assert_equal expected_business, legacy.non_oauth_parameters
    assert_equal expected_business, modern.non_oauth_parameters
    # The normalized parameter set feeding the signature is also identical.
    assert_equal legacy.normalized_parameters, modern.normalized_parameters
  end

  # A business field named like an OAuth value is NOT a protocol parameter and
  # must never be stripped or treated as a duplicate. (Here: ordinary data.)
  def test_business_field_sharing_protocol_naming_space_is_preserved
    request = Net::HTTP::Get.new("/v1/orders?oauth_nonce_hint=from-client")
    request.oauth!(@consumer.http, @consumer, @token, SIGN_OPTIONS.merge(scheme: :header))

    proxy = proxy_for(rack_env_for(request))
    assert OAuth::Signature.verify(proxy, consumer: @consumer, token: @token)
    assert_equal "from-client", proxy.non_oauth_parameters["oauth_nonce_hint"]
  end

  # --- ambiguity rejection --------------------------------------------------

  def test_header_plus_query_protocol_params_is_rejected
    request = build_signed_request(:header)
    mixed_path = "#{request.path}&oauth_token=stale&oauth_signature=stale"

    error = assert_raises(OAuth::AmbiguousCredentials) do
      proxy_for(rack_env_for(request, path_override: mixed_path)).parameters
    end

    assert_equal %i[header query], error.locations
    assert_includes error.parameter_names, "oauth_token"
    # Error data carries names/locations only, never secret values.
    refute_match(/stale/, error.message)
    assert_equal "oauth.ambiguous_credentials", error.to_h[:error]
  end

  def test_header_plus_form_protocol_params_is_rejected
    request = build_signed_request(:header)
    env = rack_env_for(request)
    env["rack.input"] = StringIO.new("note=urgent&oauth_nonce=leaked")
    env["CONTENT_TYPE"] = "application/x-www-form-urlencoded"

    error = assert_raises(OAuth::AmbiguousCredentials) do
      proxy_for(env).parameters
    end

    assert_equal %i[body header], error.locations
    assert_includes error.parameter_names, "oauth_nonce"
  end

  def test_query_plus_form_protocol_params_is_rejected_without_header
    env = Rack::MockRequest.env_for(
      "#{ENDPOINT}?oauth_consumer_key=ck&oauth_signature=qs",
      method: "POST",
      "CONTENT_TYPE" => "application/x-www-form-urlencoded",
      input: "oauth_token=body-token"
    )

    error = assert_raises(OAuth::AmbiguousCredentials) { proxy_for(env).parameters }
    assert_equal %i[body query], error.locations
  end

  def test_different_protocol_names_split_across_locations_are_still_ambiguous
    request = build_signed_request(:header)
    # Only one extra, *different* oauth name on the URL: still ambiguous.
    mixed_path = "#{request.path}&oauth_verifier=leftover"

    error = assert_raises(OAuth::AmbiguousCredentials) do
      proxy_for(rack_env_for(request, path_override: mixed_path)).parameters
    end
    assert_equal %i[header query], error.locations
    assert_includes error.parameter_names, "oauth_verifier"
  end

  def test_ambiguity_check_can_be_explicitly_opted_out
    request = build_signed_request(:header)
    mixed_path = "#{request.path}&oauth_token=stale"
    rack_request = Rack::Request.new(rack_env_for(request, path_override: mixed_path))
    proxy = OAuth::RequestProxy.proxy(rack_request,
                                      consumer: @consumer, token: @token,
                                      allow_duplicate_oauth_locations: true)

    # Legacy merge behavior restored for controlled rollback scenarios.
    assert proxy.parameters.key?("oauth_token")
  end
end
