# frozen_string_literal: true

require_relative "../test_helper"

require "oauth/request_proxy/rack_request"
require "rack/method_override"

# These tests exercise a real Rack stack. They assert on the signature base
# string, the verification result, and which method the business endpoint
# actually ran -- not merely on Rack::Request#request_method.
class RackRequestProxyMethodOverrideTest < Minitest::Test
  CONSUMER_SECRET = "consumer-secret"
  TOKEN_SECRET = "token-secret"
  URI = "https://example.com/resource"
  BOUNDARY = "AaB03x"

  # Business endpoint with a per-method side-effect counter.
  class BusinessEndpoint
    attr_reader :hits

    def initialize
      @hits = Hash.new(0)
    end

    def call(env)
      method = env["REQUEST_METHOD"]
      @hits[method] += 1
      [200, { "content-type" => "text/plain" }, ["executed:#{method}"]]
    end

    def executed?
      hits.values.sum.positive?
    end
  end

  # Verifies the OAuth signature, then delegates to the business endpoint.
  class OAuthEndpoint
    attr_reader :signature_base_string, :verified, :proxy_method

    def initialize(app, options = {})
      @app = app
      @options = options
    end

    def call(env)
      proxy = OAuth::RequestProxy.proxy(Rack::Request.new(env), signature_options)
      @signature_base_string = proxy.signature_base_string
      @proxy_method = proxy.method
      @verified = OAuth::Signature.verify(proxy, signature_options)
      return [401, { "content-type" => "text/plain" }, ["denied"]] unless @verified

      @app.call(env)
    end

    private

    def signature_options
      { consumer_secret: CONSUMER_SECRET, token_secret: TOKEN_SECRET }.merge(@options)
    end
  end

  # Build the request as the client sends it. `wire_method` and `body` are
  # exactly what goes over the network.
  def rack_env(wire_method:, body: "", header_override: nil, content_type: "application/x-www-form-urlencoded")
    env = Rack::MockRequest.env_for(URI, method: wire_method, input: body)
    env["CONTENT_TYPE"] = content_type if content_type
    env["CONTENT_LENGTH"] = body.bytesize.to_s
    env["HTTP_X_HTTP_METHOD_OVERRIDE"] = header_override if header_override
    env
  end

  def oauth_parameters
    {
      "oauth_consumer_key" => "consumer-key",
      "oauth_signature_method" => "HMAC-SHA1",
      "oauth_timestamp" => "137131200",
      "oauth_nonce" => "fixed-nonce",
      "oauth_version" => "1.0",
    }
  end

  def oauth_header(parameters)
    "OAuth " + parameters.map { |k, v| "#{k}=\"#{OAuth::Helper.escape(v)}\"" }.join(", ")
  end

  # Sign the request the way a client would: over `signed_method` and
  # `signed_parameters` only. Extra parameters present in the actual body are
  # therefore NOT covered by the signature. Returns the signed parameter hash,
  # including `oauth_signature`, so tests can hand it to a clobbering verifier.
  def sign_as_client(env, signed_method:, signed_parameters: {})
    parameters = oauth_parameters.merge(signed_parameters)
    env["HTTP_AUTHORIZATION"] = oauth_header(parameters)

    proxy = OAuth::RequestProxy::MockRequest.new(
      "method" => signed_method,
      "uri" => URI,
      "parameters" => parameters
    )
    signature = OAuth::Signature.sign(proxy, consumer_secret: CONSUMER_SECRET, token_secret: TOKEN_SECRET)
    signed = parameters.merge("oauth_signature" => signature)
    env["HTTP_AUTHORIZATION"] = oauth_header(signed)
    signed
  end

  # Build the middleware stack under test. `order` is one of:
  #   :override_outer - Rack::MethodOverride runs before signature verification
  #   :verifier_outer - signature verification runs before Rack::MethodOverride
  def stack_for(order, options = {})
    business = BusinessEndpoint.new

    if order == :override_outer
      verifier = OAuthEndpoint.new(business, options)
      [Rack::MethodOverride.new(verifier), business, verifier]
    else
      verifier = OAuthEndpoint.new(Rack::MethodOverride.new(business), options)
      [verifier, business, verifier]
    end
  end

  def call_stack(order, env, options = {})
    stack, business, verifier = stack_for(order, options)
    status, _headers, _body = stack.call(env)
    {
      status: status,
      base_method: verifier.signature_base_string.split("&").first,
      base_string: verifier.signature_base_string,
      verified: verifier.verified,
      proxy_method: verifier.proxy_method,
      hits: business.hits.dup,
      executed: business.executed?,
    }
  end

  ORDERS = %i[override_outer verifier_outer].freeze

  # --- Header-triggered override -------------------------------------------

  def test_header_override_added_by_attacker_is_rejected
    ORDERS.each do |order|
      env = rack_env(wire_method: "POST", body: "foo=bar", header_override: "DELETE")
      sign_as_client(env, signed_method: "POST", signed_parameters: { "foo" => "bar" })

      result = call_stack(order, env)

      assert_equal 401, result[:status], "order=#{order}"
      refute result[:verified], "order=#{order}"
      assert_equal "DELETE", result[:base_method], "order=#{order}: signature must bind the dispatched method"
      refute result[:executed], "order=#{order}: business endpoint must not run"
      assert_empty result[:hits], "order=#{order}"
    end
  end

  def test_header_override_signed_as_effective_method_is_accepted
    ORDERS.each do |order|
      env = rack_env(wire_method: "POST", body: "foo=bar", header_override: "DELETE")
      sign_as_client(env, signed_method: "DELETE", signed_parameters: { "foo" => "bar" })

      result = call_stack(order, env)

      assert_equal 200, result[:status], "order=#{order}"
      assert result[:verified], "order=#{order}"
      assert_equal "DELETE", result[:base_method], "order=#{order}"
      assert_equal 1, result[:hits]["DELETE"], "order=#{order}"
    end
  end

  # --- Form-triggered override ---------------------------------------------

  def test_form_override_appended_by_attacker_is_rejected
    ORDERS.each do |order|
      env = rack_env(wire_method: "POST", body: "foo=bar&_method=DELETE")
      # Client signed the body *without* _method.
      sign_as_client(env, signed_method: "POST", signed_parameters: { "foo" => "bar" })

      result = call_stack(order, env)

      assert_equal 401, result[:status], "order=#{order}"
      refute result[:verified], "order=#{order}"
      assert_equal "POST", result[:base_method], "order=#{order}"
      refute result[:executed], "order=#{order}: business endpoint must not run"
      assert_empty result[:hits], "order=#{order}"
    end
  end

  def test_form_override_changed_from_signed_value_is_rejected
    ORDERS.each do |order|
      env = rack_env(wire_method: "POST", body: "foo=bar&_method=PATCH")
      sign_as_client(env, signed_method: "POST", signed_parameters: { "foo" => "bar", "_method" => "DELETE" })

      result = call_stack(order, env)

      assert_equal 401, result[:status], "order=#{order}"
      refute result[:verified], "order=#{order}"
      refute result[:executed], "order=#{order}: business endpoint must not run"
    end
  end

  def test_form_override_signed_by_client_is_accepted
    ORDERS.each do |order|
      env = rack_env(wire_method: "POST", body: "foo=bar&_method=DELETE")
      sign_as_client(env, signed_method: "POST", signed_parameters: { "foo" => "bar", "_method" => "DELETE" })

      result = call_stack(order, env)

      assert_equal 200, result[:status], "order=#{order}"
      assert result[:verified], "order=#{order}"
      assert_equal "POST", result[:base_method], "order=#{order}: original method is signed"
      assert_equal 1, result[:hits]["DELETE"], "order=#{order}: business runs the signed override"
    end
  end

  # --- clobber_request: body is not part of the signature -------------------

  def test_form_override_is_rejected_when_body_is_not_signed
    ORDERS.each do |order|
      env = rack_env(wire_method: "POST", body: "foo=bar&_method=DELETE")
      # Only OAuth parameters are signed; the body is deliberately excluded.
      signed = sign_as_client(env, signed_method: "POST")

      # clobber_request requires the verifier to supply the signed parameter set.
      result = call_stack(order, env, clobber_request: true, parameters: signed)

      assert_equal 401, result[:status], "order=#{order}"
      refute result[:verified], "order=#{order}"
      refute result[:executed], "order=#{order}: business endpoint must not run"
    end
  end

  # --- multipart bodies ----------------------------------------------------

  def test_multipart_override_appended_by_attacker_is_rejected
    body = "--#{BOUNDARY}\r\n" \
           "Content-Disposition: form-data; name=\"_method\"\r\n\r\n" \
           "DELETE\r\n" \
           "--#{BOUNDARY}--\r\n"
    content_type = "multipart/form-data; boundary=#{BOUNDARY}"

    ORDERS.each do |order|
      env = rack_env(wire_method: "POST", body: body, content_type: content_type)
      sign_as_client(env, signed_method: "POST")

      result = call_stack(order, env)

      assert_equal 401, result[:status], "order=#{order}"
      refute result[:verified], "order=#{order}"
      refute result[:executed], "order=#{order}: business endpoint must not run"
    end
  end

  # --- Opt-out policies ----------------------------------------------------

  def test_original_policy_reproduces_legacy_behavior
    env = rack_env(wire_method: "POST", body: "foo=bar", header_override: "DELETE")
    sign_as_client(env, signed_method: "POST", signed_parameters: { "foo" => "bar" })

    result = call_stack(:override_outer, env, method_override: :original)

    assert_equal 200, result[:status]
    assert result[:verified]
    assert_equal "POST", result[:base_method]
    assert_equal 1, result[:hits]["DELETE"], "legacy policy still dispatches DELETE"
  end

  def test_effective_policy_signs_the_dispatched_method
    env = rack_env(wire_method: "POST", body: "foo=bar", header_override: "DELETE")
    sign_as_client(env, signed_method: "DELETE", signed_parameters: { "foo" => "bar" })

    result = call_stack(:override_outer, env, method_override: :effective)

    assert_equal 200, result[:status]
    assert_equal "DELETE", result[:base_method]
    assert_equal 1, result[:hits]["DELETE"]
  end

  def test_unknown_policy_raises
    env = rack_env(wire_method: "POST", body: "foo=bar")
    sign_as_client(env, signed_method: "POST", signed_parameters: { "foo" => "bar" })

    assert_raises(ArgumentError) do
      call_stack(:override_outer, env, method_override: :bogus)
    end
  end

  # --- Override is only recognized where Rack would apply one --------------

  def test_form_parameter_does_not_override_non_post_wire_method
    %w[PUT PATCH DELETE].each do |wire|
      env = rack_env(wire_method: wire, body: "_method=DELETE")
      sign_as_client(env, signed_method: wire, signed_parameters: { "_method" => "DELETE" })

      result = call_stack(:override_outer, env)

      assert_equal 200, result[:status], "wire=#{wire}"
      assert_equal wire, result[:base_method], "wire=#{wire}: Rack does not override non-POST"
      assert_equal 1, result[:hits][wire], "wire=#{wire}"
    end
  end

  def test_header_override_does_not_apply_to_non_post_wire_method
    env = rack_env(wire_method: "PUT", body: "foo=bar", header_override: "DELETE")
    sign_as_client(env, signed_method: "PUT", signed_parameters: { "foo" => "bar" })

    result = call_stack(:override_outer, env)

    assert_equal 200, result[:status]
    assert result[:verified]
    assert_equal "PUT", result[:base_method], "Rack ignores the header for non-POST"
    assert_equal 1, result[:hits]["PUT"]
  end

  # ActionDispatch::Request#request_method reports the wire method; derive the
  # effective method from the env so the proxy behaves the same for both.
  def test_request_object_whose_request_method_ignores_override
    env = rack_env(wire_method: "POST", body: "foo=bar&_method=DELETE")
    sign_as_client(env, signed_method: "POST", signed_parameters: { "foo" => "bar", "_method" => "DELETE" })
    Rack::MethodOverride.new(->(inner) { [200, {}, inner["REQUEST_METHOD"]] }).call(env)

    wire_request_class = Class.new(Rack::Request) do
      def request_method
        env["rack.methodoverride.original_method"] || env["REQUEST_METHOD"]
      end
    end

    proxy = OAuth::RequestProxy.proxy(wire_request_class.new(env))
    assert_equal "POST", proxy.method
  end

  def test_invalid_form_method_value_is_not_treated_as_override
    env = rack_env(wire_method: "POST", body: "foo=bar&_method=BOGUS")
    sign_as_client(env, signed_method: "POST", signed_parameters: { "foo" => "bar", "_method" => "BOGUS" })

    result = call_stack(:override_outer, env)

    assert_equal 200, result[:status]
    assert_equal "POST", result[:base_method]
    assert_equal 1, result[:hits]["POST"], "invalid override is not applied by Rack"
  end

  # Rack ignores the header whenever a _method form key is present, even if the
  # form value is invalid. The proxy must follow the same precedence so that a
  # valid signature can never be checked against a method that will not run.
  def test_invalid_form_method_shadows_valid_header
    env = rack_env(wire_method: "POST", body: "_method=BOGUS", header_override: "DELETE")
    sign_as_client(env, signed_method: "POST", signed_parameters: { "_method" => "BOGUS" })

    result = call_stack(:override_outer, env)

    assert_equal 200, result[:status]
    assert result[:verified]
    assert_equal "POST", result[:base_method], "form key shadows the header; Rack applies neither"
    assert_equal 1, result[:hits]["POST"]
  end

  def test_valid_form_method_shadows_conflicting_header
    env = rack_env(wire_method: "POST", body: "_method=DELETE", header_override: "PATCH")
    sign_as_client(env, signed_method: "POST", signed_parameters: { "_method" => "DELETE" })

    result = call_stack(:override_outer, env)

    assert_equal 200, result[:status]
    assert result[:verified]
    assert_equal "POST", result[:base_method], "signed form override is honored over the header"
    assert_equal 1, result[:hits]["DELETE"]
  end

  # Rack also treats a POST with no content type as form data.
  def test_override_without_content_type_is_bound
    ORDERS.each do |order|
      env = rack_env(wire_method: "POST", body: "foo=bar&_method=DELETE", content_type: nil)
      sign_as_client(env, signed_method: "POST", signed_parameters: { "foo" => "bar" })

      result = call_stack(order, env)

      assert_equal 401, result[:status], "order=#{order}"
      refute result[:executed], "order=#{order}"
    end
  end

  def test_multipart_override_signed_as_effective_method_is_accepted
    body = "--#{BOUNDARY}\r\n" \
           "Content-Disposition: form-data; name=\"_method\"\r\n\r\n" \
           "DELETE\r\n" \
           "--#{BOUNDARY}--\r\n"
    content_type = "multipart/form-data; boundary=#{BOUNDARY}"

    ORDERS.each do |order|
      env = rack_env(wire_method: "POST", body: body, content_type: content_type)
      sign_as_client(env, signed_method: "DELETE")

      result = call_stack(order, env)

      assert_equal 200, result[:status], "order=#{order}"
      assert_equal "DELETE", result[:base_method], "order=#{order}"
      assert_equal 1, result[:hits]["DELETE"], "order=#{order}"
    end
  end

  def test_array_valued_method_parameter_is_not_an_override
    env = rack_env(wire_method: "POST", body: "_method[]=DELETE")
    sign_as_client(env, signed_method: "POST", signed_parameters: { "_method" => ["DELETE"] })

    result = call_stack(:override_outer, env)

    assert_equal 200, result[:status]
    assert_equal "POST", result[:base_method]
    assert_equal 1, result[:hits]["POST"]
  end

  # Rack::MethodOverride only reads _method from the POST body, never from the
  # query string. A signed query-string _method must not legitimize a
  # header-driven override.
  def test_query_string_method_does_not_legitimize_header_override
    env = rack_env(wire_method: "POST", body: "foo=bar", header_override: "DELETE")
    env["QUERY_STRING"] = "_method=DELETE"
    env["REQUEST_URI"] = "/resource?_method=DELETE"
    sign_as_client(env, signed_method: "POST", signed_parameters: { "foo" => "bar", "_method" => "DELETE" })

    result = call_stack(:override_outer, env)

    assert_equal 401, result[:status]
    assert_equal "DELETE", result[:base_method]
    refute result[:executed], "business endpoint must not run"
  end

  # --- Unrelated behavior --------------------------------------------------

  def test_plain_post_without_override_still_verifies
    ORDERS.each do |order|
      env = rack_env(wire_method: "POST", body: "foo=bar")
      sign_as_client(env, signed_method: "POST", signed_parameters: { "foo" => "bar" })

      result = call_stack(order, env)

      assert_equal 200, result[:status], "order=#{order}"
      assert result[:verified], "order=#{order}"
      assert_equal "POST", result[:base_method], "order=#{order}"
      assert_equal 1, result[:hits]["POST"], "order=#{order}"
    end
  end
end
