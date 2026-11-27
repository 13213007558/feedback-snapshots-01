# frozen_string_literal: true

require "test_helper"

class HTTPFeaturesBoundAuthTest < Minitest::Test
  cover "HTTP::Features::BoundAuth*"

  RESOURCE = "https://api.example.com/v1/orders/42"
  ALIAS    = "https://api.example.com/v2/orders/42"
  FOREIGN  = "https://api.example.com/v1/orders/99"
  OTHER_ORIGIN = "https://evil.example.com/v1/orders/42"

  # A transport double that only records the requests actually sent.
  class RecordingTransport < HTTP::Client
    attr_reader :sent

    def initialize(**options)
      super(HTTP::Options.new(**options))
      @sent = []
    end

    def perform(request, _options)
      @sent << request
      HTTP::Response.new(version: "1.1", status: 200, body: "ok", request: request)
    end
  end

  def header_feature(**overrides)
    options = {
      material:  "tok_123",
      resources: [RESOURCE],
      aliases:   { ALIAS => RESOURCE },
      attach:    { in: :header, name: "Authorization", scheme: "Bearer" }
    }.merge(overrides)

    HTTP::Features::BoundAuth.new(**options)
  end

  def query_feature(**overrides)
    header_feature(attach: { in: :query, name: "access_token" }, **overrides)
  end

  def make_request(uri = RESOURCE, verb: :get, **options)
    HTTP::Request.new(verb: verb, uri: uri, **options)
  end

  def client(feature, **options)
    RecordingTransport.new(**options, features: { bound_auth: feature })
  end

  # -- feature registration --

  def test_is_registered_as_bound_auth
    assert_equal HTTP::Features::BoundAuth, HTTP::Options.available_features[:bound_auth]
  end

  def test_is_a_feature
    assert_kind_of HTTP::Feature, header_feature
  end

  def test_is_opt_in_and_absent_from_default_options
    refute HTTP::Options.new.features.key?(:bound_auth)
  end

  def test_chainable_dsl_enables_the_feature
    session = HTTP.bound_auth(
      material: "tok", resources: [RESOURCE],
      attach: { name: "Authorization", scheme: "Bearer" }
    )

    assert_kind_of HTTP::Features::BoundAuth, session.default_options.feature(:bound_auth)
  end

  # -- configuration --

  def test_exposes_the_material_resources_aliases_and_attach_rule
    feature = header_feature

    assert_equal "tok_123", feature.material
    assert_equal [HTTP::URI.parse(RESOURCE).normalize], feature.resources
    assert_equal "Bearer", feature.attach[:scheme]
    assert feature.aliases.key?(HTTP::URI.parse(ALIAS).normalize)
  end

  def test_default_attach_location_is_the_authorization_header
    feature = HTTP::Features::BoundAuth.new(material: "tok", resources: [RESOURCE], attach: {})

    assert_equal :header, feature.attach[:in]
    assert_equal "Authorization", feature.attach[:name]
    assert_nil feature.attach[:scheme]
  end

  def test_rejects_an_unknown_attach_location
    error = assert_raises(HTTP::Features::BoundAuth::BindingError) do
      header_feature(attach: { in: :cookie, name: "Cookie" })
    end

    assert_match(/unsupported attach location/, error.message)
  end

  def test_rejects_a_missing_or_empty_attach_name
    assert_raises(HTTP::Features::BoundAuth::BindingError) do
      header_feature(attach: { name: nil })
    end
    assert_raises(HTTP::Features::BoundAuth::BindingError) do
      header_feature(attach: { name: "" })
    end
  end

  def test_rejects_an_empty_material
    assert_raises(HTTP::Features::BoundAuth::BindingError) do
      header_feature(material: "")
    end
  end

  def test_rejects_a_feature_without_resources
    assert_raises(HTTP::Features::BoundAuth::BindingError) do
      header_feature(resources: [])
    end
  end

  def test_rejects_an_alias_pointing_at_an_unapproved_resource
    assert_raises(HTTP::Features::BoundAuth::BindingError) do
      header_feature(aliases: { "https://api.example.com/v2/x" => FOREIGN })
    end
  end

  def test_binding_error_is_a_request_error
    assert_operator HTTP::Features::BoundAuth::BindingError, :<, HTTP::RequestError
  end

  # -- header attachment on the approved resource --

  def test_attaches_the_material_to_an_approved_resource_request
    feature = header_feature
    authorized = feature.wrap_request(make_request)

    assert_equal "Bearer tok_123", authorized.headers["Authorization"]
  end

  def test_keeps_default_query_parameters_when_attaching_to_a_header
    feature = header_feature
    uri = HTTP::URI.parse("#{RESOURCE}?tenant=acme")
    authorized = feature.wrap_request(make_request(uri: uri))

    assert_equal "tenant=acme", authorized.uri.query
    assert_equal "Bearer tok_123", authorized.headers["Authorization"]
  end

  def test_keeps_a_head_request_read_only_and_drops_its_body
    feature = header_feature
    authorized = feature.wrap_request(make_request(verb: :head, body: "payload"))

    assert_equal :head, authorized.verb
    assert_nil authorized.body.source
  end

  def test_keeps_a_get_request_read_only_and_drops_any_body
    feature = header_feature
    authorized = feature.wrap_request(make_request(verb: :get, body: "payload"))

    assert_equal :get, authorized.verb
    assert_nil authorized.body.source
  end

  def test_preserves_origin_headers_proxy_version_and_normalizer
    normalizer = ->(uri) { HTTP::URI::NORMALIZER.call(uri) }
    original = make_request(headers: { "Accept" => "application/json" },
                       proxy: { proxy_address: "proxy.example.com", proxy_port: 8080 },
                       version: "1.0", uri_normalizer: normalizer)
    authorized = header_feature.wrap_request(original)

    assert_equal "application/json", authorized.headers["Accept"]
    assert_equal original.proxy, authorized.proxy
    assert_equal "1.0", authorized.version
    assert_same normalizer, authorized.uri_normalizer
  end

  def test_header_without_scheme_uses_the_raw_material
    feature = header_feature(attach: { name: "X-Api-Key" })
    authorized = feature.wrap_request(make_request)

    assert_equal "tok_123", authorized.headers["X-Api-Key"]
  end

  # -- query attachment --

  def test_attaches_the_material_as_a_query_parameter
    feature = query_feature
    authorized = feature.wrap_request(make_request)

    params = ::URI.decode_www_form(authorized.uri.query).to_h
    assert_equal "tok_123", params["access_token"]
    assert_nil authorized.headers["Authorization"]
  end

  def test_query_attachment_keeps_existing_and_default_parameters
    feature = query_feature
    authorized = feature.wrap_request(make_request(uri: "#{RESOURCE}?tenant=acme"))

    params = ::URI.decode_www_form(authorized.uri.query).to_h
    assert_equal "acme", params["tenant"]
    assert_equal "tok_123", params["access_token"]
  end

  # -- resource binding and path aliases --

  def test_approves_a_request_whose_path_matches_a_resource_ignoring_query
    feature = header_feature
    authorized = feature.wrap_request(make_request(uri: "#{RESOURCE}?tenant=acme"))

    assert_equal HTTP::URI.parse(RESOURCE).path, authorized.uri.path
  end

  def test_allows_an_approved_path_alias_and_keeps_using_the_material
    feature = header_feature
    authorized = feature.wrap_request(make_request(uri: ALIAS))

    assert_equal "/v2/orders/42", authorized.uri.path
    assert_equal "Bearer tok_123", authorized.headers["Authorization"]
  end

  def test_alias_keeps_working_with_default_query_parameters
    feature = header_feature
    authorized = feature.wrap_request(make_request(uri: "#{ALIAS}?tenant=acme"))

    assert_equal "Bearer tok_123", authorized.headers["Authorization"]
    assert_equal "tenant=acme", authorized.uri.query
  end

  def test_blocks_a_known_location_that_was_not_approved
    feature = header_feature

    assert_raises(HTTP::Features::BoundAuth::BindingError) do
      feature.wrap_request(make_request(uri: FOREIGN))
    end
  end

  def test_blocks_a_same_path_on_a_different_origin
    feature = header_feature

    assert_raises(HTTP::Features::BoundAuth::BindingError) do
      feature.wrap_request(make_request(uri: OTHER_ORIGIN))
    end
  end

  def test_blocks_a_non_read_only_verb
    feature = header_feature

    assert_raises(HTTP::Features::BoundAuth::BindingError) do
      feature.wrap_request(make_request(verb: :post, body: "data"))
    end
  end

  def test_blocked_requests_are_not_returned_for_sending
    feature = header_feature

    assert_raises(HTTP::Features::BoundAuth::BindingError) do
      feature.wrap_request(make_request(verb: :delete))
    end

    assert_empty feature.hops
  end

  # -- hop trail: material category per hop --

  def test_records_each_sent_hop_with_its_material_category
    feature = header_feature
    feature.wrap_request(make_request)
    feature.wrap_request(make_request(uri: ALIAS))

    assert_equal 2, feature.hops.length

    first, second = feature.hops
    assert_equal "bearer", first[:material_category]
    assert_equal :header, first[:attached_in]
    assert_equal "Authorization", first[:attached_name]
    assert_equal RESOURCE, String(first[:resource].to_s)
    assert_equal RESOURCE, String(second[:resource].to_s)
    assert_equal ALIAS, second[:uri].to_s
  end

  def test_material_category_defaults_to_token_without_a_scheme
    feature = header_feature(attach: { name: "X-Api-Key" })
    feature.wrap_request(make_request)

    assert_equal "token", feature.hops.first[:material_category]
  end

  def test_records_the_query_category_for_query_attachment
    feature = query_feature
    feature.wrap_request(make_request)

    hop = feature.hops.first
    assert_equal :query, hop[:attached_in]
    assert_equal "access_token", hop[:attached_name]
    assert_equal "token", hop[:material_category]
  end

  def test_each_hop_holds_the_request_that_will_actually_be_sent
    feature = header_feature
    authorized = feature.wrap_request(make_request)

    assert_same authorized, feature.hops.first[:request]
  end

  # -- blocked trail: why steps stopped --

  def test_records_why_an_unapproved_location_was_stopped
    feature = header_feature
    suppress_binding_error { feature.wrap_request(make_request(uri: FOREIGN)) }

    assert_equal 1, feature.blocked.length
    entry = feature.blocked.first
    assert_equal FOREIGN, entry[:uri].to_s
    assert_nil entry[:request]
    assert_match(/no approved resource or alias/, entry[:reason])
  end

  def test_records_why_a_non_read_only_request_was_stopped
    feature = header_feature
    suppress_binding_error { feature.wrap_request(make_request(verb: :put, body: "x")) }

    entry = feature.blocked.first
    assert_equal :put, entry[:request].verb
    assert_match(/non read-only verb/, entry[:reason])
  end

  def test_trails_are_defensive_copies
    feature = header_feature
    feature.wrap_request(make_request)

    feature.hops.clear
    feature.blocked.clear

    assert_equal 1, feature.hops.length
    assert_empty feature.blocked
  end

  # -- end to end through the client with a recording transport --

  def test_client_sends_only_authorized_requests_and_records_them
    feature = header_feature
    http = client(feature, params: { tenant: "acme" })

    http.get(RESOURCE)
    http.get(ALIAS)

    assert_equal 2, http.sent.length
    http.sent.each do |sent|
      assert_equal :get, sent.verb
      assert_equal "Bearer tok_123", sent.headers["Authorization"]
      assert_equal "tenant=acme", sent.uri.query
    end
  end

  def test_client_never_sends_a_request_for_an_unapproved_location
    feature = header_feature
    http = client(feature)

    assert_raises(HTTP::Features::BoundAuth::BindingError) { http.get(FOREIGN) }
    assert_raises(HTTP::Features::BoundAuth::BindingError) { http.post(RESOURCE, body: "x") }

    assert_empty http.sent
    assert_equal 2, feature.blocked.length
    assert_empty feature.hops
  end

  def test_client_approves_the_alias_but_requires_re_approval_for_a_new_location
    feature = header_feature
    http = client(feature, params: { tenant: "acme" })

    http.get(ALIAS)
    assert_equal 1, http.sent.length

    assert_raises(HTTP::Features::BoundAuth::BindingError) do
      http.get("https://api.example.com/v3/orders/42")
    end

    assert_equal 1, http.sent.length, "the unapproved migration must not be sent"
    assert_equal HTTP::URI.parse(ALIAS).path, feature.hops.first[:uri].path
    assert_equal "tenant=acme", feature.hops.first[:uri].query
    assert_match(/no approved resource or alias/, feature.blocked.first[:reason])
  end

  def test_query_attachment_flows_through_the_client
    feature = query_feature
    http = client(feature, params: { tenant: "acme" })

    http.get(RESOURCE)

    params = ::URI.decode_www_form(http.sent.first.uri.query).to_h
    assert_equal "acme", params["tenant"]
    assert_equal "tok_123", params["access_token"]
  end

  private

  def suppress_binding_error
    yield
  rescue HTTP::Features::BoundAuth::BindingError
    nil
  end
end
