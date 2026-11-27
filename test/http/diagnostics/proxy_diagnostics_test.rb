# frozen_string_literal: true

require "test_helper"
require "support/proxy_diagnostics"

class ProxyDiagnosticsTest < Minitest::Test
  def setup
    super
    @policy = ProxyDiagnostics::Fixture.policy
    @capture = ProxyDiagnostics::Fixture.capture(policy: @policy)
    @expected = ProxyDiagnostics::Fixture.expectations
  end

  def acceptance(capture: @capture, policy: @policy, expected: @expected)
    ProxyDiagnostics::Acceptance.new(capture: capture, policy: policy, expected: expected)
  end

  # -- proxy channel --

  def test_proxy_channel_connects_to_the_proxy_endpoint
    assert_equal ProxyDiagnostics::Fixture::PROXY_ADDRESS, @capture.transport.connected_host
    assert_equal ProxyDiagnostics::Fixture::PROXY_PORT, @capture.transport.connected_port
  end

  def test_proxy_channel_sends_a_connect_request_for_the_origin
    assert_equal "CONNECT origin.internal.test:443 HTTP/1.1", @capture.proxy_request.headline
  end

  def test_proxy_channel_carries_the_metadata_the_client_derives
    assert_equal "origin.internal.test", @capture.proxy_request.header("Host")
    assert_equal HTTP::Request::USER_AGENT, @capture.proxy_request.header("User-Agent")
    assert_match(/\ABasic /, @capture.proxy_request.header("Proxy-Authorization"))
  end

  def test_proxy_channel_carries_only_allowlisted_extra_fields
    assert_equal %w[X-Proxy-Route X-Request-Id X-Tenant],
                 @capture.proxy_request.headers.map(&:name) - %w[Host User-Agent Proxy-Authorization]
  end

  def test_proxy_channel_keeps_proxy_values_distinct_from_same_named_app_fields
    request = @capture.proxy_request

    assert_equal "proxy-request-id", request.header("X-Request-Id")
    assert_equal "tenant-proxy", request.header("X-Tenant")
  end

  def test_proxy_channel_never_receives_origin_only_credentials
    assert_nil @capture.proxy_request.header("Authorization")
    assert_nil @capture.proxy_request.header("Cookie")
  end

  def test_proxy_channel_preserves_wire_spelling
    assert_includes @capture.proxy_request.names, "X-Request-Id"
    refute_includes @capture.proxy_request.names, "x-request-id"
  end

  # -- origin channel --

  def test_origin_channel_request_line_targets_the_application_resource
    assert_equal "GET /v1/orders?access_token=origin-secret HTTP/1.1", @capture.origin_request.headline
  end

  def test_origin_channel_receives_application_fields
    request = @capture.origin_request

    assert_equal "application/json", request.header("Accept")
    assert_equal "app-request-id", request.header("x-request-id")
    assert_equal "tenant-app", request.header("X-Tenant")
  end

  def test_origin_channel_receives_origin_only_credentials
    assert_equal "Bearer app-origin-token", @capture.origin_request.header("Authorization")
    assert_equal "session=app-cookie", @capture.origin_request.header("Cookie")
  end

  def test_origin_channel_never_receives_proxy_only_fields
    assert_nil @capture.origin_request.header("X-Proxy-Route")
    assert_nil @capture.origin_request.header("Proxy-Authorization")
  end

  def test_origin_channel_keeps_the_app_spelling_of_a_shared_field
    assert_includes @capture.origin_request.names, "x-request-id"
  end

  # -- event channel --

  def test_event_channel_finishes_the_main_span
    event = @capture.finished_request_event

    assert_equal "request.http", event.name
    assert_equal :finish, event.phase
    assert_equal 200, event.payload.dig(:response, :status)
  end

  def test_event_channel_projects_only_allowlisted_request_fields
    assert_equal({ "Accept" => "application/json", "x-request-id" => "app-request-id" },
                 @capture.finished_request_event.headers)
  end

  def test_event_channel_projects_response_fields_without_the_exchange_only_ones
    headers = @capture.finished_request_event.response_headers

    assert_equal "application/json", headers["Content-Type"]
    assert_equal "origin-request-id", headers["X-Request-Id"]
    refute headers.key?("Set-Cookie")
    refute headers.key?("Proxy-Authenticate")
  end

  def test_event_channel_drops_the_query_and_userinfo
    assert_equal "https://origin.internal.test/v1/orders", @capture.finished_request_event.payload[:uri]
  end

  def test_event_channel_does_not_carry_origin_only_credentials
    headers = @capture.finished_request_event.headers

    refute headers.key?("Authorization")
    refute headers.key?("Cookie")
  end

  def test_raw_payload_still_holds_credentials_that_the_projection_removes
    raw = @capture.raw_finished_payload[:request]

    assert_equal "Bearer app-origin-token", raw.headers["Authorization"]

    leaked = @capture.shareable_events.select { |event| event.headers.key?("Authorization") }
    assert_empty leaked
  end

  # -- same name, different case --

  def test_reconciler_groups_the_same_field_across_all_three_channels
    assert_equal %i[proxy origin event], @capture.reconciler.channels("X-Request-Id")
  end

  def test_reconciler_reports_each_channel_spelling_without_collapsing_them
    spellings = @capture.reconciler.spellings("X-Request-Id")

    assert_equal ["X-Request-Id"], spellings[:proxy]
    assert_equal ["x-request-id"], spellings[:origin]
    assert_equal ["x-request-id"], spellings[:event]
  end

  def test_reconciler_keeps_proxy_and_application_values_separate
    values = @capture.reconciler.values("X-Request-Id")

    assert_equal ["proxy-request-id"], values[:proxy]
    assert_equal ["app-request-id"], values[:origin]
  end

  def test_shareable_event_lookup_is_case_insensitive
    values = @capture.finished_request_event.values("X-Request-Id")

    assert_equal ["app-request-id"], values
  end

  def test_reconciler_finds_no_duplicate_spellings_within_a_channel
    assert_empty @capture.reconciler.case_variant_duplicates
  end

  def test_reconciler_detects_a_field_that_repeats_under_two_spellings
    capture = ProxyDiagnostics.capture(
      policy:  @policy,
      headers: { "X-Request-Id" => "one", "x-request-id" => "two" },
      proxy:   { proxy_address: "proxy.test", proxy_port: 8080 },
      uri:     "https://origin.test/"
    )
    duplicate = capture.reconciler.case_variant_duplicates.find { |item| item.channel == :origin }

    assert_equal "X-Request-Id", duplicate.key
    assert_equal ["X-Request-Id", "x-request-id"], duplicate.spellings
  end

  # -- acceptance --

  def test_acceptance_passes_for_a_channel_scoped_policy
    assert_empty acceptance.violations
    acceptance.verify!
  end

  def test_acceptance_fails_when_a_proxy_field_is_not_allowlisted
    capture = ProxyDiagnostics::Fixture.capture(policy: ProxyDiagnostics::Fixture.event_only_policy)
    strict = ProxyDiagnostics::Policy.new(
      proxy_headers: ["X-Proxy-Route"],
      shareable_headers: ProxyDiagnostics::Fixture::SHAREABLE_ALLOWLIST
    )

    assert_includes acceptance(capture: capture, policy: strict).codes, :proxy_field_not_allowed
  end

  def test_acceptance_fails_when_the_request_line_target_is_wrong
    expected = @expected.merge(target: "/wrong")
    codes = acceptance(expected: expected).codes

    assert_includes codes, :origin_request_line
  end

  def test_acceptance_fails_when_an_event_keeps_the_query
    capture = ProxyDiagnostics::Fixture.capture(policy: @policy)
    event = capture.finished_request_event
    event.payload[:uri] = "https://origin.test/?token=secret"

    assert_includes acceptance(capture: capture).codes, :event_kept_query
  end

  def test_acceptance_fails_when_an_event_field_is_not_shareable
    narrow = ProxyDiagnostics::Policy.new(
      proxy_headers: ProxyDiagnostics::Fixture::PROXY_ALLOWLIST,
      shareable_headers: ["Accept"]
    )

    assert_includes acceptance(policy: narrow).codes, :event_field_not_allowed
  end
end
