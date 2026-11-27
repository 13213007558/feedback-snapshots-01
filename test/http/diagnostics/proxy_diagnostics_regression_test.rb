# frozen_string_literal: true

require "test_helper"
require "support/proxy_diagnostics"

# A preset regression: a policy that projects events onto the shareable
# allowlist but never constrains the proxy stage. The event channel looks
# clean while proxy-only fields keep reaching the CONNECT request.
class ProxyDiagnosticsRegressionTest < Minitest::Test
  def result
    @result ||= begin
      policy = ProxyDiagnostics::Fixture.event_only_policy
      capture = ProxyDiagnostics::Fixture.capture(policy: policy, proxy: ProxyDiagnostics::Fixture.leaky_proxy)
      acceptance = ProxyDiagnostics::Acceptance.new(
        capture:  capture,
        policy:   policy,
        expected: ProxyDiagnostics::Fixture.expectations
      )
      [capture, acceptance]
    end
  end

  def capture
    result.first
  end

  def acceptance
    result.last
  end

  def test_regression_event_channel_passes_its_own_projection
    headers = capture.finished_request_event.headers

    assert_equal({ "Accept" => "application/json", "x-request-id" => "app-request-id" }, headers)
    assert_equal "https://origin.internal.test/v1/orders", capture.finished_request_event.payload[:uri]
  end

  def test_regression_still_leaks_application_credentials_to_the_proxy
    assert_equal "Bearer app-origin-token", capture.proxy_request.header("Authorization")
    assert_equal "session=app-cookie", capture.proxy_request.header("Cookie")
  end

  def test_regression_still_leaks_unlisted_proxy_metadata_to_the_proxy
    assert_equal "tenant-proxy", capture.proxy_request.header("X-Tenant")
    assert_includes capture.proxy_request.names, "Authorization"
  end

  def test_regression_fails_acceptance_at_the_proxy_channel
    assert_includes acceptance.codes, :proxy_received_origin_only_field
    assert_includes acceptance.codes, :proxy_field_not_allowed
  end

  def test_regression_does_not_fail_at_the_event_channel
    channels = acceptance.violations.map(&:channel)

    refute_includes channels, :event
  end

  def test_regression_verify_raises_with_proxy_details
    error = assert_raises(Minitest::Assertion) { acceptance.verify! }

    assert_includes error.message, "proxy/proxy_received_origin_only_field"
    assert_includes error.message, "proxy/proxy_field_not_allowed"
    refute_includes error.message, "event/"
  end
end
