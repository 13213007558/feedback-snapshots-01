# frozen_string_literal: true

require "test_helper"

class HTTPClientTLSPermissionTest < Minitest::Test
  cover "HTTP::ClientTLS::Permission*"

  def allowed_origins
    ["https://billing.internal", "https://vault.internal:8443"]
  end

  def permission
    @permission ||= HTTP::ClientTLS::Permission.new(allowed_origins)
  end

  def test_normalizes_origins_to_scheme_host_and_port
    origins = HTTP::ClientTLS::Permission.new(
      ["https://billing.internal/v1/charges", HTTP::URI.parse("https://vault.internal:8443/root?x=1")]
    ).allowed_origins

    assert_equal ["https://billing.internal", "https://vault.internal:8443"], origins
  end

  def test_accepts_a_single_origin_without_wrapping
    single = HTTP::ClientTLS::Permission.new("https://billing.internal")

    assert_equal ["https://billing.internal"], single.allowed_origins
  end

  def test_allowed_returns_true_for_matching_origin_regardless_of_path
    assert permission.allowed?(HTTP::URI.parse("https://billing.internal/v1/charges"))
  end

  def test_allowed_treats_port_as_part_of_the_address
    refute permission.allowed?(HTTP::URI.parse("https://billing.internal:8443/v1"))
    assert permission.allowed?(HTTP::URI.parse("https://vault.internal:8443/secrets"))
  end

  def test_allowed_treats_scheme_as_part_of_the_address
    refute permission.allowed?(HTTP::URI.parse("http://billing.internal/v1"))
  end

  def test_allowed_returns_false_for_unknown_origin
    refute permission.allowed?(HTTP::URI.parse("https://evil.example.com/"))
  end

  def test_verify_passes_for_an_allowed_origin
    assert_nil permission.verify!(HTTP::URI.parse("https://billing.internal/"))
  end

  def test_verify_raises_explainable_error_for_a_rejected_origin
    error = assert_raises(HTTP::ClientCertificateError) do
      permission.verify!(HTTP::URI.parse("https://evil.example.com:9000/steal"))
    end

    assert_includes error.message, "https://evil.example.com:9000"
    allowed_origins.each { |origin| assert_includes error.message, origin }
  end
end
