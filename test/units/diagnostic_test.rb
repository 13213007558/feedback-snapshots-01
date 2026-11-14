# frozen_string_literal: true

require_relative "../test_helper"

require "oauth"
require "json"
require "net/http"

class DiagnosticTest < Minitest::Test
  DIAGNOSTIC_KEY = "ephemeral-diagnostic-key-0123456789abcdef"
  OTHER_KEY = "ephemeral-diagnostic-key-abcdef0123456789"

  CONSUMER_SECRET = "consumer-secret-shhh"
  TOKEN_SECRET = "token-secret-shhh"
  AUTH_CODE = "authz-code-shhh"
  SECRET_BUSINESS_VALUE = "super-secret-account-ref"

  # Two requests that differ ONLY in percent-encoding of the query string:
  # "~" is left unreserved by one party and encoded as %7E by the other.
  def encoding_request_a
    net_http_get("http://example.com/resource?data=%7Euser&oauth_consumer_key=ck")
  end

  def encoding_request_b
    net_http_get("http://example.com/resource?data=~user&oauth_consumer_key=ck")
  end

  # Two requests that differ ONLY in duplicate parameter handling:
  # one party sends "tag" twice, the other collapses it to a single value.
  def duplicate_request_a
    net_http_get("http://example.com/resource?tag=red&tag=blue&oauth_consumer_key=ck")
  end

  def duplicate_request_b
    net_http_get("http://example.com/resource?tag=red&oauth_consumer_key=ck")
  end

  def test_requires_a_diagnostic_key
    assert_raises(ArgumentError) { OAuth::Diagnostic.explain(encoding_request_a) }
    assert_raises(ArgumentError) { OAuth::Diagnostic.explain(encoding_request_a, diagnostic_key: "short") }
  end

  def test_report_is_clearly_marked_as_diagnostic_and_unverified
    report = explain(encoding_request_a)

    assert_equal OAuth::Diagnostic::REPORT_VERSION, report["diagnostic"]
    assert_includes report["notice"], "DIAGNOSTIC USE ONLY"
    assert_includes report["trust"], "UNVERIFIED"
  end

  def test_report_breaks_down_method_uri_sources_and_encoding_steps
    report = explain(encoding_request_a)

    assert_equal "GET", report["method"]
    assert_equal "http://example.com/resource", report["normalized_uri"]

    data_entry = report["parameters"].find { |p| p["name"] == "data" }
    assert_equal "query", data_entry["source"]
    assert_equal "~user", data_entry["value"]
    assert_equal "~user", data_entry["value_escaped"]

    raw_pair = report["query_string_pairs"].find { |p| p["name"] == "data" }
    assert_equal "%7Euser", raw_pair["raw_value"]
  end

  def test_identical_requests_have_no_divergence
    assert_nil OAuth::Diagnostic.first_divergence(
      explain(encoding_request_a),
      explain(encoding_request_a)
    )
  end

  def test_first_divergence_locates_percent_encoding_difference
    divergence = OAuth::Diagnostic.first_divergence(
      explain(encoding_request_a),
      explain(encoding_request_b)
    )

    refute_nil divergence
    # The parsed values are identical; the raw percent-encoding is the first
    # point where the two parties disagree.
    assert_equal "$.query_string_pairs[0].raw_value", divergence["path"]
    assert_equal "%7Euser", divergence["a"]
    assert_equal "~user", divergence["b"]
  end

  def test_first_divergence_locates_duplicate_parameter_difference
    divergence = OAuth::Diagnostic.first_divergence(
      explain(duplicate_request_a),
      explain(duplicate_request_b)
    )

    refute_nil divergence
    assert_match(/\A\$\.parameters\[\d+\]/, divergence["path"])
  end

  def test_signature_base_string_tag_detects_duplicate_parameter_difference
    report_a = explain(duplicate_request_a)
    report_b = explain(duplicate_request_b)

    refute_equal report_a["signature_base_string_tag"], report_b["signature_base_string_tag"]
  end

  def test_tags_are_keyed_so_low_entropy_values_are_not_guessable
    low_entropy_request = net_http_get("http://example.com/resource?flag=1")

    tag_a = OAuth::Diagnostic.explain(low_entropy_request, diagnostic_key: DIAGNOSTIC_KEY)
    tag_b = OAuth::Diagnostic.explain(low_entropy_request, diagnostic_key: OTHER_KEY)

    refute_equal tag_a["signature_base_string_tag"], tag_b["signature_base_string_tag"]
    # A plain (unkeyed) digest of the low-entropy value must not appear.
    require "digest"
    refute_includes tag_a.to_json, Digest::SHA256.hexdigest("flag=1")
  end

  def test_report_and_logs_contain_no_secrets_or_sensitive_fields
    request = {
      "method" => "GET",
      "uri" => "http://example.com/resource",
      "parameters" => {
        "oauth_consumer_key" => "ck",
        "oauth_signature" => "provided-signature-value",
        "oauth_verifier" => AUTH_CODE,
        "account_ref" => SECRET_BUSINESS_VALUE,
        "note" => "public-note"
      }
    }

    report = OAuth::Diagnostic.explain(
      request,
      diagnostic_key: DIAGNOSTIC_KEY,
      sensitive_parameters: %w[account_ref],
      consumer_secret: CONSUMER_SECRET,
      token_secret: TOKEN_SECRET
    )

    log_line = JSON.generate(report)

    [CONSUMER_SECRET, TOKEN_SECRET, AUTH_CODE, SECRET_BUSINESS_VALUE, "provided-signature-value"].each do |secret|
      refute_includes log_line, secret
    end

    # Non-sensitive values remain visible for comparison.
    assert_includes log_line, "public-note"

    # Secrets are comparable via tags only.
    assert_equal report["secrets"]["consumer_secret_tag"],
                 OAuth::Diagnostic.explain(request, diagnostic_key: DIAGNOSTIC_KEY,
                                                    consumer_secret: CONSUMER_SECRET)["secrets"]["consumer_secret_tag"]
  end

  def test_diagnostic_does_not_mutate_request_or_generate_nonce
    parameters = {"oauth_consumer_key" => "ck", "note" => "hi"}
    request = {"method" => "GET", "uri" => "http://example.com/resource", "parameters" => parameters}
    before = Marshal.load(Marshal.dump(request))

    OAuth::Diagnostic.explain(request, diagnostic_key: DIAGNOSTIC_KEY)

    assert_equal before, request
    refute parameters.key?("oauth_nonce")
    refute parameters.key?("oauth_signature")
  end

  def test_diagnostic_does_not_sign_the_proxy
    proxy = OAuth::RequestProxy.proxy(
      {"method" => "GET", "uri" => "http://example.com/resource", "parameters" => {"a" => "b"}}
    )

    OAuth::Diagnostic.explain(proxy, diagnostic_key: DIAGNOSTIC_KEY)

    refute proxy.signed?
  end

  private

  def explain(request, options = {})
    OAuth::Diagnostic.explain(request, {diagnostic_key: DIAGNOSTIC_KEY}.merge(options))
  end

  def net_http_get(path)
    uri = URI.parse(path)
    req = Net::HTTP::Get.new("#{uri.path}?#{uri.query}")
    OAuth::RequestProxy.proxy(req, uri: path)
  end
end
