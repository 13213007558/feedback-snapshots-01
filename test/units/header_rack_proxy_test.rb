# frozen_string_literal: true

require_relative "../test_helper"

require "oauth/request_proxy/rack_request"

# Exercises the shared parsing boundary through the Rack request proxy: the
# header must reach signature verification exactly as sent, realm must stay
# out of the signed parameters, and malformed or ambiguous headers must be
# rejected rather than silently changing the verified credential.
class HeaderRackProxyTest < Minitest::Test
  def proxy_for(header, url = "http://example.com/test")
    env = Rack::MockRequest.env_for(url, "HTTP_AUTHORIZATION" => header)
    request = Rack::Request.new(env)
    OAuth::RequestProxy.proxy(request, uri: url)
  end

  def test_header_params_feed_into_parameters
    proxy = proxy_for('OAuth oauth_consumer_key="key", oauth_nonce="nonce"')

    assert_equal "key", proxy.parameters["oauth_consumer_key"]
    assert_equal "nonce", proxy.parameters["oauth_nonce"]
  end

  def test_realm_is_parsed_but_excluded_from_signed_parameters
    header = 'OAuth realm="http://example.com", oauth_consumer_key="key", oauth_nonce="nonce"'
    proxy = proxy_for(header)

    # The base class keeps only oauth_* fields for verification; realm is a
    # display parameter and must never participate in the signature.
    refute proxy.parameters.key?("realm")
    assert proxy.oauth_parameters.keys.all? { |k| k.start_with?("oauth_") }
    assert_equal "key", proxy.oauth_consumer_key
  end

  def test_encoded_separators_round_trip_into_signature_base_string
    # A value containing the structural characters comma, equals and
    # ampersand is percent-encoded on the wire (RFC 5849 3.6) and decoded back
    # to the exact original for signature computation.
    original_token = "a,b=c&d"
    wire_value = OAuth::Helper.escape(original_token)
    header = "OAuth oauth_token=\"#{wire_value}\", " \
             'oauth_consumer_key="key", oauth_nonce="nonce", ' \
             'oauth_signature_method="HMAC-SHA1", oauth_timestamp="1240004133"'
    proxy = proxy_for(header)

    assert_equal original_token, proxy.oauth_token

    # The header entry point must normalize the token identically to delivering
    # the same value through the query string, so the verified credential
    # cannot differ by entry point.
    query_env = Rack::MockRequest.env_for(
      "http://example.com/test?oauth_consumer_key=key&oauth_nonce=nonce" \
      "&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1240004133&oauth_token=#{wire_value}"
    )
    query_proxy = OAuth::RequestProxy.proxy(Rack::Request.new(query_env), uri: "http://example.com/test")

    assert_equal query_proxy.signature_base_string, proxy.signature_base_string
    refute_includes proxy.signature_base_string, "realm"
  end

  def test_quoted_raw_separators_are_decoded_but_still_distinct
    # Punctuation literally inside quotes is data, not header structure.
    proxy = proxy_for('OAuth oauth_token="one,two=three&four", oauth_nonce="n"')

    assert_equal "one,two=three&four", proxy.oauth_token
  end

  def test_malformed_header_raises_problem_through_proxy
    malformed_headers = [
      'OAuth oauth_nonce="unterminated',
      'OAuth oauth_nonce="a", oauth_nonce="b"',
      'OAuth oauth_token="100%done"',
      'OAuth garbage'
    ]

    malformed_headers.each do |header|
      assert_raises(OAuth::Problem, "expected rejection of #{header.inspect}") do
        proxy_for(header).parameters
      end
    end
  end

  def test_header_values_match_verification_entry_point
    # Build a request with a known signature, then verify it through the Rack
    # proxy. Parsing must not alter any field the signature was computed over.
    consumer_secret = "consumer_secret"
    token_secret = "token_secret"

    signed_header = signed_authorization_header(consumer_secret, token_secret)
    proxy = proxy_for(signed_header, "http://example.com/resource")

    assert OAuth::Signature.verify(proxy,
                                  consumer_secret: consumer_secret,
                                  token_secret: token_secret)
  end

  def test_tampered_signature_field_fails_verification
    consumer_secret = "consumer_secret"
    token_secret = "token_secret"

    signed_header = signed_authorization_header(consumer_secret, token_secret)
    tampered = signed_header.sub(/oauth_nonce="[^"]+"/, 'oauth_nonce="attacker-nonce"')

    refute_equal signed_header, tampered
    proxy = proxy_for(tampered, "http://example.com/resource")

    refute OAuth::Signature.verify(proxy,
                                   consumer_secret: consumer_secret,
                                   token_secret: token_secret)
  end

  def test_duplicate_field_is_rejected_instead_of_first_or_last_wins
    # Demonstrates the security fix: neither the first nor the last repeated
    # value is selected, the whole request is refused deterministically.
    header = 'OAuth oauth_nonce="first", oauth_nonce="last", oauth_consumer_key="key"'

    assert_raises(OAuth::Problem) { proxy_for(header).parameters }
  end

  private

  def signed_authorization_header(consumer_secret, token_secret)
    header_params = {
      "oauth_consumer_key" => "key",
      "oauth_token" => "token",
      "oauth_signature_method" => "HMAC-SHA1",
      "oauth_timestamp" => "1240004133",
      "oauth_nonce" => "nonce",
      "oauth_version" => "1.0"
    }

    signing_env = Rack::MockRequest.env_for("http://example.com/resource",
                                            "HTTP_AUTHORIZATION" => "OAuth " + header_params.map { |k, v|
                                              "#{k}=\"#{OAuth::Helper.escape(v)}\""
                                            }.join(", "))
    signing_proxy = OAuth::RequestProxy.proxy(Rack::Request.new(signing_env),
                                              uri: "http://example.com/resource")
    signature = OAuth::Signature.sign(signing_proxy,
                                      consumer_secret: consumer_secret,
                                      token_secret: token_secret)
    header_params["oauth_signature"] = signature

    "OAuth " + header_params.map { |k, v| "#{k}=\"#{OAuth::Helper.escape(v)}\"" }.join(", ")
  end
end
