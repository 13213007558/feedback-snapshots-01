# frozen_string_literal: true

require "test_helper"

class HTTPClientTLSAllowedOriginsTest < Minitest::Test
  cover "HTTP::Client*"

  APPROVED_ORIGIN = "https://billing.internal"
  OTHER_APPROVED_ORIGIN = "https://vault.internal:8443"
  REJECTED_ORIGIN = "https://evil.example.com"

  def ssl_params
    @ssl_params ||= {
      cert: OpenSSL::X509::Certificate.new,
      key:  OpenSSL::PKey::RSA.new(2048),
      ca_file: "/etc/internal/ca.pem"
    }
  end

  # A stand-in for HTTP::Connection that records the trust material the
  # client hands to the connection layer, without touching a real socket.
  def build_recording_connection(records)
    Class.new do
      define_method(:initialize) do |_req, options|
        @options = options
        records << self
      end

      define_method(:options) { @options }
      define_method(:send_request) { |_req| nil }
      define_method(:read_headers!) { nil }
      define_method(:status_code) { 200 }
      define_method(:http_version) { "1.1" }
      define_method(:headers) { HTTP::Headers.new }
      define_method(:proxy_response_headers) { nil }
      define_method(:pending_response=) { |_res| nil }
      define_method(:keep_alive?) { true }
      define_method(:expired?) { false }
      define_method(:close) { nil }
      define_method(:failed_proxy_connect?) { false }
      define_method(:finish_response) { nil }
    end
  end

  def build_client(records)
    HTTP::Client.new(
      ssl: ssl_params,
      ssl_allowed_origins: [APPROVED_ORIGIN, OTHER_APPROVED_ORIGIN]
    )
  end

  def run_with_stubbed_connection(client, records)
    connection_class = build_recording_connection(records)
    HTTP::Connection.stub(:new, ->(req, options) { connection_class.new(req, options) }) do
      yield
    end
  end

  def test_approved_addresses_pass_handshake_material_and_reconnect_reuses_it
    records = []
    client = build_client(records)

    run_with_stubbed_connection(client, records) do
      client.get("#{APPROVED_ORIGIN}/v1/charges")
      client.get("#{APPROVED_ORIGIN}/v1/refunds")

      # Force a reconnect while staying inside the same approved configuration.
      client.close
      client.get("#{OTHER_APPROVED_ORIGIN}/secrets")
    end

    assert_equal 2, records.size, "expected one reused connection plus one reconnect"

    records.each do |connection|
      assert_equal ssl_params, connection.options.ssl,
                   "trust material must reach the connection layer unchanged"
      assert_includes connection.options.ssl_allowed_origins, APPROVED_ORIGIN
    end
  end

  def test_rejected_address_fails_before_the_connection_layer_is_reached
    records = []
    client = build_client(records)

    error = nil
    run_with_stubbed_connection(client, records) do
      error = assert_raises(HTTP::ClientCertificateError) do
        client.get("#{REJECTED_ORIGIN}/collect")
      end
    end

    assert_empty records, "no connection must be opened for a rejected address"
    assert_includes error.message, REJECTED_ORIGIN
    assert_includes error.message, APPROVED_ORIGIN
    assert_includes error.message, OTHER_APPROVED_ORIGIN
  end

  def test_same_configuration_keeps_working_after_a_rejected_request
    records = []
    client = build_client(records)

    run_with_stubbed_connection(client, records) do
      assert_raises(HTTP::ClientCertificateError) do
        client.get("#{REJECTED_ORIGIN}/collect")
      end

      client.get("#{APPROVED_ORIGIN}/v1/charges")
    end

    assert_equal 1, records.size
    assert_equal ssl_params, records.first.options.ssl
  end

  def test_requests_are_unrestricted_when_no_allowlist_is_configured
    records = []
    client = HTTP::Client.new(ssl: ssl_params)

    run_with_stubbed_connection(client, records) do
      client.get("#{REJECTED_ORIGIN}/anything")
    end

    assert_equal 1, records.size
  end

  def test_plain_http_requests_are_not_governed_by_the_allowlist
    records = []
    client = build_client(records)

    run_with_stubbed_connection(client, records) do
      client.get("http://billing.internal/plain")
    end

    assert_equal 1, records.size
  end

  def test_chainable_dsl_sets_normalized_allowed_origins
    session = HTTP.ssl_allowed_origins(
      "#{APPROVED_ORIGIN}/v1", OTHER_APPROVED_ORIGIN
    )

    assert_equal [APPROVED_ORIGIN, OTHER_APPROVED_ORIGIN],
                 session.default_options.ssl_allowed_origins
  end
end
