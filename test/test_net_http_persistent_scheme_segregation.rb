require 'minitest/autorun'
require 'net/http/persistent'

##
# Security regression tests for sharing one host:port (and proxy settings)
# between plaintext HTTP and HTTPS requests.
#
# The pool must key connections by the transport security context, otherwise
# an HTTPS request can silently borrow a plaintext socket and send
# credentials before any TLS handshake ever happens.
#
# A record-typed stand-in for Net::HTTP records every protocol transition
# (configure TLS, start, send a request) so each connection's scheme, target
# and ordering can be asserted without touching real sockets.

class TestNetHttpPersistentSchemeSegregation < Minitest::Test

  # Immutable record of one thing that happened to a connection.
  Event = Data.define(:kind, :detail) do
    def to_s
      "#{kind}(#{detail})"
    end
  end

  # Identity of a connection, independent of which request currently holds it.
  Identity = Data.define(:address, :port, :proxy_address, :proxy_port,
                         :proxy_user, :proxy_pass)

  # Record-typed stand-in that quacks like the subset of Net::HTTP used by
  # Net::HTTP::Persistent.  Every state change is appended to .events.
  class RecordingHTTP
    attr_accessor :open_timeout, :read_timeout, :write_timeout,
                  :keep_alive_timeout, :ignore_eof, :max_retries,
                  :ciphers, :ssl_timeout, :ssl_version, :min_version,
                  :max_version, :verify_depth, :verify_mode,
                  :verify_hostname, :cert_store, :ca_file, :ca_path,
                  :cert, :key, :extra_chain_cert, :debug_output
    attr_reader :events, :address, :port,
                :proxy_address, :proxy_port, :proxy_user, :proxy_pass

    def initialize(address, port,
                   proxy_address = nil, proxy_port = nil,
                   proxy_user = nil, proxy_pass = nil)
      @address       = address
      @port          = port
      @proxy_address = proxy_address
      @proxy_port    = proxy_port
      @proxy_user    = proxy_user
      @proxy_pass    = proxy_pass

      @use_ssl = false
      @started = false
      @events  = []
    end

    def identity
      Identity.new(address, port, proxy_address, proxy_port,
                   proxy_user, proxy_pass)
    end

    def use_ssl?
      @use_ssl
    end

    def started?
      @started
    end

    def proxy?
      !@proxy_address.nil?
    end

    def proxy_from_env?
      false
    end

    # Net::HTTP::Persistent#ssl flips this on before #start, so the recorded
    # order proves TLS is configured before the socket is opened.
    def use_ssl=(value)
      @use_ssl = value
      @events << Event.new(:tls, value ? 'on' : 'off')
    end

    def set_debug_output(io)
      @debug_output = io
    end

    def start
      @events << Event.new(:start, "#{use_ssl? ? 'https' : 'http'}://" \
                                   "#{target}")
      @started = true
      self
    end

    def finish
      @events << Event.new(:finish, target)
      @started = false
    end

    def request(req, &block)
      raise "request sent on a stopped connection" unless started?

      detail = "#{use_ssl? ? 'https' : 'http'}://#{target}#{req.path}"
      @events << Event.new(:request, detail)

      # Mirror Net::HTTP: proxy credentials ride the CONNECT tunnel, which is
      # only valid once TLS has been established for the target.
      if proxy? && use_ssl?
        req['proxy-authorization'] =
          'Basic ' + ["#{proxy_user}:#{proxy_pass}"].pack('m0')
      end

      response = Net::HTTPResponse.allocate
      response.instance_variable_set :@header, {}
      def response.http_version; '1.1' end
      def response.read_body; :read_body end
      yield response if block_given?
      response
    end

    def target
      proxy? ? "#{proxy_address}:#{proxy_port}->#{address}:#{port}"
             : "#{address}:#{port}"
    end
  end

  HOST = 'example.com'
  PORT = 8080

  def setup
    @persistent = Net::HTTP::Persistent.new name: 'scheme-test'
    @persistent.idle_timeout = nil

    @persistent.pool.available
      .instance_variable_set(:@create_block, method(:create_connection))
  end

  def create_connection(http_args)
    use_ssl = http_args.last
    Net::HTTP::Persistent::Connection.new(
      RecordingHTTP, http_args[0...-1],
      @persistent.ssl_generation, use_ssl
    )
  end

  def http_uri(path = '/plain')
    URI "http://#{HOST}:#{PORT}#{path}"
  end

  def https_uri(path = '/secure')
    URI "https://#{HOST}:#{PORT}#{path}"
  end

  def checkout(uri)
    @persistent.connection_for(uri) { |connection| connection }
  end

  def request(uri)
    @persistent.request uri
  end

  def test_pool_key_separates_http_and_https_for_the_same_host_and_port
    http_conn  = checkout http_uri
    https_conn = checkout https_uri

    refute_same http_conn, https_conn

    refute http_conn.http.use_ssl?,  'HTTP connection must stay plaintext'
    assert https_conn.http.use_ssl?, 'HTTPS connection must use TLS'

    assert_equal [HOST, PORT], [http_conn.http.address, http_conn.http.port]
    assert_equal [HOST, PORT], [https_conn.http.address, https_conn.http.port]
  end

  def test_switching_scheme_twice_never_crosses_security_contexts
    first_http   = checkout http_uri('/1')
    first_https  = checkout https_uri('/1')
    second_http  = checkout http_uri('/2')
    second_https = checkout https_uri('/2')

    assert_same first_http, second_http,
                'same-scheme HTTP connections must be reused'
    assert_same first_https, second_https,
                'same-scheme HTTPS connections must be reused'

    refute_same first_http, first_https
    refute first_http.http.use_ssl?
    assert first_https.http.use_ssl?
  end

  def test_legitimate_same_scheme_requests_still_reuse_one_connection
    first  = checkout http_uri('/a')
    second = checkout http_uri('/b')
    third  = checkout http_uri('/c')

    assert_same first, second
    assert_same second, third
    assert_equal 1, count_connections
  end

  def test_tls_is_configured_and_started_before_any_request_is_sent
    connection = checkout https_uri

    kinds = connection.http.events.map(&:kind)

    assert_equal [:tls, :start], kinds.first(2),
                 'TLS must be configured and the socket started before use'

    request https_uri('/secret')

    request_event = connection.http.events.find { |e| e.kind == :request }
    tls_index     = connection.http.events.index { |e| e.kind == :tls }
    start_index   = connection.http.events.index { |e| e.kind == :start }
    request_index = connection.http.events.index(request_event)

    assert tls_index < start_index
    assert start_index < request_index
    assert_match %r{\Ahttps://}, request_event.detail
  end

  def test_authentication_header_is_only_sent_after_tls_establishment
    proxy = URI 'http://proxy.example:3128'
    proxy.user = 'johndoe'
    proxy.password = 'hunter2'
    @persistent.proxy = proxy

    uri = https_uri '/private'

    connection = nil
    @persistent.connection_for(uri) { |c| connection = c }

    get = Net::HTTP::Get.new uri.request_uri
    @persistent.request uri, get

    assert connection.http.use_ssl?,
           'proxied HTTPS request must still establish TLS to the target'
    assert connection.http.proxy?

    ordered = connection.http.events.map(&:kind)
    assert_equal [:tls, :start, :request], ordered

    request_index = ordered.index(:request)
    assert_equal 2, request_index
    assert get['proxy-authorization'],
           'proxy CONNECT credentials must be attached on the TLS tunnel'
  end

  def test_direct_and_proxied_connections_are_pooled_separately
    proxy = URI 'http://proxy.example:3128'
    @persistent.proxy = proxy

    proxied = checkout https_uri

    @persistent.proxy = nil
    direct  = checkout https_uri

    refute_same proxied, direct

    assert proxied.http.proxy?
    refute direct.http.proxy?

    assert_equal 'proxy.example', proxied.http.proxy_address
    assert_equal 3128, proxied.http.proxy_port
    assert_nil direct.http.proxy_address

    assert proxied.http.use_ssl?
    assert direct.http.use_ssl?
  end

  def test_direct_http_after_proxied_https_does_not_borrow_that_socket
    proxy = URI 'http://proxy.example:3128'
    @persistent.proxy = proxy

    proxied_https = checkout https_uri

    @persistent.proxy = nil
    direct_http = checkout http_uri

    refute_same proxied_https, direct_http
    refute direct_http.http.use_ssl?
    refute direct_http.http.proxy?
    assert proxied_https.http.use_ssl?
  end

  def test_idle_reset_reopens_with_the_same_security_context
    connection = checkout https_uri
    http = connection.http

    connection.last_use = Time.now - 3600
    @persistent.idle_timeout = 5

    reset_connection = checkout https_uri

    assert_same connection, reset_connection
    assert http.use_ssl?, 'reset connection must keep using TLS'

    kinds = http.events.map(&:kind)
    assert_equal [:tls, :start, :finish, :start], kinds
    refute_includes kinds, :request
  end

  def test_recheckout_after_finish_rebuilds_tls_before_request
    connection = checkout https_uri
    @persistent.finish connection

    refute connection.http.started?

    reopened = checkout https_uri
    request https_uri('/again')

    assert_same connection, reopened
    assert connection.http.started?
    assert connection.http.use_ssl?

    kinds = connection.http.events.map(&:kind)
    assert_equal [:tls, :start, :finish, :tls, :start, :request], kinds
  end

  def test_http_request_never_checks_out_an_https_connection
    https_conn = checkout https_uri
    http_conn  = checkout http_uri

    refute_same https_conn, http_conn
    refute http_conn.http.use_ssl?

    request http_uri('/insecure')

    http_events = http_conn.http.events
    assert http_events.all? { |e| e.detail.nil? || !e.detail.start_with?('https') }
    assert_equal :start, http_events.first.kind
    refute_includes http_events.map(&:kind), :tls
  end

  def test_connection_record_targets_match_the_requested_uri
    http_conn  = checkout http_uri
    https_conn = checkout https_uri

    assert_equal "#{HOST}:#{PORT}", http_conn.http.target
    assert_equal "#{HOST}:#{PORT}", https_conn.http.target

    http_start  = http_conn.http.events.find { |e| e.kind == :start }
    https_start = https_conn.http.events.find { |e| e.kind == :start }

    assert_equal "http://#{HOST}:#{PORT}", http_start.detail
    assert_equal "https://#{HOST}:#{PORT}", https_start.detail
  end

  private

  def count_connections
    ques = @persistent.pool.available.instance_variable_get(:@ques)
    ques.sum { |_key, stack| stack.size } + checked_out_count
  end

  def checked_out_count
    thread_key = @persistent.pool.key
    stacks = Thread.current[thread_key]
    return 0 unless stacks

    stacks.sum { |_args, stack| stack.size }
  end
end
