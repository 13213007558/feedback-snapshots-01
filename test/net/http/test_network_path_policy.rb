# frozen_string_literal: true

require 'test/unit'
require 'net/http'

class TestNetHTTPNetworkPathPolicy < Test::Unit::TestCase
  class ScriptedSocket
    attr_reader :writes, :close_count

    def initialize(failure: false, succeed: true, on_first_close: nil)
      @failure = failure
      @succeed = succeed
      @on_first_close = on_first_close
      @closed = false
      @close_count = 0
      @status_reads = 0
      @writes = []
    end

    def write(data)
      @writes << data
      data.bytesize
    end

    def flush
      self
    end

    def close
      return if @closed

      @closed = true
      @close_count += 1
      @on_first_close&.call(self)
    end

    def closed?
      @closed
    end

    def io
      self
    end

    def to_io
      self
    end

    def wait_readable(_timeout = nil)
      false
    end

    def eof?
      false
    end

    def readuntil(terminator, ignore_eof = false, limit: nil)
      raise "unexpected terminator #{terminator.inspect}" unless terminator == "\n"
      return '' if ignore_eof

      @status_reads += 1
      raise Errno::ECONNRESET if @failure && @status_reads == 1
      raise EOFError unless @succeed

      "HTTP/1.1 200 OK\n"
    end

    def read_all(_dest)
      ''
    end
  end

  class PathRecordingHTTP < Net::HTTP
    attr_reader :connect_paths, :sockets
    attr_accessor :scripts

    def initialize(address, port = 80)
      super
      @connect_paths = []
      @sockets = []
      @scripts = []
    end

    private

    def connect
      network_path = @connect_network_path || resolve_network_path
      authorize_network_path!(network_path)
      @connect_paths << network_path
      script = @scripts.shift || {}
      socket = ScriptedSocket.new(**script)
      @sockets << socket
      @socket = socket
      @connected_network_path = network_path
      @last_communicated = nil
    end
  end

  class SeparateApproval
    attr_reader :checks

    def initialize(direct: false, proxy: true)
      @direct = direct
      @proxy = proxy
      @checks = []
    end

    def direct_allowed?(path)
      @checks << [:direct, path.key]
      @direct
    end

    def proxy_allowed?(path)
      @checks << [:proxy, path.key]
      @proxy
    end
  end

  class RawSocketDouble
    attr_reader :closed

    def setsockopt(*_args)
    end

    def close
      @closed = true
    end

    def closed?
      @closed
    end
  end

  def new_http(*scripts)
    http = PathRecordingHTTP.new('service.internal', 80)
    http.proxy_from_env = false
    http.scripts = scripts
    http.max_retries = 1
    http
  end

  def test_interleaved_started_request_and_new_request_bind_separate_paths
    approval = SeparateApproval.new(direct: false, proxy: true)
    a = new_http(
      { failure: true },
      { failure: false, succeed: true }
    )
    a.proxy_address = 'proxy-a.internal'
    a.proxy_port = 1000
    a.network_path_approval = approval

    b = nil
    a.scripts[0][:on_first_close] = lambda do |_closed_socket|
      # Operations changes the shared mutable proxy configuration while A's
      # first attempt has already been written and is waiting to retry.
      a.proxy_address = 'proxy-b.internal'
      a.proxy_port = 2000

      b = new_http({ failure: false, succeed: true })
      b.proxy_address = 'proxy-b.internal'
      b.proxy_port = 2000
      b.network_path_approval = approval
      b.start
      response = b.get('/new')
      assert_equal '200', response.code
    end

    a.start
    response = a.get('/started')

    assert_equal '200', response.code

    # A's start and its one retry remain bound to A's resolved route.
    assert_equal 2, a.connect_paths.size
    assert_equal %w[proxy-a.internal proxy-a.internal],
                 a.connect_paths.map(&:proxy_address)
    assert_equal [1000, 1000], a.connect_paths.map(&:proxy_port)

    # The interleaved new request uses the current changed route.
    assert_equal 1, b.connect_paths.size
    assert_equal 'proxy-b.internal', b.connect_paths.first.proxy_address
    assert_equal 2000, b.connect_paths.first.proxy_port

    # A's first connection is closed before retry; successful retry and B's
    # keep-alive connection are not closed.
    assert_predicate a.sockets[0], :closed?
    assert_equal 1, a.sockets[0].close_count
    refute_predicate a.sockets[1], :closed?
    refute_predicate b.sockets[0], :closed?

    # The failed A connection had actually started sending the request to
    # the proxy using the absolute-form request target.
    request_bytes = a.sockets[0].writes.join
    assert_includes request_bytes, 'GET http://service.internal/started HTTP/1.1'

    # Proxy approval is distinct from direct approval.
    refute_empty approval.checks
    assert_equal [[:proxy, a.connect_paths[0].key],
                  [:proxy, b.connect_paths[0].key],
                  [:proxy, a.connect_paths[1].key]], approval.checks
    assert(approval.checks.all? { |kind, _key| kind == :proxy })
  ensure
    a&.finish if a&.started?
    b&.finish if b&.started?
  end

  def test_retry_rechecks_proxy_approval_for_bound_route
    approval = SeparateApproval.new(direct: false, proxy: true)
    http = new_http({ failure: true }, { failure: false })
    http.proxy_address = 'proxy-a.internal'
    http.proxy_port = 1000
    http.network_path_approval = approval
    http.scripts[0][:on_first_close] = lambda do |_socket|
      approval.instance_variable_set(:@proxy, false)
    end

    http.start
    error = assert_raise(Net::HTTP::MissingNetworkApproval) do
      http.get('/started')
    end

    assert_equal :proxy, error.approval_kind
    assert_match(/missing proxy network approval/, error.message)
    assert_equal 1, http.connect_paths.size
    assert_predicate http.sockets[0], :closed?
    assert_equal 1, http.sockets[0].close_count
    assert_equal 1, http.sockets.size
  ensure
    http&.finish if http&.started?
  end

  def test_reused_connection_is_replaced_when_selected_path_changes
    approval = SeparateApproval.new(direct: true, proxy: true)
    http = new_http({ failure: false }, { failure: false })
    http.proxy_address = 'proxy-a.internal'
    http.proxy_port = 1000
    http.network_path_approval = approval

    http.start
    assert_equal '200', http.get('/one').code
    first_socket = http.sockets.first
    refute_predicate first_socket, :closed?

    http.proxy_address = 'proxy-b.internal'
    http.proxy_port = 2000
    assert_equal '200', http.get('/two').code

    assert_predicate first_socket, :closed?
    assert_equal 2, http.connect_paths.size
    assert_equal %w[proxy-a.internal proxy-b.internal],
                 http.connect_paths.map(&:proxy_address)
    refute_predicate http.sockets[1], :closed?
  ensure
    http&.finish if http&.started?
  end

  def test_reused_connection_is_closed_when_current_approval_is_revoked
    approval = SeparateApproval.new(direct: true, proxy: false)
    http = new_http({ failure: false })
    http.network_path_approval = approval

    http.start
    assert_equal '200', http.get('/one').code
    socket = http.sockets.first

    approval.instance_variable_set(:@direct, false)

    error = assert_raise(Net::HTTP::MissingNetworkApproval) do
      http.get('/two')
    end
    assert_equal :direct, error.approval_kind
    assert_match(/missing direct network approval/, error.message)
    assert_predicate socket, :closed?
    assert_equal 1, http.connect_paths.size
  ensure
    http&.finish if http&.started?
  end

  def test_direct_error_names_missing_direct_approval
    http = Net::HTTP.new('direct-only.internal', 80)
    http.proxy_from_env = false
    http.network_path_policy = Net::HTTP::NetworkPathPolicy.new(
      direct: ->(_path) { false },
      proxy: ->(_path) { true }
    )

    error = assert_raise(Net::HTTP::MissingNetworkApproval) do
      http.get('/')
    end

    assert_equal :direct, error.approval_kind
    assert_match(/missing direct network approval/, error.message)
    assert_match(/direct-only\.internal:80/, error.message)
    refute_predicate http, :started?
  end

  def test_proxy_error_names_missing_proxy_approval
    http = Net::HTTP.new('target.internal', 80)
    http.proxy_from_env = false
    http.proxy_address = 'proxy.internal'
    http.proxy_port = 3128
    http.network_path_policy = Net::HTTP::NetworkPathPolicy.new(
      direct: ->(_path) { true },
      proxy: ->(_path) { false }
    )

    error = assert_raise(Net::HTTP::MissingNetworkApproval) do
      http.get('/')
    end

    assert_equal :proxy, error.approval_kind
    assert_equal :proxy, error.network_path.kind
    assert_match(/missing proxy network approval/, error.message)
    assert_match(/proxy\.internal:3128/, error.message)
    refute_predicate http, :started?
  end

  def test_resolves_direct_and_proxy_paths
    direct = Net::HTTP.new('direct.internal', 443)
    direct.use_ssl = true
    direct.proxy_from_env = false

    path = direct.send(:resolve_network_path)
    assert_predicate path, :direct?
    assert_equal 'direct.internal', path.connection_address
    assert_equal 443, path.connection_port
    assert path.use_ssl?

    proxied = Net::HTTP.new('target.internal', 8080)
    proxied.proxy_from_env = false
    proxied.proxy_address = 'proxy.internal'
    proxied.proxy_port = 3128

    path = proxied.send(:resolve_network_path)
    assert_predicate path, :proxy?
    assert_equal 'proxy.internal', path.connection_address
    assert_equal 3128, path.connection_port
    assert_equal 'target.internal', path.target_address
    assert_equal 8080, path.target_port
  end

  def test_real_connect_opens_selected_proxy_address_and_finish_closes_socket
    opened = []
    raw_socket = RawSocketDouble.new
    http = Net::HTTP.new('target.internal', 80)
    http.proxy_from_env = false
    http.proxy_address = 'proxy.internal'
    http.proxy_port = 3128
    http.define_singleton_method(:timeouted_connect) do |address, port|
      opened << [address, port]
      raw_socket
    end

    http.start

    assert_equal [['proxy.internal', 3128]], opened
    assert_equal :proxy, http.connected_network_path.kind
    refute_predicate raw_socket, :closed?

    http.finish
    assert_predicate raw_socket, :closed?
  end

  def test_new_request_resolves_changed_environment_proxy_configuration
    original = ENV.slice('http_proxy', 'no_proxy')
    ENV.delete('no_proxy')
    ENV['http_proxy'] = 'http://env-proxy-a:1000'

    http = Net::HTTP.new('env-target.internal', 80)
    first = http.send(:resolve_network_path)
    assert_predicate first, :proxy?
    assert_equal 'env-proxy-a', first.proxy_address

    ENV['http_proxy'] = 'http://env-proxy-b:2000'
    second = http.send(:resolve_network_path)
    assert_equal 'env-proxy-b', second.proxy_address
    assert_equal 2000, second.proxy_port
    refute_equal first, second
  ensure
    original.each { |key, value| value.nil? ? ENV.delete(key) : ENV[key] = value }
  end
end
