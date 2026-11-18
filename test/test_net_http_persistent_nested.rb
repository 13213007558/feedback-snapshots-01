require 'rubygems'
require 'minitest/autorun'
require 'net/http/persistent'
require 'timeout'

HAVE_OPENSSL = defined?(OpenSSL::SSL) unless defined?(HAVE_OPENSSL)

##
# Tests for nested requests: a response block that performs another request
# through the same Net::HTTP::Persistent client.
#
# The sandbox these tests run in forbids binding sockets, so "endpoints" are
# in-process fakes keyed by host:port that record every request they receive
# and play back scripted responses.  A RecordingPool wraps the real pool to
# log every checkout/checkin so the stack discipline can be asserted.

class TestNetHttpPersistentNested < Minitest::Test

  class FakeResponse # :nodoc:
    attr_reader :body

    def initialize body
      @body = body
    end

    def http_version() '1.1' end
    def connection_close?() false end
    def connection_keep_alive?() true end
    def read_body() @body end
  end

  ##
  # Records every request routed to it and responds through the given block.

  class RecordingEndpoint # :nodoc:
    Request = Struct.new :method, :path, :authorization, :http, :response_body

    attr_reader :requests

    def initialize &responder
      @responder = responder
      @requests  = []
      @lock      = Mutex.new
    end

    def handle http, req
      record = Request.new req.method, req.path, req['authorization'], http

      @lock.synchronize { @requests << record }

      body = @responder.call self, req
      record.response_body = body

      FakeResponse.new body
    end
  end

  ##
  # Duck-typed stand-in for Net::HTTP.  Only implements the methods
  # Net::HTTP::Persistent calls.

  class RecordingHTTP # :nodoc:
    attr_accessor :use_ssl, :ciphers, :ssl_timeout, :ssl_version,
                  :min_version, :max_version, :verify_depth, :verify_mode,
                  :ca_file, :ca_path, :cert, :key, :cert_store,
                  :ignore_eof, :keep_alive_timeout, :read_timeout,
                  :write_timeout, :open_timeout
    attr_reader :address, :port

    def initialize endpoint, address, port
      @endpoint = endpoint
      @address  = address
      @port     = port
      @use_ssl  = false
      @started  = false
    end

    def start()   @started = true  end
    def started?() @started        end
    def finish()  @started = false end
    def proxy?()  false            end
    def proxy_address() nil        end
    def proxy_port()    nil        end
    def max_retries=(_)            end
    def set_debug_output(_)        end

    def request req, &block
      response = @endpoint.handle self, req

      block.call response if block

      response
    end
  end

  ##
  # The real pool, plus an event log of every checkout/checkin.

  class RecordingPool < Net::HTTP::Persistent::Pool # :nodoc:
    Event = Struct.new :action, :target, :connection, :depth

    attr_reader :events

    def initialize options = {}, &block
      super

      @events     = []
      @event_lock = Mutex.new
    end

    def checkout net_http_args
      connection = super

      record :checkout, net_http_args, connection,
             Thread.current[@key][net_http_args].size

      connection
    end

    def checkin net_http_args
      return super if net_http_args.is_a? Hash # ConnectionPool fork hook

      stack = Thread.current[@key][net_http_args]

      record :checkin, net_http_args, stack.last, stack.size

      super
    end

    private

    def record action, net_http_args, connection, depth
      @event_lock.synchronize do
        @events << Event.new(action, net_http_args[0, 2], connection, depth)
      end
    end
  end

  def setup
    @endpoints = {}
  end

  def endpoint host, port, &responder
    endpoint = RecordingEndpoint.new(&responder)
    @endpoints[[host, port]] = endpoint
    endpoint
  end

  def new_client pool_size:
    client    = Net::HTTP::Persistent.new pool_size: pool_size
    endpoints = @endpoints

    pool = RecordingPool.new size: pool_size do |net_http_args|
      endpoint = endpoints.fetch net_http_args[0, 2]

      connection = Net::HTTP::Persistent::Connection.allocate
      connection.http = RecordingHTTP.new endpoint, *net_http_args[0, 2]
      connection.ssl_generation = client.ssl_generation
      connection.reset

      connection
    end

    client.instance_variable_set :@pool, pool

    client
  end

  def get uri, token
    req = Net::HTTP::Get.new uri.request_uri
    req['authorization'] = "Bearer #{token}"
    req
  end

  def pool_stats client
    available = client.pool.available

    {
      created:  available.instance_variable_get(:@created),
      enqueued: available.instance_variable_get(:@enqueued),
    }
  end

  def wait_for queue
    Timeout.timeout(10) { queue.pop }
  end

  def monotonic
    Process.clock_gettime Process::CLOCK_MONOTONIC
  end

  def events_for client, host, port
    client.pool.events.select { |event| event.target == [host, port] }
  end

  ##
  # Different target, different connection: the nested request must not
  # receive the outer connection, and each checkin must return the resource
  # that was checked out.  Barriers make the interleaving deterministic.

  def test_nested_request_different_host
    endpoint_a = endpoint('a.test', 80) { |_, _| 'response-A' }

    b_entered = Queue.new
    b_release = Queue.new
    endpoint_b = endpoint('b.test', 80) do |_, _|
      b_entered.push true
      b_release.pop
      'response-B'
    end

    http = new_client pool_size: 2

    uri_a = URI 'http://a.test/outer'
    uri_b = URI 'http://b.test/inner'

    outer_entered = Queue.new
    outer_release = Queue.new
    nested_done   = Queue.new
    outer_finish  = Queue.new

    worker = Thread.new do
      http.request uri_a, get(uri_a, 'token-A') do |_response|
        outer_entered.push true
        wait_for outer_release

        nested = http.request uri_b, get(uri_b, 'token-B')
        nested_done.push nested.body

        wait_for outer_finish
      end
    end

    begin
      wait_for outer_entered

      stats = pool_stats http
      assert_equal 1, stats[:created]
      assert_equal 0, stats[:enqueued], 'outer connection is checked out'

      outer_release.push true
      wait_for b_entered

      stats = pool_stats http
      assert_equal 2, stats[:created],
                   'nested request to another host gets its own connection'
      assert_equal 0, stats[:enqueued],
                   'both connections are checked out while nested'

      checkouts = http.pool.events.select { |event| event.action == :checkout }
      assert_equal [['a.test', 80], ['b.test', 80]], checkouts.map(&:target)
      refute_same checkouts[0].connection, checkouts[1].connection,
                  'nested checkout must not receive the outer connection'

      b_release.push true

      assert_equal 'response-B', wait_for(nested_done)

      stats = pool_stats http
      assert_equal 2, stats[:created]
      assert_equal 1, stats[:enqueued],
                   'inner connection returned, outer still checked out'

      outer_finish.push true
      worker.value
    ensure
      [outer_release, b_release, outer_finish].each { |queue| queue.push true }
      worker.join
    end

    stats = pool_stats http
    assert_equal 2, stats[:created]
    assert_equal 2, stats[:enqueued], 'all connections returned at the end'

    events = http.pool.events
    checkins = events.select { |event| event.action == :checkin }
    assert_equal [['b.test', 80], ['a.test', 80]], checkins.map(&:target),
                 'inner connection is checked in before the outer one'

    checkouts = events.select { |event| event.action == :checkout }
    checkins.zip(checkouts.reverse).each do |checkin, checkout|
      assert_same checkout.connection, checkin.connection,
                  'each checkin returns the connection that was checked out'
    end

    assert_equal 1, endpoint_a.requests.size
    assert_equal 'Bearer token-A', endpoint_a.requests[0].authorization
    assert_equal '/outer', endpoint_a.requests[0].path

    assert_equal 1, endpoint_b.requests.size
    assert_equal 'Bearer token-B', endpoint_b.requests[0].authorization
    assert_equal '/inner', endpoint_b.requests[0].path

    # a third request after the outer one completes reuses the pooled
    # connection for its target
    third = http.request uri_a, get(uri_a, 'token-A3')
    assert_equal 'response-A', third.body

    stats = pool_stats http
    assert_equal 2, stats[:created], 'no new connection for the third request'
    assert_equal 2, stats[:enqueued]

    a_checkouts = events_for(http, 'a.test', 80).select { |e| e.action == :checkout }
    assert_same a_checkouts[0].connection, a_checkouts[1].connection

    assert_equal 2, endpoint_a.requests.size
    assert_equal 'Bearer token-A3', endpoint_a.requests[1].authorization
  end

  ##
  # Same target: the pool is reentrant per thread -- the nested checkout
  # reuses the outer connection and the inner checkin must not return it to
  # the available pool.  This works even with a pool of one.

  def test_nested_request_same_host_is_reentrant
    endpoint_a = endpoint('a.test', 80) { |_, req| "response-for-#{req.path}" }

    http = new_client pool_size: 1

    uri_outer = URI 'http://a.test/outer'
    uri_inner = URI 'http://a.test/inner'

    inner_body            = nil
    enqueued_during_outer = nil

    response = http.request uri_outer, get(uri_outer, 'token-outer') do |_|
      inner = http.request uri_inner, get(uri_inner, 'token-inner')

      inner_body            = inner.body
      enqueued_during_outer = pool_stats(http)[:enqueued]
    end

    assert_equal 'response-for-/inner', inner_body
    assert_equal 'response-for-/outer', response.body

    assert_equal 0, enqueued_during_outer,
                 'inner checkin must not return the shared connection'

    stats = pool_stats http
    assert_equal 1, stats[:created], 'same-target nesting shares the connection'
    assert_equal 1, stats[:enqueued]

    checkouts = http.pool.events.select { |event| event.action == :checkout }
    assert_equal [1, 2], checkouts.map(&:depth)
    assert_same checkouts[0].connection, checkouts[1].connection,
                'same-thread same-target checkout is reentrant'

    checkins = http.pool.events.select { |event| event.action == :checkin }
    assert_equal [2, 1], checkins.map(&:depth)

    assert_equal 2, endpoint_a.requests.size
    assert_same endpoint_a.requests[0].http, endpoint_a.requests[1].http
    assert_equal 'Bearer token-outer', endpoint_a.requests[0].authorization
    assert_equal 'Bearer token-inner', endpoint_a.requests[1].authorization

    third = http.request uri_outer, get(uri_outer, 'token-third')
    assert_equal 'response-for-/outer', third.body
    assert_equal 1, pool_stats(http)[:created]
  end

  ##
  # HTTP and HTTPS targets get separate connections with the right TLS
  # settings; credentials never leak across targets.

  def test_nested_request_mixed_http_and_https
    skip 'OpenSSL is missing' unless HAVE_OPENSSL

    secure = endpoint('secure.test', 443) { |_, req| "https-#{req.path}" }
    plain  = endpoint('plain.test', 80)   { |_, req| "http-#{req.path}" }

    http = new_client pool_size: 4

    https_outer = URI 'https://secure.test/outer'
    http_inner  = URI 'http://plain.test/inner'

    inner_body = nil

    response = http.request https_outer, get(https_outer, 'token-https') do |_|
      inner_body = http.request(http_inner, get(http_inner, 'token-http')).body
    end

    assert_equal 'https-/outer', response.body
    assert_equal 'http-/inner',  inner_body

    # reverse direction: plain outer, TLS inner
    http_outer  = URI 'http://plain.test/outer2'
    https_inner = URI 'https://secure.test/inner2'

    inner_body = nil

    response = http.request http_outer, get(http_outer, 'token-http') do |_|
      inner_body = http.request(https_inner, get(https_inner, 'token-https')).body
    end

    assert_equal 'http-/outer2',  response.body
    assert_equal 'https-/inner2', inner_body

    secure_http = secure.requests[0].http
    plain_http  = plain.requests[0].http

    refute_same secure_http, plain_http
    assert_equal true,  secure_http.use_ssl
    assert_equal false, plain_http.use_ssl
    assert_equal OpenSSL::SSL::VERIFY_PEER, secure_http.verify_mode
    assert_nil plain_http.verify_mode

    assert_equal %w[Bearer\ token-https Bearer\ token-https],
                 secure.requests.map(&:authorization)
    assert_equal %w[Bearer\ token-http Bearer\ token-http],
                 plain.requests.map(&:authorization)

    stats = pool_stats http
    assert_equal 2, stats[:created]
    assert_equal 2, stats[:enqueued]
  end

  ##
  # Pool of one, different target: the nested checkout cannot be satisfied
  # and must fail promptly with ConnectionPool::TimeoutError instead of
  # waiting forever.  The failed checkout must not disturb the outer
  # connection.

  def test_nested_request_different_host_pool_exhausted
    endpoint_a = endpoint('a.test', 80) { |_, _| 'response-A' }
    endpoint_b = endpoint('b.test', 80) { |_, _| 'response-B' }

    http = new_client pool_size: 1

    uri_a = URI 'http://a.test/outer'
    uri_b = URI 'http://b.test/inner'

    elapsed                 = nil
    enqueued_after_failure  = nil

    response = http.request uri_a, get(uri_a, 'token-A') do |_|
      started = monotonic

      assert_raises ConnectionPool::TimeoutError do
        http.request uri_b, get(uri_b, 'token-B')
      end

      elapsed                = monotonic - started
      enqueued_after_failure = pool_stats(http)[:enqueued]
    end

    assert_equal 'response-A', response.body

    assert_operator elapsed, :>=, 0.4, 'waits for the pool timeout'
    assert_operator elapsed, :<,  2,   'fails promptly, never waits forever'

    assert_equal 0, enqueued_after_failure,
                 'a failed checkout must not leak a checkin'
    assert_equal 0, endpoint_b.requests.size, 'no request reached B'

    stats = pool_stats http
    assert_equal 1, stats[:created]
    assert_equal 1, stats[:enqueued]

    events = http.pool.events
    assert_equal 1, events.count { |event| event.action == :checkout }
    assert_equal 1, events.count { |event| event.action == :checkin }

    third = http.request uri_a, get(uri_a, 'token-A3')
    assert_equal 'response-A', third.body
    assert_equal 1, pool_stats(http)[:created]
  end

  ##
  # Inner request to another host fails: the failed request must check in
  # its own connection -- not the outer one -- and the counts must be
  # consistent immediately, not only after a later rebuild.

  def test_nested_request_inner_failure_returns_correct_connection
    endpoint_a = endpoint('a.test', 80) { |_, _| 'response-A' }

    fail_once = true
    endpoint_b = endpoint('b.test', 80) do |_, _|
      if fail_once then
        fail_once = false
        raise Errno::ECONNREFUSED
      end

      'response-B'
    end

    http = new_client pool_size: 2

    uri_a = URI 'http://a.test/outer'
    uri_b = URI 'http://b.test/inner'

    inner_error         = nil
    stats_after_failure = nil

    response = http.request uri_a, get(uri_a, 'token-A') do |_|
      begin
        http.request uri_b, get(uri_b, 'token-B')
      rescue Net::HTTP::Persistent::Error => e
        inner_error = e
      end

      stats_after_failure = pool_stats http
    end

    assert_equal 'response-A', response.body
    assert_match(/connection refused: b\.test:80/, inner_error.message)

    # consistent right after the failure, before any later request
    assert_equal 2, stats_after_failure[:created]
    assert_equal 1, stats_after_failure[:enqueued],
                 'the failed inner connection is returned, the outer is not'

    assert_equal 1, endpoint_b.requests.size
    assert_equal 'Bearer token-B', endpoint_b.requests[0].authorization

    b_checkout = events_for(http, 'b.test', 80).find { |e| e.action == :checkout }
    b_checkin  = events_for(http, 'b.test', 80).find { |e| e.action == :checkin }
    assert_same b_checkout.connection, b_checkin.connection,
                'the failed request checks in its own connection'

    a_events = events_for http, 'a.test', 80
    assert_equal 1, a_events.count { |e| e.action == :checkin }
    refute_same b_checkin.connection,
                a_events.find { |e| e.action == :checkin }.connection

    # recovery: the returned (finished) connection is restarted in place,
    # proving the error checkin was not masked by a rebuild
    third = http.request uri_b, get(uri_b, 'token-B3')
    assert_equal 'response-B', third.body

    stats = pool_stats http
    assert_equal 2, stats[:created], 'no replacement connection was created'
    assert_equal 2, stats[:enqueued]

    b_checkouts = events_for(http, 'b.test', 80).select { |e| e.action == :checkout }
    assert_same b_checkouts[0].connection, b_checkouts[1].connection

    assert_equal 2, endpoint_b.requests.size
    assert_equal 'Bearer token-B3', endpoint_b.requests[1].authorization
  end

  ##
  # Inner failure on the same target: the shared connection is finished by
  # the failure, but the checkout stack stays balanced -- the inner checkin
  # only pops the stack and must not return the connection to the pool.

  def test_nested_request_same_host_inner_failure
    fail_once = true
    endpoint_a = endpoint('a.test', 80) do |_, req|
      if req.path == '/inner' && fail_once then
        fail_once = false
        raise IOError, 'inner request failed'
      end

      "response-for-#{req.path}"
    end

    http = new_client pool_size: 1

    uri_outer = URI 'http://a.test/outer'
    uri_inner = URI 'http://a.test/inner'

    stats_after_failure = nil

    response = http.request uri_outer, get(uri_outer, 'token-outer') do |_|
      assert_raises IOError do
        http.request uri_inner, get(uri_inner, 'token-inner')
      end

      stats_after_failure = pool_stats http
    end

    assert_equal 'response-for-/outer', response.body

    assert_equal 1, stats_after_failure[:created]
    assert_equal 0, stats_after_failure[:enqueued],
                 'inner checkin only pops the stack, nothing is returned'

    stats = pool_stats http
    assert_equal 1, stats[:created]
    assert_equal 1, stats[:enqueued]

    events = http.pool.events
    assert_equal events.count { |event| event.action == :checkout },
                 events.count { |event| event.action == :checkin }

    # the connection finished by the inner failure is restarted on next use
    third = http.request uri_outer, get(uri_outer, 'token-third')
    assert_equal 'response-for-/outer', third.body
    assert_equal 1, pool_stats(http)[:created]
  end

end
