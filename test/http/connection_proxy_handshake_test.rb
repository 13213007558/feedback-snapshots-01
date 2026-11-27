# frozen_string_literal: true

require "test_helper"
require "stringio"

class HTTPConnectionProxyHandshakeTest < Minitest::Test
  cover "HTTP::Connection*"

  PROXY = { proxy_address: "proxy.corp.local", proxy_port: 3128 }.freeze

  # In-memory body stream that can only be consumed once: it has no
  # #rewind, and it counts every #read so tests can prove how many
  # times the connection touched the body.
  class OneShotStream
    attr_reader :read_count

    def initialize(data)
      @io = StringIO.new(data)
      @read_count = 0
    end

    def read(*args)
      @read_count += 1
      @io.read(*args)
    end

    def size
      @io.size
    end
  end

  # Fake connection socket driven by a scripted list of readpartial
  # results. Every write/read/close is logged so tests can assert the
  # exact order of the exchange.
  class FakeConnection
    attr_reader :ops

    def initialize(reads)
      @reads  = reads
      @ops    = []
      @closed = false
    end

    def connect(*); end

    def start_tls(*); end

    def write(data)
      @ops << [:write, data.dup]
      data.bytesize
    end

    def readpartial(_size, _buffer = nil)
      @ops << [:read]
      @reads.shift || :eof
    end

    def close
      @closed = true
      @ops << [:close]
    end

    def closed?
      @closed
    end

    def op_kinds
      @ops.map(&:first)
    end

    def wire
      @ops.select { |op| op[0] == :write }.map(&:last).join
    end
  end

  def build_request(body:, uri: "http://example.com/upload", proxy: PROXY)
    HTTP::Request.new(verb: :post, uri: uri, proxy: proxy, body: body)
  end

  def build_connection(socket, req)
    timeout_class = fake(new: socket)
    options = HTTP::Options.new(
      timeout_class: timeout_class,
      persistent:    "http://example.com"
    )
    HTTP::Connection.new(req, options)
  end

  # Scenario 1: the proxy deliberates and then refuses the request with a
  # final 407 instead of 100 Continue. The one-shot body stream must never
  # be read, and the caller sees the refusal as the response.
  def test_proxy_delayed_refusal_never_reads_the_body
    body = OneShotStream.new("x" * 100)
    req  = build_request(body: body)
    socket = FakeConnection.new([
      "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=corp\r\n",
      "Content-Length: 0\r\n\r\n"
    ])
    conn = build_connection(socket, req)

    assert_equal :idle, conn.request_phase

    conn.send_request(req)

    assert_equal :proxy_refused, conn.request_phase

    conn.read_headers!

    # phase identifier the caller receives
    assert_equal :proxy_refused, conn.request_phase
    assert_equal 407, conn.status_code

    # the body stream was never read
    assert_equal 0, body.read_count

    # headers went out (with Expect), the proxy answered, no body was sent
    assert_equal %i[write read read], socket.op_kinds
    assert_includes socket.wire, "Expect: 100-continue"
    refute_includes socket.wire, "x" * 100

    # connection disposition: refusal is a complete, framed response,
    # so the connection stays open and reusable
    refute socket.closed?
    assert_predicate conn, :keep_alive?
  end

  # Scenario 2: the proxy agrees with 100 Continue and the target responds
  # immediately. The body is streamed exactly once, after the proxy's go-ahead.
  def test_proxy_accept_then_target_responds
    body = OneShotStream.new("payload")
    req  = build_request(body: body)
    socket = FakeConnection.new([
      "HTTP/1.1 100 Continue\r\n\r\n",
      "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    ])
    conn = build_connection(socket, req)

    conn.send_request(req)

    # proxy confirmed readiness before the body was consumed
    assert_equal :proxy_ready, conn.request_phase

    conn.read_headers!

    # phase identifier the caller receives
    assert_equal :target_responded, conn.request_phase
    assert_equal 200, conn.status_code
    assert_equal "ok", conn.readpartial

    # the body stream was consumed exactly once
    assert_equal 2, body.read_count # one read for content, one returning nil at EOF
    assert_equal 1, socket.wire.scan("payload").size

    # headers -> proxy read (100) -> body -> target response
    assert_equal %i[write read write read], socket.op_kinds

    # connection disposition: kept open
    refute socket.closed?
    assert_predicate conn, :keep_alive?
  end

  # Scenario 3: a second request over the same, now established connection
  # skips the handshake entirely and keeps the current streaming semantics.
  def test_second_request_on_established_connection_streams_directly
    body = OneShotStream.new("first")
    req  = build_request(body: body)
    socket = FakeConnection.new([
      "HTTP/1.1 100 Continue\r\n\r\n",
      "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
      "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
    ])
    conn = build_connection(socket, req)

    conn.send_request(req)
    conn.read_headers!
    assert_equal "ok", conn.readpartial
    assert_equal "", conn.readpartial # drains the parser and finishes the response

    assert_predicate conn, :finished_request?
    ops_before = socket.ops.length

    second_body = OneShotStream.new("second")
    second_req  = build_request(body: second_body, uri: "http://example.com/upload2")
    conn.send_request(second_req)
    conn.read_headers!

    # phase identifier the caller receives
    assert_equal :target_responded, conn.request_phase
    assert_equal 200, conn.status_code

    # the second body stream was consumed exactly once
    assert_equal 2, second_body.read_count

    # no handshake on an established connection: headers and body go out
    # in a single write, with no read in between and no Expect header
    second_ops = socket.ops[ops_before..]
    assert_equal %i[write read], second_ops.map(&:first)
    second_wire = second_ops.select { |op| op[0] == :write }.map(&:last).join
    assert_includes second_wire, "second"
    refute_includes second_wire, "Expect"

    # connection disposition: same socket, still open
    refute socket.closed?
    assert_predicate conn, :keep_alive?
  end

  # After a refusal the connection can be reused: the next exchange on the
  # now-established connection streams normally and reports the new phase.
  def test_connection_reuse_after_refusal
    body = OneShotStream.new("x" * 10)
    req  = build_request(body: body)
    socket = FakeConnection.new([
      "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n",
      "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    ])
    conn = build_connection(socket, req)

    conn.send_request(req)
    conn.read_headers!

    assert_equal :proxy_refused, conn.request_phase
    assert_equal "", conn.readpartial # drains the framed empty refusal body
    assert_predicate conn, :finished_request?

    second_body = OneShotStream.new("y")
    conn.send_request(build_request(body: second_body))
    conn.read_headers!

    assert_equal :target_responded, conn.request_phase
    assert_equal 200, conn.status_code
    assert_equal 2, second_body.read_count
  end

  # Direct connections have no proxy to confirm with: the body streams
  # immediately, exactly as before.
  def test_direct_connection_keeps_streaming_semantics
    body = OneShotStream.new("direct")
    req  = build_request(body: body, proxy: {})
    socket = FakeConnection.new([
      "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    ])
    conn = build_connection(socket, req)

    conn.send_request(req)
    conn.read_headers!

    assert_equal :target_responded, conn.request_phase
    assert_equal %i[write read], socket.op_kinds
    refute_includes socket.wire, "Expect"
    assert_includes socket.wire, "direct"
  end

  # A refused CONNECT tunnel is a proxy refusal: the caller can tell it
  # apart from failures that happen past the proxy.
  def test_refused_connect_tunnel_marks_proxy_refused
    req = HTTP::Request.new(
      verb: :get, uri: "https://example.com/", proxy: PROXY
    )
    socket = FakeConnection.new([
      "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n"
    ])
    conn = build_connection(socket, req)

    assert_predicate conn, :failed_proxy_connect?
    assert_equal :proxy_refused, conn.request_phase
  end

  # Once the CONNECT tunnel is up, a later failure is reported as happening
  # past the proxy: the phase stays :tunnel_established.
  def test_failure_after_tunnel_established_is_distinct_from_refusal
    req = HTTP::Request.new(
      verb: :post, uri: "https://example.com/upload", proxy: PROXY, body: "data"
    )
    socket = FakeConnection.new([
      "HTTP/1.1 200 Connection established\r\n\r\n"
    ])
    conn = build_connection(socket, req)

    assert_equal :tunnel_established, conn.request_phase

    conn.send_request(req)

    # the tunnel drops before the target answers
    assert_raises(HTTP::ResponseHeaderError) { conn.read_headers! }
    assert_equal :tunnel_established, conn.request_phase
  end
end
