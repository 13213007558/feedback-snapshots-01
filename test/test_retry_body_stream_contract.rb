# frozen_string_literal: true

# Contract tests for the retry boundary that Net::HTTP::Persistent inherits
# from Net::HTTP. They document, with observable bytes, what a retry actually
# re-sends when the request body comes from a body_stream.
#
# Asserted facts:
#   * Persistent has no retry loop of its own; it only forwards #max_retries to
#     Net::HTTP (see Net::HTTP#transport_request).
#   * Net::HTTP retries solely on the method name being in IDEMPOTENT_METHODS_
#     and the exception being in its rescue list. It never rewinds a stream.
#   * A partially consumed body_stream is therefore replayed from its current
#     position. An exhausted stream re-sends an EMPTY body while the caller can
#     still receive 200. That is not safe recovery.
#
# Run: ruby -Ilib -Itest test/test_retry_body_stream_contract.rb

require 'minitest/autorun'
require 'net/http/persistent'
require 'stringio'

# Deterministic in-memory socket; Net::HTTP wraps it in Net::BufferedIO.
class ContractSocket
  attr_reader :written, :body_bytes, :write_calls, :id

  def initialize(id, script)
    @id = id
    @script = script
    @out = String.new(encoding: Encoding::BINARY)
    @inbox = StringIO.new(String.new(encoding: Encoding::BINARY))
    @written = 0
    @body_bytes = 0
    @write_calls = 0
    @header_done = false
  end

  def write(str)
    raise IOError, 'closed stream' if @closed
    str = str.to_str
    @write_calls += 1
    if (hidx = str.index("\r\n\r\n"))
      emit(str.byteslice(0, hidx + 4))
      tail = str.byteslice(hidx + 4, str.bytesize) || +''
      write_body(tail) unless tail.empty?
    elsif @header_done
      write_body(str)
    else
      emit(str)
    end
    maybe_respond
    str.bytesize
  end

  def write_nonblock(str, exception: true); write(str); end

  def read_nonblock(maxlen, buf = nil, exception: true)
    chunk = @inbox.read(maxlen)
    if chunk.nil? || chunk.empty?
      raise EOFError if exception
      return nil
    end
    buf ? buf.replace(chunk) : chunk
  end

  def wire_after_header; @out.split("\r\n\r\n", 2).last || +''; end

  def to_io; self; end
  def wait_readable(_); nil; end
  def wait_writable(_); true; end
  def eof?; @inbox.eof?; end
  def closed?; @closed == true; end
  def close; @closed = true; end
  def setsockopt(*); end

  private

  def write_body(part)
    keep = @script[:fail_after_body_bytes]
    return emit(part) unless keep
    remaining = keep - @body_bytes
    if remaining >= part.bytesize
      emit(part)
      raise Errno::ECONNRESET, 'scripted mid-body reset' if @body_bytes >= keep
    else
      emit(part.byteslice(0, remaining)) if remaining.positive?
      raise Errno::ECONNRESET, 'scripted mid-body reset'
    end
  end

  def emit(str)
    @out << str
    @written += str.bytesize
    if @header_done
      @body_bytes += str.bytesize
    elsif (idx = str.index("\r\n\r\n"))
      @header_done = true
      @body_bytes += (str.bytesize - (idx + 4))
    end
  end

  def maybe_respond
    resp = @script[:response]
    return unless resp
    return if @responded
    @responded = true
    status_line, headers, body = resp
    head = +"#{status_line}\r\n"
    headers.each { |k, v| head << "#{k}: #{v}\r\n" }
    head << "\r\n"
    @inbox.write(head)
    @inbox.write(body)
    @inbox.rewind
  end
end

# Stream without rewind, mirroring a pipe/socket-backed body source.
class ForwardOnlyStream
  def initialize(data); @data = data.b; @pos = 0; end
  attr_reader :pos

  def read(length = nil, outbuf = nil)
    chunk = length ? @data.byteslice(@pos, length) : @data.byteslice(@pos..)
    return nil if chunk.nil? || chunk.empty?
    @pos += chunk.bytesize
    outbuf ? outbuf.replace(chunk) : chunk
  end

  def rewind; raise IOError, 'cannot rewind a forward-only stream'; end
  def eof?; @pos >= @data.bytesize; end
  def close; end
end

# Rewindable source that records how often it is actually rewound.
class TrackedStringIO < StringIO
  attr_reader :rewind_count
  def initialize(*)
    super
    @rewind_count = 0
  end
  def rewind
    @rewind_count += 1
    super
  end
end

class TestRetryBodyStreamContract < Minitest::Test
  BODY = 'ABCDEFGHIJ'
  OK = ['HTTP/1.1 200 OK', { 'Content-Length' => '2' }, 'ok']

  def setup
    @sockets = []
    @scripts = []
    @connect_attempts = 0
  end

  # Replace Net::HTTP#connect for the duration of a block, restoring it after.
  def with_fake_connect
    owner = self
    Net::HTTP.class_eval do
      alias_method :_contract_connect, :connect unless method_defined?(:_contract_connect)
      define_method(:connect) { owner.fake_connect(self) }
    end
    yield
  ensure
    Net::HTTP.class_eval do
      remove_method(:connect)
      alias_method :connect, :_contract_connect
      remove_method :_contract_connect
    end
  end

  def fake_connect(http)
    @connect_attempts += 1
    script = @scripts.fetch(@sockets.size)
    raise Errno::ECONNREFUSED, 'scripted connect refusal' if script[:fail_on_connect]
    io = ContractSocket.new(@sockets.size + 1, script)
    @sockets << io
    http.instance_variable_set(:@socket,
      Net::BufferedIO.new(io, read_timeout: 60, write_timeout: 60))
    http.instance_variable_set(:@last_communicated, nil)
  end

  def build_request(method, stream, chunked)
    uri = URI('http://example.test/resource')
    req = Net::HTTP.const_get(method.capitalize).new(uri.request_uri)
    if chunked
      req['Transfer-Encoding'] = 'chunked'
    else
      req['Content-Length'] = BODY.bytesize.to_s
    end
    req.body_stream = stream
    [uri, req]
  end

  def run_request(method:, stream:, chunked: false, max_retries: 1, scripts:)
    @scripts = scripts
    uri, req = build_request(method, stream, chunked)
    persistent = Net::HTTP::Persistent.new(name: 'contract')
    persistent.max_retries = max_retries
    with_fake_connect do
      begin
        res = persistent.request(uri, req)
        [:ok, res.code]
      rescue => e
        [:raised, e.class]
      end
    end
  end

  def test_put_content_length_rewindable_stream_does_not_rewind_and_resends_empty
    stream = TrackedStringIO.new(BODY)
    status, code = run_request(
      method: 'PUT', stream: stream, max_retries: 1,
      scripts: [{ fail_after_body_bytes: 4 }, { response: OK }])
    assert_equal :ok, status
    assert_equal '200', code
    assert_equal 2, @sockets.size
    assert_equal 'ABCD', @sockets[0].wire_after_header
    assert_equal '', @sockets[1].wire_after_header # empty body, still 200
    assert_equal 0, stream.rewind_count             # library never rewinds
    assert_equal BODY.bytesize, stream.pos          # first pass consumed all
  end

  def test_forward_only_stream_same_empty_replay_without_rewind_capability
    stream = ForwardOnlyStream.new(BODY)
    status, code = run_request(
      method: 'PUT', stream: stream, max_retries: 1,
      scripts: [{ fail_after_body_bytes: 4 }, { response: OK }])
    assert_equal :ok, status
    assert_equal '200', code
    assert_equal 'ABCD', @sockets[0].wire_after_header
    assert_equal '', @sockets[1].wire_after_header
  end

  def test_post_is_not_retried_even_with_max_retries_one
    stream = ForwardOnlyStream.new(BODY)
    status, klass = run_request(
      method: 'POST', stream: stream, max_retries: 1,
      scripts: [{ fail_after_body_bytes: 4 }, { response: OK }])
    assert_equal :raised, status
    assert_equal Errno::ECONNRESET, klass
    assert_equal 1, @sockets.size
    assert_equal 'ABCD', @sockets[0].wire_after_header
  end

  def test_max_retries_zero_forbids_retry_despite_idempotent_name
    stream = ForwardOnlyStream.new(BODY)
    status, klass = run_request(
      method: 'PUT', stream: stream, max_retries: 0,
      scripts: [{ fail_after_body_bytes: 4 }, { response: OK }])
    assert_equal :raised, status
    assert_equal Errno::ECONNRESET, klass
    assert_equal 1, @sockets.size
  end

  def test_chunked_replay_emits_only_terminator_on_second_attempt
    stream = TrackedStringIO.new(BODY)
    status, code = run_request(
      method: 'PUT', stream: stream, chunked: true, max_retries: 1,
      scripts: [{ fail_after_body_bytes: 8 }, { response: OK }])
    assert_equal :ok, status
    assert_equal '200', code
    assert_includes @sockets[0].wire_after_header, 'ABCDE'
    assert_equal "0\r\n\r\n", @sockets[1].wire_after_header # empty chunk
    assert_equal 0, stream.rewind_count
  end

  def test_connect_refusal_is_outside_the_retry_boundary
    stream = ForwardOnlyStream.new(BODY)
    status, klass = run_request(
      method: 'PUT', stream: stream, max_retries: 1,
      scripts: [{ fail_on_connect: true }, { response: OK }])
    assert_equal :raised, status
    # Persistent wraps ECONNREFUSED in its own Error before Net::HTTP retries.
    assert_equal Net::HTTP::Persistent::Error, klass
    assert_equal 1, @connect_attempts   # connect failure is never retried
    assert_empty @sockets               # no usable socket, zero bytes sent
  end

  def test_caller_driven_rewind_replays_the_full_body
    stream = TrackedStringIO.new(BODY)
    @scripts = [{ fail_after_body_bytes: 4 }, { response: OK }]
    persistent = Net::HTTP::Persistent.new(name: 'manual')
    persistent.max_retries = 0 # caller owns replay policy
    uri = URI('http://example.test/resource')
    attempts = 0
    code = nil
    with_fake_connect do
      begin
        attempts += 1
        stream.rewind if attempts > 1
        req = Net::HTTP::Put.new(uri.request_uri)
        req['Content-Length'] = BODY.bytesize.to_s
        req.body_stream = stream
        code = persistent.request(uri, req).code
      rescue Errno::ECONNRESET
        retry if attempts < 2
      end
    end
    assert_equal '200', code
    assert_equal 1, stream.rewind_count
    assert_equal 'ABCDEFGHIJ', @sockets[1].wire_after_header
  end
end
