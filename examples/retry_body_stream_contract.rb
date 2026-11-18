# frozen_string_literal: true

# Observable demo of the Net::HTTP retry boundary as reached through
# Net::HTTP::Persistent. No real network is used: Net::HTTP#connect is replaced
# with an in-memory socket that scripts failures and records every byte sent.
#
# Run:  ruby -Ilib examples/retry_body_stream_contract.rb
#
# What it shows:
#   * Net::HTTP retries only by method name (IDEMPOTENT_METHODS_) and only for
#     a fixed exception list; it never rewinds the request body_stream.
#   * A partially/fully consumed stream is therefore replayed from its current
#     position. With the stream exhausted, the retry sends an EMPTY body and
#     still reports 200. That 200 is not evidence that the body was recovered.
#   * max_retries=0 is the caller's explicit opt-out; a manual rewind is the
#     only way to truly replay a stream-backed body.

require 'net/http/persistent'
require 'stringio'

BODY = 'ABCDEFGHIJ'
OK_RESPONSE = ['HTTP/1.1 200 OK', { 'Content-Length' => '2' }, 'ok'].freeze

class ScriptedSocket
  attr_reader :body_bytes, :write_calls, :id

  def initialize(id, script)
    @id = id
    @script = script
    @out = String.new(encoding: Encoding::BINARY)
    @inbox = StringIO.new(String.new(encoding: Encoding::BINARY))
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
    feed_response if @script[:response] && !@responded
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

  def body_on_wire; @out.split("\r\n\r\n", 2).last || +''; end
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
      raise Errno::ECONNRESET, 'mid-body reset' if @body_bytes >= keep
    else
      emit(part.byteslice(0, remaining)) if remaining.positive?
      raise Errno::ECONNRESET, 'mid-body reset'
    end
  end

  def emit(str)
    @out << str
    if @header_done
      @body_bytes += str.bytesize
    elsif (idx = str.index("\r\n\r\n"))
      @header_done = true
      @body_bytes += (str.bytesize - (idx + 4))
    end
  end

  def feed_response
    @responded = true
    status_line, headers, body = @script[:response]
    head = +"#{status_line}\r\n"
    headers.each { |k, v| head << "#{k}: #{v}\r\n" }
    head << "\r\n"
    @inbox.write(head)
    @inbox.write(body)
    @inbox.rewind
  end
end

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

class CountingStringIO < StringIO
  attr_reader :rewind_count
  def initialize(*); super; @rewind_count = 0; end
  def rewind; @rewind_count += 1; super; end
end

class Demo
  def initialize
    @sockets = []
    @scripts = []
  end

  def with_fake_connect
    owner = self
    Net::HTTP.class_eval do
      alias_method :_demo_connect, :connect unless method_defined?(:_demo_connect)
      define_method(:connect) { owner.fake_connect(self) }
    end
    yield
  ensure
    Net::HTTP.class_eval do
      remove_method(:connect)
      alias_method :connect, :_demo_connect
      remove_method :_demo_connect
    end
  end

  def fake_connect(http)
    script = @scripts.fetch(@sockets.size)
    raise Errno::ECONNREFUSED if script[:fail_on_connect]
    io = ScriptedSocket.new(@sockets.size + 1, script)
    @sockets << io
    http.instance_variable_set(:@socket,
      Net::BufferedIO.new(io, read_timeout: 60, write_timeout: 60))
    http.instance_variable_set(:@last_communicated, nil)
  end

  def call(method, stream, chunked, max_retries, scripts)
    @sockets = []
    @scripts = scripts
    uri = URI('http://example.test/resource')
    req = Net::HTTP.const_get(method.capitalize).new(uri.request_uri)
    if chunked
      req['Transfer-Encoding'] = 'chunked'
    else
      req['Content-Length'] = BODY.bytesize.to_s
    end
    req.body_stream = stream
    persistent = Net::HTTP::Persistent.new(name: 'demo')
    persistent.max_retries = max_retries
    outcome =
      with_fake_connect do
        begin
          res = persistent.request(uri, req)
          "HTTP #{res.code}"
        rescue => e
          "RAISE #{e.class}"
        end
      end
    [outcome, @sockets.map { |s| "conn##{s.id} body=#{s.body_on_wire.inspect}" }]
  end

  def run
    show '1. rewindable StringIO, PUT, reset after 4 body bytes, retries=1',
         call('PUT', CountingStringIO.new(BODY), false, 1,
              [{ fail_after_body_bytes: 4 }, { response: OK_RESPONSE }])

    show '2. forward-only stream, same PUT (cannot rewind)',
         call('PUT', ForwardOnlyStream.new(BODY), false, 1,
              [{ fail_after_body_bytes: 4 }, { response: OK_RESPONSE }])

    show '3. POST (non-idempotent name), same failure, retries=1',
         call('POST', ForwardOnlyStream.new(BODY), false, 1,
              [{ fail_after_body_bytes: 4 }, { response: OK_RESPONSE }])

    show '4. explicit opt-out: PUT with max_retries=0',
         call('PUT', ForwardOnlyStream.new(BODY), false, 0,
              [{ fail_after_body_bytes: 4 }, { response: OK_RESPONSE }])

    show '5. chunked PUT, reset mid-body, retries=1',
         call('PUT', CountingStringIO.new(BODY), true, 1,
              [{ fail_after_body_bytes: 8 }, { response: OK_RESPONSE }])

    show '6. connect refused before any byte, PUT, retries=1',
         call('PUT', ForwardOnlyStream.new(BODY), false, 1,
              [{ fail_on_connect: true }, { response: OK_RESPONSE }])
  end

  def show(title, (outcome, wires))
    puts "-" * 74
    puts title
    puts "  outcome : #{outcome}"
    wires.each { |w| puts "  #{w}" }
  end
end

Demo.new.run
