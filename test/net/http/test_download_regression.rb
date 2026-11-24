# coding: US-ASCII
# frozen_string_literal: false

require 'net/http'
require 'test/unit'
require 'stringio'
require 'zlib'

class NetHTTPDownloadRegressionTest < Test::Unit::TestCase
  PLAINTEXT = (String.new('Net::HTTP download regression: caf\u00e9 / \u03a9 / \u{1f680}', encoding: Encoding::UTF_8) * 4).freeze
  PLAINTEXT_BYTES = PLAINTEXT.b
  GZIP_FIXTURE = Zlib.gzip(PLAINTEXT_BYTES).freeze

  RANGE_START = 4
  RANGE_LENGTH = 16
  RANGE_END = RANGE_START + RANGE_LENGTH - 1
  RANGE_TOTAL = GZIP_FIXTURE.bytesize
  RANGE_BYTES = GZIP_FIXTURE.byteslice(RANGE_START, RANGE_LENGTH).freeze

  class RecordingIO
    attr_reader :close_calls, :closure_count, :error_count, :request

    def initialize(response, read_error: nil)
      @response = StringIO.new(response.b)
      @request = StringIO.new
      @read_error = read_error
      @closed = false
      @close_calls = 0
      @closure_count = 0
      @error_count = 0
    end

    def close
      @close_calls += 1
      return if @closed

      @closed = true
      @closure_count += 1
      @response.close
    end

    def closed?
      @closed
    end

    def eof?
      @response.eof?
    end

    def write_nonblock(chunk, exception: false)
      @request.write(chunk)
      chunk.bytesize
    end

    def read_nonblock(length, buffer = nil, exception: false)
      if @read_error && @response.eof?
        @error_count += 1
        raise @read_error, 'simulated terminal read failure'
      end

      @response.read_nonblock(length, buffer, exception: exception)
    end

    def to_io
      self
    end

    def wait_readable(_timeout = nil)
      nil
    end

    def request_string
      @request.string
    end
  end

  class Harness
    attr_reader :http, :old_io, :old_connection, :new_io, :new_connection

    def initialize(old_response, new_response = nil, read_error: nil)
      @old_io = RecordingIO.new(old_response, read_error: read_error)
      @old_connection = Net::BufferedIO.new(@old_io)

      if new_response
        @new_io = RecordingIO.new(new_response)
        @new_connection = Net::BufferedIO.new(@new_io)
      end

      @http = Net::HTTP.new('downloader.example', 80, nil)
      @http.max_retries = 0
      @http.instance_variable_set(:@started, true)
      @http.instance_variable_set(:@socket, @old_connection)

      replacement = @new_connection
      @http.define_singleton_method(:connect) do
        raise 'unexpected connection attempt' unless replacement

        @socket = replacement
        @last_communicated = nil
      end
    end
  end

  def setup
    omit('zlib is required for gzip regression tests') unless Net::HTTP::HAVE_ZLIB
  end

  def test_lazy_full_gzip_uses_decoded_bytes_and_length
    harness = Harness.new(full_response)
    response = nil

    harness.http.request(full_request) do |res|
      response = res
      assert_equal false, res.instance_variable_get(:@read)
      assert_equal 'gzip', res['content-encoding']
      assert_equal GZIP_FIXTURE.bytesize.to_s, res['content-length']

      body = res.read_body

      assert_equal PLAINTEXT_BYTES, body
      assert_equal Encoding::ASCII_8BIT, body.encoding
      assert_equal PLAINTEXT.bytesize, body.bytesize
      assert_equal PLAINTEXT.bytesize, body.length
      assert_equal PLAINTEXT.length, body.dup.force_encoding(Encoding::UTF_8).length
    end

    assert_nil response['content-encoding']
    assert_equal PLAINTEXT.bytesize.to_s, response['content-length']
    assert_equal PLAINTEXT.bytesize, response.content_length
    assert_equal 0, harness.old_io.closure_count
    assert_same harness.old_connection, harness.http.instance_variable_get(:@socket)
  end

  def test_callback_full_gzip_receives_decoded_chunks
    harness = Harness.new(full_response)
    chunks = []
    response = nil

    harness.http.request(full_request) do |res|
      response = res
      assert_equal false, res.instance_variable_get(:@read)
      assert_callback_stream(res, PLAINTEXT_BYTES, chunks)
    end

    assert_equal PLAINTEXT_BYTES, chunks.join
    assert_nil response['content-encoding']
    assert_equal PLAINTEXT.bytesize.to_s, response['content-length']
    assert_equal 0, harness.old_io.closure_count
    assert_same harness.old_connection, harness.http.instance_variable_get(:@socket)
  end

  def test_lazy_range_keeps_declared_compressed_representation
    harness = Harness.new(range_response)
    request = mixed_range_request
    response = nil

    harness.http.request(request) do |res|
      response = res
      body = res.read_body

      assert_equal RANGE_BYTES, body
      assert_equal Encoding::ASCII_8BIT, body.encoding
    end

    assert_range_headers(response)
    assert_request_sent_range_and_automatic_gzip(harness.old_io)
    assert_equal 0, harness.old_io.closure_count
    assert_same harness.old_connection, harness.http.instance_variable_get(:@socket)
  end

  def test_callback_range_receives_raw_declared_bytes
    harness = Harness.new(range_response)
    chunks = []
    response = nil

    harness.http.request(mixed_range_request) do |res|
      response = res
      assert_callback_stream(res, RANGE_BYTES, chunks)
    end

    assert_equal RANGE_BYTES, chunks.join
    assert_range_headers(response)
    assert_request_sent_range_and_automatic_gzip(harness.old_io)
    assert_equal 0, harness.old_io.closure_count
    assert_same harness.old_connection, harness.http.instance_variable_get(:@socket)
  end

  def test_callback_terminal_read_error_keeps_partial_result_evidence_and_recycles_connection
    harness = Harness.new(broken_end_response, ok_response, read_error: Errno::ECONNRESET)
    chunks = []
    response = nil

    error = assert_raise(Errno::ECONNRESET) do
      harness.http.request(Net::HTTP::Get.new('/broken-download')) do |res|
        response = res
        assert_callback_stream(res, PLAINTEXT_BYTES, chunks)
      end
    end

    assert_match(/simulated terminal read failure/, error.message)
    assert_equal PLAINTEXT_BYTES, chunks.join
    assert_equal false, response.instance_variable_get(:@read)
    assert_failed_connection_closed(harness)
    assert_next_request_uses_fresh_connection(harness)
  end

  def test_lazy_terminal_read_error_closes_connection_and_next_request_uses_new_identity
    harness = Harness.new(broken_end_response, ok_response, read_error: IOError)
    response = nil

    error = assert_raise(IOError) do
      harness.http.request(Net::HTTP::Get.new('/broken-lazy-download')) do |res|
        response = res
        res.read_body
      end
    end

    assert_match(/simulated terminal read failure/, error.message)
    assert_equal false, response.instance_variable_get(:@read)
    assert_failed_connection_closed(harness)
    assert_next_request_uses_fresh_connection(harness)
  end

  private

  def full_request
    Net::HTTP::Get.new('/full-download.tar.gz')
  end

  def mixed_range_request
    request = Net::HTTP::Get.new('/mixed-download.tar.gz')
    request.range = RANGE_START..RANGE_END

    assert request.decode_content
    assert_match(/gzip/, request['accept-encoding'])
    assert_equal "bytes=#{RANGE_START}-#{RANGE_END}", request['range']
    request
  end

  def assert_callback_stream(response, expected, chunks)
    offset = chunks.sum(&:bytesize)

    response.read_body do |chunk|
      assert_equal Encoding::ASCII_8BIT, chunk.encoding
      assert_equal expected.byteslice(offset, chunk.bytesize), chunk
      chunks << chunk
      offset += chunk.bytesize
    end

    assert_equal expected.bytesize, offset
    chunks
  end

  def assert_range_headers(response)
    assert_equal '206', response.code
    assert_equal 'gzip', response['content-encoding']
    assert_equal RANGE_BYTES.bytesize.to_s, response['content-length']
    assert_equal "bytes #{RANGE_START}-#{RANGE_END}/#{RANGE_TOTAL}", response['content-range']
    assert_equal RANGE_START..RANGE_END, response.content_range
    assert_equal RANGE_BYTES.bytesize, response.range_length
  end

  def assert_request_sent_range_and_automatic_gzip(io)
    assert_match(/^GET \/mixed-download\.tar\.gz HTTP\/1\.1/, io.request_string)
    assert_match(/^Range: bytes=#{RANGE_START}-#{RANGE_END}\r?$/, io.request_string)
    assert_match(/^Accept-Encoding: [^\r\n]*gzip/, io.request_string)
  end

  def assert_failed_connection_closed(harness)
    old_io = harness.old_io

    assert_equal 1, old_io.error_count
    assert_equal 1, old_io.closure_count
    assert_operator old_io.close_calls, :>=, 1
    assert_predicate old_io, :closed?
    assert_predicate harness.old_connection, :closed?
    assert_same harness.old_io, harness.http.instance_variable_get(:@socket).io
    assert_equal 1, old_io.request_string.scan(%r/^GET \/broken/).size
  end

  def assert_next_request_uses_fresh_connection(harness)
    next_response = harness.http.get('/next-normal-request')

    assert_equal 'ok', next_response.body
    assert_same harness.new_connection, harness.http.instance_variable_get(:@socket)
    assert_same harness.new_io, harness.http.instance_variable_get(:@socket).io
    assert_not_same harness.old_connection, harness.new_connection
    assert_not_same harness.old_io, harness.new_io
    assert_equal 0, harness.new_io.closure_count
    assert_match(/^GET \/next-normal-request HTTP\/1\.1/, harness.new_io.request_string)
  end

  def http_response(body, status, headers)
    text = +"HTTP/1.1 #{status}\r\n"
    headers.each do |name, value|
      text << "#{name}: #{value}\r\n"
    end
    text << "\r\n"
    text.b << body.b
  end

  def full_response
    http_response(GZIP_FIXTURE, '200 OK',
      'Content-Encoding' => 'gzip',
      'Content-Length' => GZIP_FIXTURE.bytesize.to_s,
      'Content-Type' => 'application/gzip')
  end

  def range_response
    http_response(RANGE_BYTES, '206 Partial Content',
      'Content-Encoding' => 'gzip',
      'Content-Length' => RANGE_BYTES.bytesize.to_s,
      'Content-Range' => "bytes #{RANGE_START}-#{RANGE_END}/#{RANGE_TOTAL}",
      'Accept-Ranges' => 'bytes')
  end

  def broken_end_response
    http_response(GZIP_FIXTURE, '200 OK',
      'Content-Encoding' => 'gzip',
      'Connection' => 'keep-alive')
  end

  def ok_response
    http_response('ok', '200 OK', 'Content-Length' => '2')
  end
end
