require 'minitest/autorun'
require 'net/http/persistent'

##
# Exercises the connection-pool contract when a streamed response body is not
# consumed by the caller's block.
#
# Each scenario drives two responses tagged +T1+ and +T2+ through a pool of one
# connection, exits the block at a different boundary, then verifies the next
# request reads only its own response.  The transport is a scripted socket, so
# leftover body bytes really would be consumed by the following request.

class TestNetHttpPersistentBodyExit < Minitest::Test

  ##
  # A socket whose readable bytes are scripted ahead of time and which records
  # what the client wrote.

  class ScriptedIO
    attr_reader :written

    def initialize data
      @data    = data.b
      @pos     = 0
      @closed  = false
      @written = +''
    end

    def read_nonblock length, buffer = nil, exception: true
      return nil if @pos >= @data.bytesize

      chunk = @data.byteslice @pos, length
      @pos += chunk.bytesize

      if buffer then
        buffer.replace chunk
      else
        chunk
      end
    end

    def write_nonblock string, exception: true
      @written << string
      string.bytesize
    end

    def to_io; self; end
    def setsockopt(*args); 0; end
    def wait_readable(timeout = nil); false; end
    def wait_writable(timeout = nil); true; end
    def close; @closed = true; end
    def closed?; @closed; end

    # The scripted peer never closes on its own; a closed connection shows up
    # through Net::HTTP#finish instead.
    def eof?; false; end
  end

  ##
  # A Net::HTTP whose transport is scripted and which counts connections and
  # finishes.  A new instance is created for every connection the pool opens.

  class ScriptedHTTP < Net::HTTP
    class << self
      attr_accessor :scripts
      attr_accessor :connects
      attr_accessor :finishes
      attr_accessor :sockets

      def reset scripts
        self.scripts  = scripts.dup
        self.connects = 0
        self.finishes = 0
        self.sockets  = []
      end
    end

    reset []

    # Replaces Net::HTTP#connect so every connection, including one created
    # again after a finish, reads from the script instead of the network.
    def connect
      self.class.connects += 1

      io = ScriptedIO.new self.class.scripts.shift || ''
      self.class.sockets << io

      @socket = Net::BufferedIO.new io
    end

    def finish
      self.class.finishes += 1
      super
    end
  end

  def self.chunked marker
    parts = marker.scan(/.{1,4}/m)

    "HTTP/1.1 200 OK\r\n" \
      "Transfer-Encoding: chunked\r\n" \
      "Connection: keep-alive\r\n\r\n" +
      parts.map { |part| "#{part.bytesize.to_s 16}\r\n#{part}\r\n" }.join +
      "0\r\n\r\n"
  end

  def self.fixed marker
    "HTTP/1.1 200 OK\r\n" \
      "Content-Length: #{marker.bytesize}\r\n" \
      "Connection: keep-alive\r\n\r\n#{marker}"
  end

  def setup
    @uri  = URI 'http://example.com/path'
    @http = Net::HTTP::Persistent.new pool_size: 1
    @http.idle_timeout = nil
    @http.max_retries  = 0

    # Create connections through the scripted transport instead of the real
    # one.  The other tests use the same pattern with a fake Net::HTTP class.
    available = @http.pool.available
    create_block = proc do |http_args|
      connection = Net::HTTP::Persistent::Connection.allocate
      connection.ssl_generation = @http.ssl_generation
      connection.http = ScriptedHTTP.new http_args[0], http_args[1]
      connection.reset

      connection
    end

    available.instance_variable_set :@create_block, create_block
  end

  def teardown
    @http.shutdown { |http| http.finish } if @http
  end

  def script *responses
    ScriptedHTTP.reset responses
  end

  def test_block_that_returns_without_reading_is_drained
    script self.class.chunked('T1AAA') + self.class.chunked('T2BBB')

    @http.request @uri do |response|
      # read nothing
    end

    assert_equal 0, ScriptedHTTP.finishes, 'unread body is safe to drain'
    assert_equal 1, ScriptedHTTP.connects

    assert_equal 'T2BBB', @http.request(@uri).body
    assert_equal 1, ScriptedHTTP.connects, 'connection was reused'
  end

  def test_break_before_reading_is_drained
    script self.class.fixed('T1AAA') + self.class.fixed('T2BBB')

    @http.request @uri do |response|
      break
    end

    assert_equal 0, ScriptedHTTP.finishes, 'unread body is safe to drain'
    assert_equal 'T2BBB', @http.request(@uri).body
    assert_equal 1, ScriptedHTTP.connects, 'connection was reused'
  end

  def test_break_in_the_middle_of_the_body_closes_the_connection
    script self.class.chunked('T1AAA'), self.class.chunked('T2BBB')

    received = []
    @http.request @uri do |response|
      response.read_body do |chunk|
        received << chunk
        break
      end
    end

    assert_equal ['T1AA'], received
    assert_equal 1, ScriptedHTTP.finishes,
                 'partial body leaves an unknown socket position'

    assert_equal 'T2BBB', @http.request(@uri).body
    assert_equal 2, ScriptedHTTP.connects, 'a fresh connection was used'
  end

  def test_exception_in_the_middle_of_the_body_closes_the_connection
    script self.class.chunked('T1AAA'), self.class.chunked('T2BBB')

    error = assert_raises RuntimeError do
      @http.request @uri do |response|
        response.read_body { |chunk| raise 'download failed' }
      end
    end

    assert_equal 'download failed', error.message
    assert_equal 1, ScriptedHTTP.finishes
    assert_equal 'T2BBB', @http.request(@uri).body
    assert_equal 2, ScriptedHTTP.connects
  end

  def test_throw_in_the_middle_of_the_body_closes_the_connection
    script self.class.chunked('T1AAA'), self.class.chunked('T2BBB')

    catch :abort do
      @http.request @uri do |response|
        response.read_body { |chunk| throw :abort }
      end
    end

    assert_equal 1, ScriptedHTTP.finishes
    assert_equal 'T2BBB', @http.request(@uri).body
    assert_equal 2, ScriptedHTTP.connects
  end

  def test_thread_kill_in_the_middle_of_the_body_closes_the_connection
    script self.class.chunked('T1AAA'), self.class.chunked('T2BBB')

    entered = Queue.new

    thread = Thread.new do
      @http.request @uri do |response|
        response.read_body do |chunk|
          entered << true
          sleep
        end
      end
    end

    entered.pop
    thread.kill
    thread.join

    assert_equal 1, ScriptedHTTP.finishes,
                 'an aborted thread must not leak an unclean connection'

    assert_equal 'T2BBB', @http.request(@uri).body
    assert_equal 2, ScriptedHTTP.connects
  end

  def test_thread_raise_in_the_middle_of_the_body_closes_the_connection
    script self.class.chunked('T1AAA'), self.class.chunked('T2BBB')

    entered = Queue.new

    thread = Thread.new do
      @http.request @uri do |response|
        response.read_body do |chunk|
          entered << true
          sleep
        end
      end
    rescue RuntimeError
      # the interrupt requested below
    end

    entered.pop
    thread.raise RuntimeError, 'request timed out'
    thread.join

    assert_equal 1, ScriptedHTTP.finishes
    assert_equal 'T2BBB', @http.request(@uri).body
    assert_equal 2, ScriptedHTTP.connects
  end

  def test_break_with_a_destination_string_closes_the_connection
    script self.class.chunked('T1AAA'), self.class.chunked('T2BBB')

    received = +''
    @http.request @uri do |response|
      response.read_body do |chunk|
        received << chunk
        break
      end
    end

    assert_equal 'T1AA', received
    assert_equal 1, ScriptedHTTP.finishes
    assert_equal 'T2BBB', @http.request(@uri).body
  end

  def test_short_body_for_the_declared_content_length_closes_the_connection
    truncated = "HTTP/1.1 200 OK\r\n" \
                "Content-Length: 10\r\n" \
                "Connection: keep-alive\r\n\r\nT1"

    script truncated, self.class.fixed('T2BBB')

    @http.request @uri do |response|
      response.read_body { |chunk| }
    end

    assert_equal 1, ScriptedHTTP.finishes,
                 'a short read must not be handed to the next request'
    assert_equal 'T2BBB', @http.request(@uri).body
    assert_equal 2, ScriptedHTTP.connects
  end

  def test_complete_body_keeps_the_connection
    script self.class.chunked('T1AAA') + self.class.chunked('T2BBB')

    @http.request @uri do |response|
      response.read_body { |chunk| }
    end

    assert_equal 0, ScriptedHTTP.finishes
    assert_equal 'T2BBB', @http.request(@uri).body
    assert_equal 1, ScriptedHTTP.connects
  end

  def test_complete_body_with_a_destination_keeps_the_connection
    script self.class.chunked('T1AAA') + self.class.chunked('T2BBB')

    received = +''
    response = @http.request @uri do |response|
      response.read_body received
    end

    assert_same received, response.body
    assert_equal 'T1AAA', received
    assert_equal 0, ScriptedHTTP.finishes
    assert_equal 'T2BBB', @http.request(@uri).body
    assert_equal 1, ScriptedHTTP.connects
  end

  def test_head_request_with_a_block_keeps_the_connection
    head = "HTTP/1.1 200 OK\r\n" \
           "Content-Length: 5\r\n" \
           "Connection: keep-alive\r\n\r\n"

    script head + head

    @http.request @uri, Net::HTTP::Head.new(@uri.path) do |response|
      assert_equal '5', response['content-length']
    end

    assert_equal 0, ScriptedHTTP.finishes
    assert_equal 1, ScriptedHTTP.connects

    @http.request @uri, Net::HTTP::Head.new(@uri.path) { |response| }

    assert_equal 0, ScriptedHTTP.finishes
    assert_equal 1, ScriptedHTTP.connects
  end

  def test_read_body_called_twice_still_raises
    script self.class.chunked('T1AAA') + self.class.chunked('T2BBB')

    @http.request @uri do |response|
      response.read_body { |chunk| }

      assert_raises IOError do
        response.read_body { |chunk| }
      end
    end

    assert_equal 0, ScriptedHTTP.finishes
    assert_equal 'T2BBB', @http.request(@uri).body
  end

  def test_pool_returns_every_checked_out_connection
    script self.class.chunked('T1AAA'), self.class.chunked('T2BBB')

    begin
      @http.request @uri do |response|
        response.read_body { |chunk| raise 'download failed' }
      end
    rescue RuntimeError
    end

    assert_nil Thread.current[@http.pool.key], 'checkout stack must be empty'
    assert_equal 1, @http.pool.available.length

    @http.request @uri do |response|
      response.read_body { |chunk| }
    end

    assert_equal 1, @http.pool.available.length
    assert_nil Thread.current[@http.pool.key]
  end

end
