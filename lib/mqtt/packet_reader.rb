# encoding: BINARY

module MQTT
  # Reads complete MQTT control packets from a socket, tolerating packets
  # that arrive split across several short reads.
  #
  # Two independent time limits stop a half-written packet from occupying
  # the client forever:
  #
  # * +read_idle_timeout+ limits the time allowed without any bytes arriving
  #   (reading-progress deadline). Bytes that keep arriving reset this limit,
  #   so a packet delivered as a trickle of short reads is still accepted.
  # * +packet_timeout+ limits the total time allowed to assemble one whole
  #   packet, from the first byte to the last (whole-packet deadline). This
  #   cannot be reset by more data trickling in.
  #
  # A limit being reached raises an MQTT::ProtocolException, which the client
  # treats like any other fatal read error: the socket is closed and any
  # waiting publishers are released with a failure.
  class PacketReader
    # Maximum time to block in IO.select on a single poll
    SELECT_TIMEOUT = 0.5

    # Maximum time (in seconds) to wait for the next byte of a packet
    attr_accessor :read_idle_timeout

    # Maximum time (in seconds) allowed to assemble a complete packet
    attr_accessor :packet_timeout

    # Create a new packet reader for a socket.
    #
    # An optional block can be supplied to control how the current time is
    # obtained, which is handy for tests that use a fake clock.
    def initialize(socket, read_idle_timeout: nil, packet_timeout: nil,
                   select_timeout: SELECT_TIMEOUT, &clock)
      @socket = socket
      @read_idle_timeout = read_idle_timeout
      @packet_timeout = packet_timeout
      @select_timeout = select_timeout
      @clock = block_given? ? clock : -> { current_time }
      @buffer = ''.b
      reset_deadlines
    end

    # Read and return one complete packet from the socket.
    #
    # Returns +nil+ if the socket is closed at a packet boundary, with no
    # partial packet left behind.
    def read
      loop do
        packet = try_parse
        return packet unless packet.nil?

        got_data, reached_eof = read_available

        if reached_eof && !got_data
          # The socket is closed and there is no buffered packet to return.
          # A partial packet left behind is a protocol violation.
          raise MQTT::ProtocolException, 'Failed to read byte from socket' unless @buffer.empty?

          return nil
        end

        # No bytes were available: block until data arrives or a deadline,
        # whichever comes first.
        wait_for_data unless got_data
        check_time_limits!
      end
    end

    # Discard any bytes belonging to a packet that was never completed.
    #
    # Called when the connection is torn down so that residual bytes can never
    # be stitched on to a packet read from a new connection.
    def reset
      @buffer = ''.b
      reset_deadlines
    end

    private

    if Process.const_defined? :CLOCK_MONOTONIC
      def current_time
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end
    else
      # Support older Ruby
      def current_time
        Time.now.to_f
      end
    end

    # Block until the socket is readable or the next timeout point is reached.
    def wait_for_data
      timeout = time_until_next_deadline
      timeout = [timeout, @select_timeout].min unless timeout.nil?
      IO.select([@socket], [], [], timeout)
    end

    # Read every byte currently available on the socket into the buffer.
    # Returns a pair: whether any bytes were read, and whether the stream
    # reached EOF during this call.
    def read_available
      got_data = false
      loop do
        chunk = @socket.read_nonblock(65_536, :exception => false)
        case chunk
        when nil
          return [got_data, true]
        when :wait_readable
          return [got_data, false]
        else
          got_data = true
          @buffer << chunk
          @last_read_at = now
          @packet_started_at ||= @last_read_at
        end
      end
    end

    # Raise if either of the two time limits has been exceeded.
    def check_time_limits!
      time = now
      unless @packet_timeout.nil? || @packet_started_at.nil?
        if time - @packet_started_at > @packet_timeout
          raise MQTT::ProtocolException,
                "Timed out waiting for a complete packet after #{@packet_timeout} seconds"
        end
      end

      return if @read_idle_timeout.nil? || @last_read_at.nil?

      return unless time - @last_read_at > @read_idle_timeout

      raise MQTT::ProtocolException,
            "Timed out waiting for packet data after #{@read_idle_timeout} seconds"
    end

    # Number of seconds until the closest outstanding deadline, or nil if
    # there is no deadline to wait against.
    def time_until_next_deadline
      deadlines = []
      deadlines << (@last_read_at + @read_idle_timeout) unless @read_idle_timeout.nil? || @last_read_at.nil?
      deadlines << (@packet_started_at + @packet_timeout) unless @packet_timeout.nil? || @packet_started_at.nil?
      return nil if deadlines.empty?

      remaining = deadlines.min - now
      remaining.negative? ? 0 : remaining
    end

    # Attempt to build a complete packet from the buffered bytes.
    # Returns nil when more data is needed.
    def try_parse
      return nil if @buffer.empty?

      packet, header_length, body_length = parse_header
      return nil if packet.nil?
      return nil if @buffer.bytesize < header_length + body_length

      body = @buffer.slice!(0, header_length + body_length)
      packet.parse_body(body.byteslice(header_length, body_length))
      reset_deadlines
      packet
    end

    # Parse the fixed header from the buffer without consuming the body.
    # Returns [packet, header_length, body_length], or nil if the header
    # itself is not fully buffered yet.
    def parse_header
      packet = MQTT::Packet.create_from_header(@buffer.getbyte(0))
      packet.validate_flags

      body_length = 0
      multiplier = 1
      pos = 1

      loop do
        return nil if @buffer.bytesize <= pos

        digit = @buffer.getbyte(pos)
        body_length += ((digit & 0x7F) * multiplier)
        multiplier *= 0x80
        pos += 1
        break if (digit & 0x80).zero? || pos > 4
      end

      packet.instance_variable_set('@body_length', body_length)
      [packet, pos, body_length]
    end

    def reset_deadlines
      @last_read_at = nil
      @packet_started_at = nil
    end

    def now
      @clock.call
    end
  end
end
