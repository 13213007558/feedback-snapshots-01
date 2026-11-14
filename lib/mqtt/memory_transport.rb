module MQTT
  # A small in-memory, full-duplex byte transport.
  #
  # It provides the subset of the IO API used by MQTT::Client, so that a
  # complete MQTT handshake can be exercised without a network or a server.
  # Each endpoint records the bytes it has written.
  class MemoryTransport
    # Create a connected pair of endpoints
    def self.pair
      to_server_read, from_client_write = IO.pipe
      from_server_read, to_client_write = IO.pipe

      client = new(to_server_read, to_client_write)
      server = new(from_server_read, from_client_write)
      [client, server]
    end

    # Bytes written by this endpoint
    attr_reader :written

    def initialize(read_io, write_io)
      @read_io = read_io
      @write_io = write_io
      @written = +''
      @written.force_encoding('ASCII-8BIT')
      @closed = false
    end

    # Write bytes to the peer endpoint
    def write(data)
      bytes = data.to_s.b
      @written << bytes
      @write_io.write(bytes)
      @write_io.flush
      bytes.bytesize
    rescue IOError
      raise IOError, 'closed stream'
    end

    # Read at most length bytes, blocking until they are available or the
    # peer is closed. Returns nil on end of stream.
    def read(length)
      @read_io.read(length)
    end

    # Read one byte as an Integer, or nil at end of stream
    def getbyte
      @read_io.getbyte
    end

    # Underlying IO, for IO.select
    def to_io
      @read_io
    end

    # Close this endpoint
    def close
      return nil if @closed

      @closed = true
      [@read_io, @write_io].each do |io|
        io.close unless io.closed?
      rescue IOError
        nil
      end
      nil
    end

    def closed?
      @closed || @read_io.closed?
    end

    def flush
      self
    end
  end
end
