autoload :OpenSSL, 'openssl'
autoload :URI, 'uri'

require 'mqtt/client/packet_id_space'

# Client class for talking to an MQTT server
module MQTT
  class Client
    # Hostname of the remote server
    attr_accessor :host

    # Port number of the remote server
    attr_accessor :port

    # The version number of the MQTT protocol to use (default 3.1.1)
    attr_accessor :version

    # Set to true to enable SSL/TLS encrypted communication
    #
    # Set to a symbol to use a specific variant of SSL/TLS.
    # Allowed values include:
    #
    # @example Using TLS 1.0
    #    client = Client.new('mqtt.example.com', :ssl => :TLSv1)
    # @see OpenSSL::SSL::SSLContext::METHODS
    attr_accessor :ssl

    # Set to false to skip tls hostname verification
    attr_accessor :verify_host

    # Time (in seconds) between pings to remote server (default is 15 seconds)
    attr_accessor :keep_alive

    # Set the 'Clean Session' flag when connecting? (default is true)
    attr_accessor :clean_session

    # Client Identifier
    attr_accessor :client_id

    # Number of seconds to wait for acknowledgement packets (default is 5 seconds)
    attr_accessor :ack_timeout

    # Number of seconds to connect to the server (default is 90 seconds)
    attr_accessor :connect_timeout

    # Username to authenticate to the server with
    attr_accessor :username

    # Password to authenticate to the server with
    attr_accessor :password

    # The topic that the Will message is published to
    attr_accessor :will_topic

    # Contents of message that is sent by server when client disconnect
    attr_accessor :will_payload

    # The QoS level of the will message sent by the server
    attr_accessor :will_qos

    # If the Will message should be retain by the server after it is sent
    attr_accessor :will_retain

    # Last ping response time
    attr_reader :last_ping_response

    # The shared, ownership-tracked space of in-flight packet identifiers.
    # PUBLISH (QoS > 0), SUBSCRIBE and UNSUBSCRIBE all allocate from it.
    attr_reader :packet_id_space

    # Replace the identifier space. Intended for testing with a smaller
    # identifier range so wrap-around and exhaustion can be exercised quickly.
    attr_writer :packet_id_space

    # Timeout between select polls (in seconds)
    SELECT_TIMEOUT = 0.5

    # Acknowledgement packets that can complete an in-flight request.
    ACK_PACKET_CLASSES = [
      MQTT::Packet::Puback,
      MQTT::Packet::Suback,
      MQTT::Packet::Unsuback
    ].freeze

    # Default attribute values
    ATTR_DEFAULTS = {
      :host => nil,
      :port => nil,
      :version => '3.1.1',
      :keep_alive => 15,
      :clean_session => true,
      :client_id => nil,
      :ack_timeout => 5,
      :connect_timeout => 30,
      :username => nil,
      :password => nil,
      :will_topic => nil,
      :will_payload => nil,
      :will_qos => 0,
      :will_retain => false,
      :ssl => false,
      :verify_host => true
    }

    # Create and connect a new MQTT Client
    #
    # Accepts the same arguments as creating a new client.
    # If a block is given, then it will be executed before disconnecting again.
    #
    # Example:
    #  MQTT::Client.connect('myserver.example.com') do |client|
    #    # do stuff here
    #  end
    #
    def self.connect(*args, &block)
      client = MQTT::Client.new(*args)
      client.connect(&block)
      client
    end

    # Generate a random client identifier
    # (using the characters 0-9 and a-z)
    def self.generate_client_id(prefix = 'ruby', length = 16)
      str = prefix.dup
      length.times do
        num = rand(36)
        # Adjust based on number or letter.
        num += num < 10 ? 48 : 87
        str += num.chr
      end
      str
    end

    # Create a new MQTT Client instance
    #
    # Accepts one of the following:
    # - a URI that uses the MQTT scheme
    # - a hostname and port
    # - a Hash containing attributes to be set on the new instance
    #
    # If no arguments are given then the method will look for a URI
    # in the MQTT_SERVER environment variable.
    #
    # Examples:
    #  client = MQTT::Client.new
    #  client = MQTT::Client.new('mqtt://myserver.example.com')
    #  client = MQTT::Client.new('mqtt://user:pass@myserver.example.com')
    #  client = MQTT::Client.new('myserver.example.com')
    #  client = MQTT::Client.new('myserver.example.com', 18830)
    #  client = MQTT::Client.new(:host => 'myserver.example.com')
    #  client = MQTT::Client.new(:host => 'myserver.example.com', :keep_alive => 30)
    #
    def initialize(*args)
      attributes = args.last.is_a?(Hash) ? args.pop : {}

      # Set server URI from environment if present
      attributes.merge!(parse_uri(ENV['MQTT_SERVER'])) if args.length.zero? && ENV['MQTT_SERVER']

      if args.length >= 1
        case args[0]
        when URI
          attributes.merge!(parse_uri(args[0]))
        when %r{^mqtts?://}
          attributes.merge!(parse_uri(args[0]))
        else
          attributes[:host] = args[0]
        end
      end

      if args.length >= 2
        attributes[:port] = args[1] unless args[1].nil?
      end

      raise ArgumentError, 'Unsupported number of arguments' if args.length >= 3

      # Merge arguments with default values for attributes
      ATTR_DEFAULTS.merge(attributes).each_pair do |k, v|
        send("#{k}=", v)
      end

      # Set a default port number
      if @port.nil?
        @port = @ssl ? MQTT::DEFAULT_SSL_PORT : MQTT::DEFAULT_PORT
      end

      if @ssl
        require 'openssl'
        require 'mqtt/openssl_fix'
      end

      # Initialise private instance variables
      @last_ping_request = current_time
      @last_ping_response = current_time
      @socket = nil
      @read_queue = Queue.new
      @read_thread = nil
      @write_semaphore = Mutex.new
      @packet_id_space = PacketIdSpace.new
    end

    # Get the OpenSSL context, that is used if SSL/TLS is enabled
    def ssl_context
      @ssl_context ||= OpenSSL::SSL::SSLContext.new
    end

    # Set a path to a file containing a PEM-format client certificate
    def cert_file=(path)
      self.cert = File.read(path)
    end

    # PEM-format client certificate
    def cert=(cert)
      ssl_context.cert = OpenSSL::X509::Certificate.new(cert)
    end

    # Set a path to a file containing a PEM-format client private key
    def key_file=(*args)
      path, passphrase = args.flatten
      ssl_context.key = OpenSSL::PKey.read(File.binread(path), passphrase)
    end

    # Set to a PEM-format client private key
    def key=(*args)
      cert, passphrase = args.flatten
      ssl_context.key = OpenSSL::PKey.read(cert, passphrase)
    end

    # Set a path to a file containing a PEM-format CA certificate and enable peer verification
    def ca_file=(path)
      ssl_context.ca_file = path
      ssl_context.verify_mode = OpenSSL::SSL::VERIFY_PEER unless path.nil?
    end

    # Set the Will for the client
    #
    # The will is a message that will be delivered by the server when the client dies.
    # The Will must be set before establishing a connection to the server
    def set_will(topic, payload, retain = false, qos = 0)
      self.will_topic = topic
      self.will_payload = payload
      self.will_retain = retain
      self.will_qos = qos
    end

    # Connect to the MQTT server
    # If a block is given, then yield to that block and then disconnect again.
    def connect(clientid = nil)
      @client_id = clientid unless clientid.nil?

      if @client_id.nil? || @client_id.empty?
        raise 'Must provide a client_id if clean_session is set to false' unless @clean_session

        # Empty client id is not allowed for version 3.1.0
        @client_id = MQTT::Client.generate_client_id if @version == '3.1.0'
      end

      raise 'No MQTT server host set when attempting to connect' if @host.nil?

      unless connected?
        # Create network socket
        tcp_socket = open_tcp_socket

        if @ssl
          # Set the protocol version
          ssl_context.ssl_version = @ssl if @ssl.is_a?(Symbol)

          @socket = OpenSSL::SSL::SSLSocket.new(tcp_socket, ssl_context)
          @socket.sync_close = true

          # Set hostname on secure socket for Server Name Indication (SNI)
          @socket.hostname = @host if @socket.respond_to?(:hostname=)

          @socket.connect

          @socket.post_connection_check(@host) if @verify_host
        else
          @socket = tcp_socket
        end

        # Construct a connect packet
        packet = MQTT::Packet::Connect.new(
          :version => @version,
          :clean_session => @clean_session,
          :keep_alive => @keep_alive,
          :client_id => @client_id,
          :username => @username,
          :password => @password,
          :will_topic => @will_topic,
          :will_payload => @will_payload,
          :will_qos => @will_qos,
          :will_retain => @will_retain
        )

        # Send packet
        send_packet(packet)

        # Receive response
        receive_connack

        # Every connection gets a fresh identifier generation: identifiers
        # (and late acknowledgements) from the previous connection are invalid.
        @packet_id_space.reset

        # Start packet reading thread
        @read_thread = Thread.new(Thread.current) do |parent|
          Thread.current[:parent] = parent
          receive_packet while connected?
        end
      end

      return unless block_given?

      # If a block is given, then yield and disconnect
      begin
        yield(self)
      ensure
        disconnect
      end
    end

    # Disconnect from the MQTT server.
    # If you don't want to say goodbye to the server, set send_msg to false.
    def disconnect(send_msg = true)
      # Stop reading packets from the socket first
      @read_thread.kill if @read_thread && @read_thread.alive?
      @read_thread = nil

      return unless connected?

      # Close the socket if it is open
      if send_msg
        packet = MQTT::Packet::Disconnect.new
        send_packet(packet)
      end
      @socket.close unless @socket.nil?
      handle_close
      @socket = nil
    end

    # Checks whether the client is connected to the server.
    def connected?
      !@socket.nil? && !@socket.closed?
    end

    # Publish a message on a particular topic to the MQTT server.
    def publish(topic, payload = '', retain = false, qos = 0)
      raise ArgumentError, 'Topic name cannot be nil' if topic.nil?
      raise ArgumentError, 'Topic name cannot be empty' if topic.empty?

      # QoS 0 messages are not acknowledged and never own an identifier.
      if qos.zero?
        packet = MQTT::Packet::Publish.new(
          :id => 0,
          :qos => qos,
          :retain => retain,
          :topic => topic,
          :payload => payload
        )
        return send_packet(packet)
      end

      # Reserve the identifier before constructing the packet so that an
      # exhausted space raises instead of reusing an in-flight identifier.
      id, entry = @packet_id_space.reserve(:publish)
      packet = MQTT::Packet::Publish.new(
        :id => id,
        :qos => qos,
        :retain => retain,
        :topic => topic,
        :payload => payload
      )

      begin
        result = send_packet(packet)
      rescue ::Exception
        # The packet never left (or may not have left): free the identifier
        # so it is reusable instead of leaking it for the whole timeout.
        @packet_id_space.release(id)
        raise
      end

      wait_for_ack(id, entry) ? result : -1
    end

    # Send a subscribe message for one or more topics on the MQTT server.
    # The topics parameter should be one of the following:
    # * String: subscribe to one topic with QoS 0
    # * Array: subscribe to multiple topics with QoS 0
    # * Hash: subscribe to multiple topics where the key is the topic and the value is the QoS level
    #
    # For example:
    #   client.subscribe( 'a/b' )
    #   client.subscribe( 'a/b', 'c/d' )
    #   client.subscribe( ['a/b',0], ['c/d',1] )
    #   client.subscribe( 'a/b' => 0, 'c/d' => 1 )
    #
    def subscribe(*topics)
      id, entry = @packet_id_space.reserve(:subscribe)
      packet = MQTT::Packet::Subscribe.new(
        :id => id,
        :topics => topics
      )
      send_packet_and_wait(packet, id, entry)
    end

    # Return the next message received from the MQTT server.
    # An optional topic can be given to subscribe to.
    #
    # The method either returns the topic and message as an array:
    #   topic,message = client.get
    #
    # Or can be used with a block to keep processing messages:
    #   client.get('test') do |topic,payload|
    #     # Do stuff here
    #   end
    #
    def get(topic = nil, options = {})
      if block_given?
        get_packet(topic) do |packet|
          yield(packet.topic, packet.payload) unless packet.retain && options[:omit_retained]
        end
      else
        loop do
          # Wait for one packet to be available
          packet = get_packet(topic)
          return packet.topic, packet.payload unless packet.retain && options[:omit_retained]
        end
      end
    end

    # Return the next packet object received from the MQTT server.
    # An optional topic can be given to subscribe to.
    #
    # The method either returns a single packet:
    #   packet = client.get_packet
    #   puts packet.topic
    #
    # Or can be used with a block to keep processing messages:
    #   client.get_packet('test') do |packet|
    #     # Do stuff here
    #     puts packet.topic
    #   end
    #
    def get_packet(topic = nil)
      # Subscribe to a topic, if an argument is given
      subscribe(topic) unless topic.nil?

      if block_given?
        # Loop forever!
        loop do
          packet = @read_queue.pop
          yield(packet)
          puback_packet(packet) if packet.qos > 0
        end
      else
        # Wait for one packet to be available
        packet = @read_queue.pop
        puback_packet(packet) if packet.qos > 0
        return packet
      end
    end

    # Returns true if the incoming message queue is empty.
    def queue_empty?
      @read_queue.empty?
    end

    # Returns the length of the incoming message queue.
    def queue_length
      @read_queue.length
    end

    # Clear the incoming message queue.
    def clear_queue
      @read_queue.clear
    end

    # Send a unsubscribe message for one or more topics on the MQTT server
    def unsubscribe(*topics)
      topics = topics.first if topics.is_a?(Enumerable) && topics.count == 1

      id, entry = @packet_id_space.reserve(:unsubscribe)
      packet = MQTT::Packet::Unsubscribe.new(
        :topics => topics,
        :id => id
      )
      send_packet_and_wait(packet, id, entry)
    end

    private

    # Try to read a packet from the server
    # Also sends keep-alive ping packets.
    def receive_packet
      # Poll socket - is there data waiting?
      result = IO.select([@socket], [], [], SELECT_TIMEOUT)
      unless result.nil?
        # Yes - read in the packet
        packet = MQTT::Packet.read(@socket)
        handle_packet packet
      end
      keep_alive!
    # Pass exceptions up to parent thread
    rescue ::Exception => exp
      unless @socket.nil?
        @socket.close
        @socket = nil
        handle_close
      end
      Thread.current[:parent].raise(exp)
    end

    # Send a packet that owns an identifier, then wait for its acknowledgement.
    # The identifier is released back to the pool if the write fails so it can
    # never become unallocatable.
    def send_packet_and_wait(packet, id, entry)
      begin
        send_packet(packet)
      rescue ::Exception
        @packet_id_space.release(id)
        raise
      end
      wait_for_ack(id, entry)
    end

    # Block on an in-flight entry until its acknowledgement arrives or the
    # acknowledgement timeout elapses. A connection close is delivered as a
    # :close event. Timeout and close release the identifier back to the pool;
    # a matching acknowledgement returns true, any other outcome returns false.
    def wait_for_ack(id, entry)
      deadline = current_time + @ack_timeout

      loop do
        remaining = deadline - current_time
        return fail_ack(id) if remaining <= 0

        response = pop_with_timeout(entry.queue, remaining)

        if response.nil? || response == :timed_out
          # The acknowledgement deadline was reached before any event arrived.
          return fail_ack(id)
        elsif response == :close
          # handle_close already released every identifier.
          return false
        else
          return true
        end
      end
    end

    if Queue.instance_method(:pop).parameters.include?([:key, :timeout])
      # Ruby 4+ takes the timeout as a keyword and returns nil (or raises
      # ThreadError) when the deadline passes with nothing in the queue.
      def pop_with_timeout(queue, seconds)
        queue.pop(:timeout => seconds)
      rescue ThreadError
        :timed_out
      end
    else
      # Older Rubies take the timeout positionally and return nil on expiry.
      def pop_with_timeout(queue, seconds)
        queue.pop(seconds) || :timed_out
      end
    end

    # Release an identifier whose acknowledgement never arrived and report the
    # request as failed rather than successful.
    def fail_ack(id)
      @packet_id_space.release(id)
      false
    end

    def handle_packet(packet)
      if packet.class == MQTT::Packet::Publish
        # Add to queue
        @read_queue.push(packet)
      elsif packet.class == MQTT::Packet::Pingresp
        @last_ping_response = current_time
      elsif ACK_PACKET_CLASSES.include?(packet.class)
        # Only a packet whose identifier, operation and connection match the
        # current owner completes its wait; anything else is discarded.
        @packet_id_space.acknowledge(packet)
      end
      # Ignore all other packets
      # FIXME: implement responses for QoS  2
    end

    def handle_close
      @packet_id_space.fail_all(:close)
    end

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

    def keep_alive!
      return unless @keep_alive > 0 && connected?

      response_timeout = (@keep_alive * 1.5).ceil
      if current_time >= @last_ping_request + @keep_alive
        packet = MQTT::Packet::Pingreq.new
        send_packet(packet)
        @last_ping_request = current_time
      elsif current_time > @last_ping_response + response_timeout
        raise MQTT::ProtocolException, "No Ping Response received for #{response_timeout} seconds"
      end
    end

    def puback_packet(packet)
      send_packet(MQTT::Packet::Puback.new(:id => packet.id))
    end

    # Read and check a connection acknowledgement packet
    def receive_connack
      Timeout.timeout(@ack_timeout) do
        packet = MQTT::Packet.read(@socket)
        if packet.class != MQTT::Packet::Connack
          raise MQTT::ProtocolException, "Response wasn't a connection acknowledgement: #{packet.class}"
        end

        # Check the return code
        if packet.return_code != 0x00
          # 3.2.2.3 If a server sends a CONNACK packet containing a non-zero
          # return code it MUST then close the Network Connection
          @socket.close
          raise MQTT::ProtocolException, packet.return_msg
        end
      end
    end

    # Send a packet to server
    def send_packet(data)
      # Raise exception if we aren't connected
      raise MQTT::NotConnectedException unless connected?

      # Only allow one thread to write to socket at a time
      @write_semaphore.synchronize do
        @socket.write(data.to_s)
      end
    end

    def parse_uri(uri)
      uri = URI.parse(uri) unless uri.is_a?(URI)
      if uri.scheme == 'mqtt'
        ssl = false
      elsif uri.scheme == 'mqtts'
        ssl = true
      else
        raise 'Only the mqtt:// and mqtts:// schemes are supported'
      end

      {
        :host => uri.host,
        :port => uri.port || nil,
        :username => uri.user ? URI::DEFAULT_PARSER.unescape(uri.user) : nil,
        :password => uri.password ? URI::DEFAULT_PARSER.unescape(uri.password) : nil,
        :ssl => ssl
      }
    end

    def open_tcp_socket
      return TCPSocket.new @host, @port, connect_timeout: @connect_timeout if RUBY_VERSION.to_f >= 3.0

      begin
        Timeout.timeout(@connect_timeout) do
          return TCPSocket.new(@host, @port)
        end
      rescue Timeout::Error
        raise IO::TimeoutError, "Connection timed out for \"#{@host}\" port #{@port}" if defined? IO::TimeoutError
        raise Errno::ETIMEDOUT, "Connection timed out for \"#{@host}\" port #{@port}"
      end
    end

    # ---- Deprecated attributes and methods  ---- #
    public

    # @deprecated Please use {#host} instead
    def remote_host
      host
    end

    # @deprecated Please use {#host=} instead
    def remote_host=(args)
      self.host = args
    end

    # @deprecated Please use {#port} instead
    def remote_port
      port
    end

    # @deprecated Please use {#port=} instead
    def remote_port=(args)
      self.port = args
    end
  end
end
