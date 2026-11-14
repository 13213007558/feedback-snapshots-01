autoload :OpenSSL, 'openssl'
autoload :URI, 'uri'

# Client class for talking to an MQTT server
module MQTT
  class Client
    # The network endpoint that a local MQTT session belongs to.
    #
    # Broker identities are part of the session boundary because the same
    # client identifier used against a different broker is a different session.
    BrokerIdentity = Struct.new(:host, :port, :ssl) do
      def to_s
        "#{ssl ? 'mqtts' : 'mqtt'}://#{host}:#{port}"
      end
    end

    # The complete boundary for locally held session state.
    #
    # A change to any of these values makes previously held local state
    # unusable for the new connection, even if the broker reports that it
    # resumed a session for the same client identifier.
    SessionIdentity = Struct.new(:broker, :client_id, :clean_session) do
      def to_s
        "#{broker} client_id=#{client_id.inspect} clean_session=#{clean_session}"
      end
    end
    SessionBoundary = SessionIdentity

    # The explicit result of establishing a new connection.
    #
    # It reports what the broker did with the session (Session Present) and
    # whether local state from a previous connection had to be discarded.
    class SessionRecovery
      # Broker endpoint used for this connection attempt
      attr_reader :broker

      # Client identifier used for the CONNECT packet
      attr_reader :client_id

      # Value of the Clean Session flag sent in the CONNECT packet
      attr_reader :clean_session

      # True if the broker resumed an existing session
      attr_reader :session_present

      # Local session boundary used for this attempt
      attr_reader :identity

      # Local session boundary from the previous connection (if any)
      attr_reader :previous_identity

      # True if local transient state was discarded for this attempt
      attr_reader :local_state_discarded

      # True if local transient state was kept for this attempt
      attr_reader :local_state_reused

      def initialize(identity, previous_identity, session_present, local_state_discarded, local_state_reused = false)
        @identity = identity
        @broker = identity.broker
        @client_id = identity.client_id
        @clean_session = identity.clean_session
        @previous_identity = previous_identity
        @session_present = session_present ? true : false
        @local_state_discarded = local_state_discarded ? true : false
        @local_state_reused = local_state_reused ? true : false
      end

      # Hostname of the broker
      def host
        @broker.host
      end

      # Port number of the broker
      def port
        @broker.port
      end

      # True if TLS/SSL was enabled for the broker connection
      def ssl
        @broker.ssl
      end

      # True if the broker restored a stored session
      def resumed?
        @session_present
      end
      alias broker_resumed_session? resumed?
      alias resumed_session? resumed?
      alias session_present? resumed?

      # True if the broker created a new session
      def new_session?
        !@session_present
      end
      alias broker_created_new_session? new_session?
      alias created_new_session? new_session?

      # Machine readable session recovery outcome
      def status
        resumed? ? :resumed : :new_session
      end
      alias result status

      def to_sym
        status
      end

      # True when the broker target, client identifier or clean session
      # setting differs from the previous local session.
      def identity_changed?
        !@previous_identity.nil? && @previous_identity != @identity
      end
      alias boundary_changed? identity_changed?

      # True if this result is for the first connection made by this client
      def first_connection?
        @previous_identity.nil?
      end

      # True if queued messages from the previous connection were discarded
      def local_state_discarded?
        @local_state_discarded
      end
      alias queued_messages_discarded? local_state_discarded?

      # True if queued messages from the previous connection were kept
      def local_state_reused?
        @local_state_reused
      end
      alias queued_messages_reused? local_state_reused?

      # True if a QoS 1 publish still waiting for its PUBACK must not expect
      # the acknowledgement to complete after this recovery.
      def pending_acknowledgements_lost?
        @pending_acknowledgements_lost
      end

      def pending_acknowledgements_lost=(value)
        @pending_acknowledgements_lost = value ? true : false
      end

      # Packet ids of operations from previous connections that must never
      # complete a future publish.
      def abandoned_puback_ids
        @abandoned_puback_ids.dup
      end

      def abandoned_puback_ids=(ids)
        @abandoned_puback_ids = ids.dup
      end

      # Human readable summary of what happened to local state.
      def recovery
        return :fresh if first_connection?

        if identity_changed?
          :target_changed
        elsif !@session_present
          :session_lost
        elsif pending_acknowledgements_lost?
          :reconnected
        else
          :resumed
        end
      end

      # Allow the result to be read like the hash used by older callers.
      def [](key)
        to_h[key.to_sym]
      end

      def to_h
        {
          :status => status,
          :result => result,
          :recovery => recovery,
          :session_present => @session_present,
          :resumed => resumed?,
          :new_session => new_session?,
          :broker => @broker,
          :host => host,
          :port => port,
          :ssl => ssl,
          :client_id => @client_id,
          :clean_session => @clean_session,
          :identity => @identity,
          :previous_identity => @previous_identity,
          :identity_changed => identity_changed?,
          :first_connection => first_connection?,
          :local_state_discarded => local_state_discarded?,
          :local_state_reused => local_state_reused?,
          :pending_acknowledgements_lost => pending_acknowledgements_lost?,
          :abandoned_puback_ids => abandoned_puback_ids
        }
      end
      alias to_hash to_h

      def to_s
        "#<#{self.class}: #{status}, identity=#{@identity.inspect}, " \
          "identity_changed=#{identity_changed?}, " \
          "local_state_discarded=#{local_state_discarded?}>"
      end
    end

    # Alias for callers that prefer an explicit result class name
    SessionResult = SessionRecovery

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

    # Result of the most recent connection attempt
    attr_reader :last_session_result

    # Timeout between select polls (in seconds)
    SELECT_TIMEOUT = 0.5

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
      @pubacks = {}
      @read_thread = nil
      @write_semaphore = Mutex.new
      @pubacks_semaphore = Mutex.new
      @session_semaphore = Mutex.new
      @subscribed_topics = {}
      @abandoned_puback_ids = {}
      @inflight_puback_ids = {}
      @lost_pubacks_since_connect = false
      @session_identity = nil
      @session_epoch = 0
      @last_session_result = nil
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
    #
    # A successful call returns a {SessionRecovery} result describing whether
    # the broker resumed the previous session or created a new one, and what
    # happened to locally held session state.
    #
    # If a block is given, then yield to that block and then disconnect again.
    # The result is also available from {#last_session_result}.
    def connect(clientid = nil)
      @client_id = clientid unless clientid.nil?

      if @client_id.nil? || @client_id.empty?
        raise 'Must provide a client_id if clean_session is set to false' unless @clean_session

        # Empty client id is not allowed for version 3.1.0
        @client_id = MQTT::Client.generate_client_id if @version == '3.1.0'
      end

      raise 'No MQTT server host set when attempting to connect' if @host.nil?

      unless connected?
        identity = current_session_boundary
        # A failed attempt must not leave the previous recovery result
        # looking like the outcome of this connection.
        @last_session_result = nil

        begin
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

          # Receive response and validate the Session Present combination
          connack = receive_connack
          session_present = connack.respond_to?(:session_present) ? connack.session_present : false

          # Decide what can be kept from the previous local session before
          # accepting any packets from this connection.
          result = establish_session(identity, session_present)
          @last_session_result = result

          # Start packet reading thread
          epoch = @session_epoch
          @read_thread = Thread.new(Thread.current) do |parent|
            Thread.current[:parent] = parent
            receive_packet(epoch) while connected? && epoch == @session_epoch
          end
        rescue ::Exception
          # Never leave a half-open socket or a stale open connection behind.
          begin
            @socket.close if !@socket.nil? && !@socket.closed?
          rescue StandardError
            nil
          end
          @socket = nil
          raise
        end
      end

      return @last_session_result unless block_given?

      # If a block is given, then yield and disconnect
      begin
        yield(self)
      ensure
        disconnect
      end

      @last_session_result
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

    # The identity used for the most recent successful connection.
    #
    # Returns nil if the client has not connected yet.
    def session_identity
      @session_identity
    end
    alias session_boundary session_identity

    # True if the broker reported that it resumed an existing session for the
    # most recent successful connection.
    def session_present?
      !@last_session_result.nil? && @last_session_result.resumed?
    end

    # The topic filters this client wants to be subscribed to.
    #
    # This is retained across reconnections so that {#resubscribe} can
    # re-establish them after the broker has created a new session.
    def subscriptions
      @subscribed_topics.dup
    end
    alias subscribed_topics subscriptions

    # Re-send SUBSCRIBE packets for all known topic filters.
    #
    # This should be called by the application when the broker reports that
    # a new session was created (Session Present is 0). Subscriptions are
    # bound to the broker session, so they must not be assumed to still exist
    # after the previous session has been lost.
    def resubscribe
      return nil if @subscribed_topics.empty?

      subscribe(@subscribed_topics)
    end

    # Publish a message on a particular topic to the MQTT server.
    def publish(topic, payload = '', retain = false, qos = 0)
      raise ArgumentError, 'Topic name cannot be nil' if topic.nil?
      raise ArgumentError, 'Topic name cannot be empty' if topic.empty?

      packet = MQTT::Packet::Publish.new(
        :id => next_packet_id,
        :qos => qos,
        :retain => retain,
        :topic => topic,
        :payload => payload
      )

      queue = qos.zero? ? nil : wait_for_puback(packet.id)

      begin
        res = send_packet(packet)
        @pubacks_semaphore.synchronize { @inflight_puback_ids[packet.id] = true } if queue
      rescue ::Exception
        @pubacks_semaphore.synchronize do
          @pubacks.delete(packet.id)
          @inflight_puback_ids.delete(packet.id)
        end
        raise
      end

      return unless queue

      deadline = current_time + @ack_timeout

      loop do
        response = queue.pop
        case response
        when :read_timeout
          if current_time > deadline
            @pubacks_semaphore.synchronize do
              @pubacks.delete(packet.id)
              @inflight_puback_ids.delete(packet.id)
              @abandoned_puback_ids[packet.id] = true
            end
            return -1
          end
        when :close, :session_lost
          # The connection (and possibly the whole session) is gone, so the
          # pending acknowledgement must not be completed by later traffic.
          # Remember the id: a delayed acknowledgement for it must never be
          # matched with a future operation that happens to reuse the id.
          @pubacks_semaphore.synchronize do
            already_retired = @abandoned_puback_ids.key?(packet.id)
            @pubacks.delete(packet.id)
            @inflight_puback_ids.delete(packet.id)
            @abandoned_puback_ids[packet.id] = true
            # establish_session may have already reported this operation as
            # lost; do not count it again on the next reconnection.
            @lost_pubacks_since_connect = true unless already_retired
          end
          return -1
        else
          @pubacks_semaphore.synchronize do
            @pubacks.delete(packet.id)
            @inflight_puback_ids.delete(packet.id)
          end
          break
        end
      end

      res
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
      packet = MQTT::Packet::Subscribe.new(
        :id => next_packet_id,
        :topics => topics
      )

      result = send_packet(packet)

      # Remember the filters and requested QoS once they have been sent, so
      # that they can be re-established if the broker creates a new session.
      packet.topics.each do |topic, qos|
        @subscribed_topics[topic] = qos
      end

      result
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

      packet = MQTT::Packet::Unsubscribe.new(
        :topics => topics,
        :id => next_packet_id
      )
      result = send_packet(packet)

      packet.topics.each { |topic| @subscribed_topics.delete(topic) }

      result
    end

    private

    # Try to read a packet from the server
    # Also sends keep-alive ping packets.
    def receive_packet(epoch = @session_epoch)
      # A reader belonging to a previous connection must not touch the
      # socket of the current session.
      return if epoch != @session_epoch

      socket = @socket
      return if socket.nil?

      # Poll socket - is there data waiting?
      result = IO.select([socket], [], [], SELECT_TIMEOUT)
      handle_timeouts if epoch == @session_epoch
      unless result.nil?
        # Yes - read in the packet
        packet = MQTT::Packet.read(socket)
        handle_packet packet, epoch
      end
      keep_alive! if epoch == @session_epoch
    # Pass exceptions up to parent thread
    rescue ::Exception => exp
      if epoch == @session_epoch && !@socket.nil?
        @socket.close
        @socket = nil
        handle_close
        Thread.current[:parent].raise(exp)
      end
    end

    def wait_for_puback(id)
      queue = Queue.new
      @pubacks_semaphore.synchronize do
        @pubacks[id] = { :queue => queue, :epoch => @session_epoch }
      end
      queue
    end

    def handle_packet(packet, epoch = @session_epoch)
      if packet.class == MQTT::Packet::Publish
        @session_semaphore.synchronize do
          # Re-check under the same lock used when a session is replaced:
          # a reader from a previous connection must never enqueue into the
          # new session even if it raced with establish_session.
          return if epoch != @session_epoch

          @read_queue.push(packet)
        end
      elsif packet.class == MQTT::Packet::Pingresp
        @last_ping_response = current_time
      elsif packet.class == MQTT::Packet::Puback
        @pubacks_semaphore.synchronize do
          # An acknowledgement for an operation from an earlier connection
          # is never allowed to complete anything on this connection, and its
          # identifier stays reserved so a future publish cannot reuse it.
          return if @abandoned_puback_ids.key?(packet.id)

          waiter = @pubacks[packet.id]
          waiter[:queue] << packet if waiter && waiter[:epoch] == @session_epoch
        end
      end
      # Ignore all other packets
      # FIXME: implement responses for QoS  2
    end

    def handle_timeouts
      @pubacks_semaphore.synchronize do
        @pubacks.each_value { |waiter| waiter[:queue] << :read_timeout }
      end
    end

    def handle_close
      @pubacks_semaphore.synchronize do
        @pubacks.each_value { |waiter| waiter[:queue] << :close }
      end
    end

    # Set up the local state for a newly established connection.
    #
    # The broker's Session Present flag is only trusted as far as the local
    # session boundary allows: it can never cause messages or acknowledgements
    # from another broker, client identifier or connection mode to be reused.
    def establish_session(identity, session_present)
      @session_semaphore.synchronize do
        previous_identity = @session_identity
        identity_changed = !previous_identity.nil? && previous_identity != identity

        # Local queued messages can only belong to this exact session if the
        # broker actually resumed it and the boundary has not changed.
        reusable = !previous_identity.nil? && !identity_changed &&
                   !identity.clean_session && session_present

        # Invalidate readers and pending operations before touching the queues,
        # so that nothing from the previous connection can leak into the new
        # session while it is being set up.
        @session_epoch += 1

        # A network reconnect always breaks the request/response relationship
        # for in-flight QoS 1 publishes: a broker may resend its PUBACK on a
        # resumed connection, but it is not proof that the new operation was
        # accepted. Retire the packet ids of every operation that was sent but
        # never acknowledged, so an old acknowledgement cannot be matched to a
        # later publish that reuses the same id.
        pending_replies = 0
        @pubacks_semaphore.synchronize do
          pending_replies = @inflight_puback_ids.size
          (@inflight_puback_ids.keys | @pubacks.keys).each do |id|
            @abandoned_puback_ids[id] = true
          end
          @pubacks.each_value { |waiter| waiter[:queue] << :session_lost }
          @pubacks.clear
          @inflight_puback_ids.clear
          pending_replies = 1 if @lost_pubacks_since_connect
          @lost_pubacks_since_connect = false
        end

        # Messages queued for an old session must not be handed to the caller
        # as if they arrived on the current connection.
        discarded_messages = false
        unless reusable
          discarded_messages = !@read_queue.empty?
          @read_queue.clear
        end

        @session_identity = identity

        result = SessionRecovery.new(
          identity,
          previous_identity,
          session_present,
          discarded_messages,
          reusable
        )
        result.pending_acknowledgements_lost = pending_replies > 0
        result.abandoned_puback_ids = @abandoned_puback_ids.keys
        result
      end
    end

    def current_session_boundary
      SessionIdentity.new(
        BrokerIdentity.new(@host, @port, @ssl ? true : false),
        @client_id,
        @clean_session ? true : false
      )
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
    #
    # Validates the Session Present flag against the Clean Session flag that
    # was sent in the CONNECT packet:
    # * Clean Session 1 must always be answered with Session Present 0.
    # * Session Present 1 is only meaningful when Clean Session is 0.
    # * Protocol version 3.1.0 has no Session Present flag, so the reserved
    #   bit must be 0.
    #
    # Returns the Connack packet on success.
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
          if packet.session_present
            raise MQTT::ProtocolException,
                  "#{packet.return_msg} (Session Present must be 0 for a refused connection)"
          end
          raise MQTT::ProtocolException, packet.return_msg
        end

        validate_session_present(packet)
        packet
      end
    end

    # Check that the Session Present flag is consistent with the connection
    # request and the protocol version.
    def validate_session_present(packet)
      return unless packet.session_present

      if @version == '3.1.0'
        @socket.close
        raise MQTT::ProtocolException, 'Session Present flag set in MQTT 3.1.0 CONNACK'
      end

      return unless @clean_session

      @socket.close
      raise MQTT::ProtocolException, 'Session Present flag set when Clean Session was requested'
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

    def next_packet_id
      @pubacks_semaphore.synchronize do
        # All 16-bit ids cannot be abandoned at once; if that ever happens,
        # the oldest reservations are no longer meaningful and are dropped.
        @abandoned_puback_ids.clear if @abandoned_puback_ids.size >= 0xffff

        begin
          @last_packet_id = (@last_packet_id || 0).next
          @last_packet_id = 1 if @last_packet_id > 0xffff
        end while @abandoned_puback_ids.key?(@last_packet_id) ||
                    @pubacks.key?(@last_packet_id)

        @last_packet_id
      end
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
