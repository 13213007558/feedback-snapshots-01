module MQTT
  # Class for implementing a proxy to filter/mangle MQTT packets.
  class Proxy
    # Raised when a filtered packet cannot be forwarded without losing the
    # relationship between a PUBLISH packet and its acknowledgements.
    class RewriteError < MQTT::Exception
    end

    # Raised when a filter attempts to make a rewrite that the proxy cannot
    # keep consistent for both ends of the connection.
    class InvalidRewrite < RewriteError
    end

    # Tracks the QoS flows for a single client connection.
    #
    # A filter is allowed to change the topic of a PUBLISH packet and, for
    # QoS 1 and QoS 2, its packet identifier. This class remembers the
    # identifier that each side used so that PUBACK, PUBREC, PUBREL and
    # PUBCOMP packets can be translated on the way back. The state is never
    # shared between connections.
    class Session
      # Direction of a packet, relative to the proxy.
      CLIENT_TO_SERVER = :client_to_server
      SERVER_TO_CLIENT = :server_to_client

      # All the directions that are tracked.
      DIRECTIONS = [CLIENT_TO_SERVER, SERVER_TO_CLIENT].freeze

      # Packet types that belong to the QoS acknowledgement handshakes.
      FLOW_CONTROL_TYPES = [
        MQTT::Packet::Puback,
        MQTT::Packet::Pubrec,
        MQTT::Packet::Pubrel,
        MQTT::Packet::Pubcomp
      ].freeze

      # Keep enough completed flows to translate delayed duplicate
      # acknowledgements, without growing without bound on a long connection.
      MAX_RETIRED_FLOWS = 1024

      # State kept for one PUBLISH packet while it is in flight.
      class Flow
        attr_reader :direction, :source_id, :destination_id, :qos
        attr_reader :source_topic, :source_payload, :transformed
        attr_accessor :state

        def initialize(direction, source_packet, destination_packet, transformed)
          @direction = direction
          @source_id = source_packet.id
          @destination_id = destination_packet.id
          @qos = source_packet.qos
          @source_topic = source_packet.topic
          @source_payload = source_packet.payload
          @transformed = transformed
          @state = @qos == 1 ? :wait_puback : :wait_pubrec
        end

        # True until the final acknowledgement has passed through the proxy.
        def active?
          @state != :complete
        end
      end

      # Create the state for one connection. The state is reset by creating a
      # new Session, which is what the proxy does for every accepted socket.
      def initialize(logger = nil)
        @logger = logger
        reset
      end

      # Process one packet as it arrives from a socket.
      #
      # Returns the packet that should be written to the other socket, or nil
      # if the packet should be dropped. Raises InvalidRewrite if forwarding
      # the filtered packet would make the two sides disagree about the
      # meaning of a packet identifier.
      def handle(direction, packet, filter = nil)
        unless DIRECTIONS.include?(direction)
          raise ArgumentError, "Unknown proxy direction: #{direction.inspect}"
        end

        if packet.is_a?(MQTT::Packet::Publish)
          handle_publish(direction, packet, filter)
        elsif FLOW_CONTROL_TYPES.include?(packet.class)
          handle_flow_control(direction, packet, filter)
        else
          filtered = apply_filter(packet, filter)
          if filtered && ((filtered.is_a?(MQTT::Packet::Publish)) ||
                          FLOW_CONTROL_TYPES.include?(filtered.class))
            raise InvalidRewrite,
                  "filter changed #{packet.type_name} into #{filtered.type_name}, which cannot be correlated"
          end
          reset if filtered && direction == CLIENT_TO_SERVER && filtered.is_a?(MQTT::Packet::Disconnect)
          filtered
        end
      end

      # Forget all packet identifier mappings for this connection.
      def reset
        @active = new_tables
        @retired = new_tables
      end

      protected

      def snapshot(packet)
        MQTT::Packet.parse(packet.to_s)
      end

      def apply_filter(packet, filter)
        return packet if filter.nil?

        filtered = filter.call(packet)
        return nil if filtered.nil?
        return filtered if filtered.is_a?(MQTT::Packet)

        raise InvalidRewrite,
              "filter returned #{filtered.class}, expected MQTT::Packet or nil"
      end

      def handle_publish(direction, packet, filter)
        if packet.qos.zero?
          original = snapshot(packet)
          filtered = apply_filter(packet, filter)
          return nil if filtered.nil?
          validate_publish(original, filtered)
          return filtered
        end

        if packet.duplicate
          flow = find_by_source(direction, packet.id)
          if flow
            validate_retransmission(packet, flow)
            return retransmit(flow)
          end

          # A DUP packet whose original rewrite is not in this session may
          # only pass through unchanged. Rewriting it would invent a new
          # identifier for a packet the other side may already have seen.
          original = snapshot(packet)
          filtered = apply_filter(packet, filter)
          return nil if filtered.nil?
          validate_publish(original, filtered)
          unless filtered.id == original.id
            raise InvalidRewrite,
                  "cannot rewrite retransmitted PUBLISH identifier #{packet.id} without a matching flow"
          end
          return register_flow(direction, original, filtered)
        elsif find_active_by_source(direction, packet.id)
          raise InvalidRewrite, "PUBLISH packet identifier #{packet.id} is already in use"
        end

        original = snapshot(packet)
        filtered = apply_filter(packet, filter)
        return nil if filtered.nil?
        validate_publish(original, filtered)
        register_flow(direction, original, filtered)
      end

      def register_flow(direction, source, destination)
        source_id = source.id
        destination_id = destination.id.to_i
        if @active[direction][:by_destination].key?(destination_id)
          raise InvalidRewrite, "rewritten packet identifier #{destination_id} is already in use"
        end

        supersede_retired(direction, source_id)
        supersede_retired(direction, destination_id, true)
        flow = Flow.new(direction, source, destination, destination.to_s)
        @active[direction][:by_source][source_id] = flow
        @active[direction][:by_destination][destination_id] = flow
        destination
      end

      def handle_flow_control(direction, packet, filter)
        original = snapshot(packet)
        filtered = apply_filter(packet, filter)
        return nil if filtered.nil?

        unless filtered.class == original.class
          raise InvalidRewrite,
                "filter changed #{original.type_name} into #{filtered.type_name}"
        end
        unless filtered.id == original.id
          raise InvalidRewrite,
                "filter must not change the packet identifier of a #{original.type_name}"
        end

        flow = find_flow_control_flow(direction, original)
        unless flow && valid_flow_control?(original, flow)
          log_warn "Discarding #{original.type_name} with uncorrelated identifier #{original.id}"
          return nil
        end

        filtered.id = original.is_a?(MQTT::Packet::Pubrel) ? flow.destination_id : flow.source_id
        advance_flow(flow, original)
        filtered
      end

      def find_flow_control_flow(direction, packet)
        # PUBREL is sent by the publisher, so it travels in the same direction
        # as the original PUBLISH. The other acknowledgements travel in the
        # opposite direction.
        flow_direction = packet.is_a?(MQTT::Packet::Pubrel) ? direction : opposite(direction)
        if packet.is_a?(MQTT::Packet::Pubrel)
          find_by_source(flow_direction, packet.id)
        else
          find_by_destination(flow_direction, packet.id)
        end
      end

      def valid_flow_control?(packet, flow)
        case packet
        when MQTT::Packet::Puback
          flow.qos == 1 && (flow.active? ? flow.state == :wait_puback : true)
        when MQTT::Packet::Pubrec
          flow.qos == 2 && (!flow.active? || [:wait_pubrec, :wait_pubcomp].include?(flow.state))
        when MQTT::Packet::Pubrel
          flow.qos == 2 && (!flow.active? || flow.state == :wait_pubcomp)
        when MQTT::Packet::Pubcomp
          flow.qos == 2 && (!flow.active? || flow.state == :wait_pubcomp)
        else
          false
        end
      end

      def advance_flow(flow, packet)
        return unless flow.active?

        case packet
        when MQTT::Packet::Puback
          retire(flow) if flow.state == :wait_puback
        when MQTT::Packet::Pubrec
          flow.state = :wait_pubcomp if flow.state == :wait_pubrec
        when MQTT::Packet::Pubcomp
          retire(flow) if flow.state == :wait_pubcomp
        end
      end

      def validate_publish(source, filtered)
        unless filtered.is_a?(MQTT::Packet::Publish)
          raise InvalidRewrite, 'filter changed a PUBLISH packet into another packet type'
        end
        unless filtered.qos == source.qos
          raise InvalidRewrite,
                "filter changed QoS from #{source.qos} to #{filtered.qos}"
        end
        unless filtered.duplicate == source.duplicate
          raise InvalidRewrite, 'filter must not change the DUP flag of a PUBLISH packet'
        end
        if source.qos > 0 && (filtered.id.to_i < 1 || filtered.id.to_i > 0xffff)
          raise InvalidRewrite, "rewritten packet identifier #{filtered.id.inspect} is not valid"
        end
        return unless filtered.topic.nil? || filtered.topic.to_s.empty?

        raise InvalidRewrite, 'filter produced a PUBLISH packet without a topic'
      end

      def validate_retransmission(packet, flow)
        return if packet.qos == flow.qos &&
                  packet.topic == flow.source_topic &&
                  packet.payload == flow.source_payload

        raise InvalidRewrite,
              "DUP PUBLISH #{packet.id} does not match the flow it claims to retransmit"
      end

      def retransmit(flow)
        # Reuse the exact rewritten packet that was sent the first time. The
        # filter is deliberately not called again: a retransmission must not
        # allocate a second rewritten identifier.
        packet = MQTT::Packet.parse(flow.transformed.dup)
        packet.duplicate = true
        packet
      end

      def find_by_source(direction, id)
        @active[direction][:by_source][id] || @retired[direction][:by_source][id]
      end

      def find_active_by_source(direction, id)
        @active[direction][:by_source][id]
      end

      def find_by_destination(direction, id)
        @active[direction][:by_destination][id] || @retired[direction][:by_destination][id]
      end

      def retire(flow)
        delete_if_same(@active[flow.direction][:by_source], flow.source_id, flow)
        delete_if_same(@active[flow.direction][:by_destination], flow.destination_id, flow)
        flow.state = :complete
        @retired[flow.direction][:by_source][flow.source_id] = flow
        @retired[flow.direction][:by_destination][flow.destination_id] = flow
        trim_retired(flow.direction)
      end

      def trim_retired(direction)
        table = @retired[direction][:by_source]
        while table.length > MAX_RETIRED_FLOWS
          oldest_id, oldest = table.first
          table.delete(oldest_id)
          delete_if_same(@retired[direction][:by_destination], oldest.destination_id, oldest)
        end
      end

      def delete_if_same(table, key, flow)
        table.delete(key) if table[key].equal?(flow)
      end

      def drop_retired_for_source(direction, source_id)
        flow = @retired[direction][:by_source].delete(source_id)
        return if flow.nil?
        delete_if_same(@retired[direction][:by_destination], flow.destination_id, flow)
      end

      def drop_retired_for_destination(direction, destination_id)
        flow = @retired[direction][:by_destination].delete(destination_id)
        return if flow.nil?
        delete_if_same(@retired[direction][:by_source], flow.source_id, flow)
      end

      # Remove a completed flow whose identifiers are about to be reused, so
      # that a stale mapping can never be returned for the new flow.
      def supersede_retired(direction, id, by_destination = false)
        if by_destination
          drop_retired_for_destination(direction, id)
        else
          drop_retired_for_source(direction, id)
        end
      end

      def opposite(direction)
        direction == CLIENT_TO_SERVER ? SERVER_TO_CLIENT : CLIENT_TO_SERVER
      end

      def new_tables
        tables = {}
        DIRECTIONS.each do |direction|
          tables[direction] = {
            :by_source => {},
            :by_destination => {}
          }
        end
        tables
      end

      def log_warn(message)
        @logger.warn(message) unless @logger.nil?
      end
    end

    # Address to bind listening socket to
    attr_reader :local_host

    # Port to bind listening socket to
    attr_reader :local_port

    # Address of upstream server to send packets upstream to
    attr_reader :server_host

    # Port of upstream server to send packets upstream to.
    attr_reader :server_port

    # Time in seconds before disconnecting an idle connection
    attr_reader :select_timeout

    # Ruby Logger object to send informational messages to
    attr_reader :logger

    # A filter Proc for packets coming from the client (to the server).
    attr_writer :client_filter

    # A filter Proc for packets coming from the server (to the client).
    attr_writer :server_filter

    # Create a new MQTT Proxy instance.
    #
    # Possible argument keys:
    #
    #  :local_host      Address to bind listening socket to.
    #  :local_port      Port to bind listening socket to.
    #  :server_host     Address of upstream server to send packets upstream to.
    #  :server_port     Port of upstream server to send packets upstream to.
    #  :select_timeout  Time in seconds before disconnecting a connection.
    #  :logger          Ruby Logger object to send informational messages to.
    #
    # NOTE: be careful not to connect to yourself!
    def initialize(args = {})
      @local_host = args[:local_host] || '0.0.0.0'
      @local_port = args[:local_port] || MQTT::DEFAULT_PORT
      @server_host = args[:server_host]
      @server_port = args[:server_port] || 18_830
      @select_timeout = args[:select_timeout] || 60

      # Setup a logger
      @logger = args[:logger]
      if @logger.nil?
        @logger = Logger.new(STDOUT)
        @logger.level = Logger::INFO
      end

      # Default is not to have any filters
      @client_filter = nil
      @server_filter = nil

      # Create TCP server socket
      @server = TCPServer.open(@local_host, @local_port)
      # Report the port that was actually bound (useful when 0 was requested)
      @local_port = @server.addr[1]
      @logger.info "MQTT::Proxy listening on #{@local_host}:#{@local_port}"
    end

    # Start accepting connections and processing packets.
    def run
      loop do
        # Wait for a client to connect and then create a thread for it
        Thread.new(@server.accept) do |client_socket|
          logger.info "Accepted client: #{client_socket.peeraddr.join(':')}"
          server_socket = TCPSocket.new(@server_host, @server_port)
          begin
            process_packets(client_socket, server_socket)
          rescue Exception => exp
            logger.error exp.to_s
          end
          logger.info "Disconnected: #{client_socket.peeraddr.join(':')}"
          server_socket.close
          client_socket.close
        end
      end
    end

    private

    def process_packets(client_socket, server_socket)
      # Packet identifier mappings belong to this connection only. Discarding
      # the session when the sockets close guarantees that an old mapping can
      # never be used by a later connection.
      session = Session.new(@logger)

      loop do
        # Wait for some data on either socket
        selected = IO.select([client_socket, server_socket], nil, nil, @select_timeout)

        # Timeout
        raise 'Timeout in select' if selected.nil?

        # Iterate through each of the sockets with data to read
        if selected[0].include?(client_socket)
          packet = MQTT::Packet.read(client_socket)
          logger.debug "client -> <#{packet.type_name}>"
          packet = session.handle(Session::CLIENT_TO_SERVER, packet, @client_filter)
          unless packet.nil?
            server_socket.write(packet)
            logger.debug "<#{packet.type_name}> -> server"
          end
        elsif selected[0].include?(server_socket)
          packet = MQTT::Packet.read(server_socket)
          logger.debug "server -> <#{packet.type_name}>"
          packet = session.handle(Session::SERVER_TO_CLIENT, packet, @server_filter)
          unless packet.nil?
            client_socket.write(packet)
            logger.debug "<#{packet.type_name}> -> client"
          end
        else
          logger.error 'Problem with select: socket is neither server or client'
        end
      end
    end
  end
end
