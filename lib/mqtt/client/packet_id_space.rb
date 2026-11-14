# encoding: BINARY

module MQTT
  class Client
    # Raised when no packet identifier can be allocated because every
    # identifier is either owned by an in-flight request or quarantined
    # pending a possibly-late acknowledgement.
    class PacketIdExhausted < MQTT::Exception
    end

    # Owns the 16-bit packet identifier space of one MQTT connection.
    #
    # QoS > 0 PUBLISH, SUBSCRIBE and UNSUBSCRIBE packets all allocate their
    # identifiers from the same space. An identifier is only handed out while
    # no other request owns it, so wrap-around can never silently reuse an
    # identifier that still has an outstanding acknowledgement.
    #
    # Every allocation records the owning operation (:publish, :subscribe or
    # :unsubscribe) and the connection generation it belongs to. An
    # acknowledgement completes a request only when its identifier, operation
    # and connection generation all match.
    #
    # When a request gives up before its acknowledgement arrives (timeout,
    # send failure or disconnect) its identifier is *quarantined* rather than
    # handed straight back out. A late acknowledgement for a quarantined
    # identifier is swallowed and releases the quarantine; the identifier can
    # then be allocated again. Reconnecting clears every quarantine. This means
    # a stale acknowledgement can never complete a different request and no
    # identifier is leaked permanently.
    class PacketIdSpace
      # One in-flight request that currently owns an identifier.
      class Entry
        # @return [Symbol] the kind of request that owns the identifier
        attr_reader :operation

        # @return [Integer] the connection generation the request belongs to
        attr_reader :generation

        # @return [Queue] queue that receives the terminal event
        attr_reader :queue

        def initialize(operation, generation)
          @operation = operation
          @generation = generation
          @queue = Queue.new
        end
      end

      # The packet class that is the valid acknowledgement for each operation.
      ACK_CLASSES = {
        :publish => MQTT::Packet::Puback,
        :subscribe => MQTT::Packet::Suback,
        :unsubscribe => MQTT::Packet::Unsuback
      }.freeze

      # @return [Hash{Integer => Entry}] identifiers owned by in-flight requests
      attr_reader :in_flight

      # @return [Hash{Integer => Integer}] identifiers released before their
      #   acknowledgement arrived, mapped to the connection generation that
      #   released them. A late acknowledgement for one of these is swallowed
      #   and clears the quarantine instead of completing another request.
      attr_reader :quarantined

      # @param max_id [Integer] largest identifier that may be allocated
      #   (defaults to the MQTT maximum of 65535)
      def initialize(max_id = 0xffff)
        @max_id = max_id
        @mutex = Mutex.new
        @in_flight = {}
        @quarantined = {}
        @next_id = 0
        @generation = 0
      end

      # Current connection generation. Incremented on every (re)connect and
      # used to reject acknowledgements left over from a previous connection.
      def generation
        @mutex.synchronize { @generation }
      end

      # Number of identifiers currently owned by in-flight requests.
      def in_flight_count
        @mutex.synchronize { @in_flight.size }
      end

      # Number of identifiers currently quarantined pending a late ack.
      def quarantined_count
        @mutex.synchronize { @quarantined.size }
      end

      # Whether an identifier is currently owned by an in-flight request.
      def in_flight?(id)
        @mutex.synchronize { @in_flight.key?(id) }
      end

      # Whether an identifier is currently quarantined within this connection.
      def quarantined?(id)
        @mutex.synchronize { @quarantined.key?(id) }
      end

      # Begin a new connection: invalidate every in-flight request and
      # quarantine owned by the previous connection and advance the generation.
      def reset
        @mutex.synchronize do
          @generation += 1
          @in_flight.clear
          @quarantined.clear
          @next_id = 0
        end
      end

      # Allocate an identifier for an operation and register its ownership.
      #
      # @param operation [Symbol] :publish, :subscribe or :unsubscribe
      # @return [Array(Integer, Entry)] the identifier and its entry
      # @raise [PacketIdExhausted] if every identifier is in flight or
      #   quarantined; the caller's request is left untouched in that case.
      def reserve(operation)
        @mutex.synchronize do
          id = next_free_id
          if id.nil?
            raise PacketIdExhausted, 'No free MQTT packet identifier is available'
          end

          entry = Entry.new(operation, @generation)
          @in_flight[id] = entry
          [id, entry]
        end
      end

      # Deliver an acknowledgement to the request that owns its identifier,
      # but only when the packet class, identifier and connection generation
      # all match.
      #
      # Acknowledgements for quarantined identifiers (a late ack for a request
      # that already timed out or failed) are swallowed and release the
      # quarantine so the identifier can be allocated again. Any other
      # unmatched acknowledgement is discarded without side effects.
      #
      # @return [Boolean] whether the acknowledgement completed a live request
      def acknowledge(packet)
        @mutex.synchronize do
          id = packet.id
          entry = @in_flight[id]

          if entry
            return false unless entry.generation == @generation
            return false unless ACK_CLASSES[entry.operation] == packet.class

            @in_flight.delete(id)
            entry.queue.push(packet)
            return true
          end

          if @quarantined.key?(id)
            # The original request already gave up. Swallow its late
            # acknowledgement and return the identifier to the allocatable
            # pool instead of completing whatever may use the id later.
            @quarantined.delete(id)
          end

          false
        end
      end

      # Release ownership of an identifier and quarantine it so a late
      # acknowledgement cannot complete a future owner of the same identifier.
      #
      # @param id [Integer] the identifier to release
      # @param event [:close, nil] terminal event to deliver to any waiting
      #   request. When nil no event is pushed (for example after a send
      #   failure before waiting started).
      # @return [void]
      def release(id, event = nil)
        @mutex.synchronize do
          entry = @in_flight.delete(id)
          return if entry.nil?

          @quarantined[id] = entry.generation
          entry.queue.push(event) unless event.nil?
        end
      end

      # Fail every in-flight request of the current connection with the same
      # event, quarantining all of their identifiers.
      #
      # Used when the connection closes. The quarantine is cleared by the
      # next successful {#reset} (a reconnect) or by the late acks themselves.
      def fail_all(event)
        @mutex.synchronize do
          @in_flight.each do |id, entry|
            @quarantined[id] = entry.generation
            entry.queue.push(event)
          end
          @in_flight.clear
        end
      end

      private

      # Find the next identifier that is neither in flight nor quarantined,
      # scanning forward and wrapping around the space. Must be called under
      # @mutex.
      def next_free_id
        @max_id.times do
          @next_id += 1
          @next_id = 1 if @next_id > @max_id
          return @next_id unless @in_flight.key?(@next_id) || @quarantined.key?(@next_id)
        end
        nil
      end
    end
  end
end
