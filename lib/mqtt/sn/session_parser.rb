module MQTT
  module SN
    # Offline MQTT-SN session parser.
    #
    # Consumes already-parsed MQTT::SN::Packet objects together with
    # caller-supplied direction, gateway and client identifiers, and
    # resolves the real topic of topic-carrying packets (Publish,
    # Puback, Suback, Subscribe, Unsubscribe) with provenance.
    #
    # Dynamic topic id mappings are only established by a REGISTER
    # that is confirmed by a successful REGACK (return code 0) from
    # the peer. Short topic names and predefined topic ids are
    # resolved independently. State is kept per (gateway, client)
    # session, so topic id reuse across gateways, clients or
    # reconnects never leaks a name from another session.
    class SessionParser
      DIRECTIONS = [:from_client, :to_client].freeze

      # The resolved topic of a single packet, with provenance.
      class TopicResolution
        attr_reader :packet   # the packet that was resolved
        attr_reader :topic    # the real topic name, or nil if unresolved
        attr_reader :source   # :register, :short, :predefined, :explicit, :unknown or :conflict
        attr_reader :gateway  # caller-supplied gateway identifier
        attr_reader :client   # caller-supplied client identifier
        attr_reader :session  # session epoch (number of CONNECTs seen, 0 = none captured)
        attr_reader :detail   # human-readable explanation of the outcome

        def initialize(packet:, topic:, source:, gateway:, client:, session:, detail: nil)
          @packet = packet
          @topic = topic
          @source = source
          @gateway = gateway
          @client = client
          @session = session
          @detail = detail
        end

        def resolved?
          !topic.nil?
        end

        def unknown?
          source == :unknown
        end

        def conflict?
          source == :conflict
        end

        def to_s
          label = topic.nil? ? source.to_s : topic.inspect
          "#{label} (source=#{source}, gateway=#{gateway}, client=#{client}, session=#{session})"
        end
      end

      # Per (gateway, client) session state.
      class Session
        attr_accessor :epoch
        attr_reader :mappings  # topic_id => {:topic, :msg_id, :session}
        attr_reader :pending   # [msg_id, direction] => {:topic_id, :topic_name}
        attr_reader :conflicts # topic_id => [name, name]
        attr_reader :rejected  # topic_id => topic_name
        attr_reader :orphaned  # topic ids seen in a REGACK without a captured REGISTER

        def initialize
          @epoch = 0
          @mappings = {}
          @pending = {}
          @conflicts = {}
          @rejected = {}
          @orphaned = []
        end
      end

      # predefined: either a flat {topic_id => name} hash applying to all
      # gateways, or {gateway => {topic_id => name}} for per-gateway tables
      # (a :default gateway key acts as a fallback).
      def initialize(predefined: {})
        @predefined = {}
        predefined.each_pair do |key, value|
          if value.is_a?(Hash)
            @predefined[key] = value
          else
            (@predefined[:default] ||= {})[key] = value
          end
        end
        @sessions = {}
      end

      # Process one parsed packet. Returns a TopicResolution for
      # topic-carrying packets, nil for everything else.
      def process(packet, direction:, gateway:, client:)
        unless DIRECTIONS.include?(direction)
          raise ArgumentError, "direction must be one of #{DIRECTIONS.inspect}"
        end

        case packet
        when MQTT::SN::Packet::Connect
          start_session(gateway, client) if direction == :from_client
          nil
        when MQTT::SN::Packet::Disconnect
          @sessions.delete(session_key(gateway, client))
          nil
        when MQTT::SN::Packet::Register
          session = session_for(gateway, client)
          session.pending[[packet.id, direction]] = {
            :topic_id => packet.topic_id,
            :topic_name => packet.topic_name
          }
          nil
        when MQTT::SN::Packet::Regack
          handle_regack(packet, direction, gateway, client)
          nil
        when MQTT::SN::Packet::Publish, MQTT::SN::Packet::Puback, MQTT::SN::Packet::Suback
          resolve_id_packet(packet, gateway, client)
        when MQTT::SN::Packet::Subscribe, MQTT::SN::Packet::Unsubscribe
          resolve_named_packet(packet, gateway, client)
        end
      end

      private

      def session_key(gateway, client)
        [gateway, client]
      end

      def session_for(gateway, client)
        @sessions[session_key(gateway, client)] ||= Session.new
      end

      def start_session(gateway, client)
        previous = @sessions[session_key(gateway, client)]
        session = Session.new
        session.epoch = previous.nil? ? 1 : previous.epoch + 1
        @sessions[session_key(gateway, client)] = session
      end

      def opposite(direction)
        direction == :from_client ? :to_client : :from_client
      end

      def handle_regack(packet, direction, gateway, client)
        session = session_for(gateway, client)
        pending = session.pending.delete([packet.id, opposite(direction)])
        if pending.nil?
          # The matching REGISTER was never captured: the topic name is
          # unknowable, so no mapping may be established.
          session.orphaned << packet.topic_id unless session.orphaned.include?(packet.topic_id)
          return
        end

        if packet.return_code != 0x00
          session.rejected[packet.topic_id] = pending[:topic_name]
          return
        end

        existing = session.mappings[packet.topic_id]
        if existing.nil?
          session.mappings[packet.topic_id] = {
            :topic => pending[:topic_name],
            :msg_id => packet.id,
            :session => session.epoch
          }
        elsif existing[:topic] != pending[:topic_name]
          # Same topic id confirmed for two different names within one
          # session: the capture is ambiguous, flag a conflict.
          session.mappings.delete(packet.topic_id)
          session.conflicts[packet.topic_id] = [existing[:topic], pending[:topic_name]]
        end
      end

      def predefined_topic(gateway, topic_id)
        table = @predefined[gateway] || @predefined[:default]
        table && table[topic_id]
      end

      def resolve_id_packet(packet, gateway, client)
        session = session_for(gateway, client)
        base = {
          :packet => packet,
          :gateway => gateway,
          :client => client,
          :session => session.epoch
        }

        case packet.topic_id_type
        when :short
          TopicResolution.new(**base,
            :topic => packet.topic_id,
            :source => :short,
            :detail => 'short topic name carried in the packet')
        when :predefined
          topic = predefined_topic(gateway, packet.topic_id)
          if topic.nil?
            TopicResolution.new(**base,
              :topic => nil,
              :source => :unknown,
              :detail => "no predefined topic id #{packet.topic_id} configured for gateway #{gateway.inspect}")
          else
            TopicResolution.new(**base,
              :topic => topic,
              :source => :predefined,
              :detail => "predefined topic id #{packet.topic_id} for gateway #{gateway.inspect}")
          end
        else
          # :normal, or nil for packet types without flags (e.g. Puback)
          resolve_normal_id(packet.topic_id, session, base)
        end
      end

      def resolve_normal_id(topic_id, session, base)
        if session.conflicts.key?(topic_id)
          names = session.conflicts[topic_id]
          return TopicResolution.new(**base,
            :topic => nil,
            :source => :conflict,
            :detail => "topic id #{topic_id} registered to conflicting names #{names.map(&:inspect).join(' and ')}")
        end

        entry = session.mappings[topic_id]
        unless entry.nil?
          return TopicResolution.new(**base,
            :topic => entry[:topic],
            :source => :register,
            :detail => "registered via REGISTER/REGACK msg id #{entry[:msg_id]} in session #{entry[:session]}")
        end

        detail =
          if session.rejected.key?(topic_id)
            "registration of #{session.rejected[topic_id].inspect} as topic id #{topic_id} was rejected"
          elsif session.orphaned.include?(topic_id)
            "REGACK for topic id #{topic_id} seen without a captured REGISTER"
          else
            "no registration captured for topic id #{topic_id}"
          end
        TopicResolution.new(**base, :topic => nil, :source => :unknown, :detail => detail)
      end

      def resolve_named_packet(packet, gateway, client)
        session = session_for(gateway, client)
        base = {
          :packet => packet,
          :gateway => gateway,
          :client => client,
          :session => session.epoch
        }

        case packet.topic_id_type
        when :normal
          TopicResolution.new(**base,
            :topic => packet.topic_name,
            :source => :explicit,
            :detail => 'full topic name carried in the packet')
        when :short
          TopicResolution.new(**base,
            :topic => packet.topic_name,
            :source => :short,
            :detail => 'short topic name carried in the packet')
        when :predefined
          topic = predefined_topic(gateway, packet.topic_id)
          if topic.nil?
            TopicResolution.new(**base,
              :topic => nil,
              :source => :unknown,
              :detail => "no predefined topic id #{packet.topic_id} configured for gateway #{gateway.inspect}")
          else
            TopicResolution.new(**base,
              :topic => topic,
              :source => :predefined,
              :detail => "predefined topic id #{packet.topic_id} for gateway #{gateway.inspect}")
          end
        end
      end
    end
  end
end
