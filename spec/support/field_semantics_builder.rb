# encoding: BINARY

module MQTTFieldSemantics
  # Builds raw MQTT packet bytes from independent logical fields.
  #
  # This deliberately does not use MQTT::Packet to assemble bytes: the specs
  # compare the library codec against this independent reference encoder.
  module Builder
    class FieldTooLong < StandardError; end

    module_function

    def fixed_header(type_id, flags, body)
      header = [((type_id & 0x0F) << 4) | (flags & 0x0F)]
      length = body.bytesize
      loop do
        digit = length % 128
        length /= 128
        digit |= 0x80 if length > 0
        header << digit
        break if length.zero?
      end
      header.pack('C*') + body.b
    end

    def utf8_field(value)
      bytes = value.to_s.b
      raise FieldTooLong, 'UTF-8 field is longer than 65535 bytes' if bytes.bytesize > 0xFFFF
      [bytes.bytesize].pack('n') + bytes
    end

    def binary_field(value)
      bytes = value.to_s.b
      raise FieldTooLong, 'Binary field is longer than 65535 bytes' if bytes.bytesize > 0xFFFF
      [bytes.bytesize].pack('n') + bytes
    end

    def publish(topic:, payload: '', qos: 0, id: 0, retain: false, duplicate: false)
      flags = (retain ? 0x1 : 0x0) | ((qos & 0x03) << 1) | (duplicate ? 0x8 : 0x0)
      body = utf8_field(topic)
      body += [id].pack('n') unless qos.zero?
      body += payload.to_s.b
      fixed_header(3, flags, body)
    end

    def connect(client_id:, version: '3.1.1', clean_session: true, keep_alive: 15,
                will_topic: nil, will_payload: '', will_qos: 0, will_retain: false,
                username: nil, password: nil)
      if version == '3.1.0'
        protocol_name = 'MQIsdp'
        protocol_level = 3
      else
        protocol_name = 'MQTT'
        protocol_level = 4
      end

      flags = 0
      flags |= 0x02 if clean_session
      flags |= 0x04 unless will_topic.nil?
      flags |= ((will_qos & 0x03) << 3)
      flags |= 0x20 if will_retain
      flags |= 0x40 unless password.nil?
      flags |= 0x80 unless username.nil?

      body = utf8_field(protocol_name)
      body += [protocol_level, flags].pack('CC')
      body += [keep_alive].pack('n')
      body += utf8_field(client_id)
      unless will_topic.nil?
        body += utf8_field(will_topic)
        body += binary_field(will_payload)
      end
      body += utf8_field(username) unless username.nil?
      body += binary_field(password) unless password.nil?
      fixed_header(1, 0, body)
    end

    def subscribe(id:, filters:)
      body = [id].pack('n')
      filters.each do |filter, qos|
        body += utf8_field(filter)
        body += [qos].pack('C')
      end
      fixed_header(8, 0x2, body)
    end

    def unsubscribe(id:, filters:)
      body = [id].pack('n')
      filters.each { |filter| body += utf8_field(filter) }
      fixed_header(10, 0x2, body)
    end

    def build(entry)
      args = decode_hex_args(entry.fetch('args'))
      case entry.fetch('packet')
      when 'publish'
        publish(
          :topic => args.fetch(:topic_hex),
          :payload => args.fetch(:payload_hex, ''.b),
          :qos => args.fetch(:qos, 0),
          :id => args.fetch(:id, 0),
          :retain => args.fetch(:retain, false),
          :duplicate => args.fetch(:duplicate, false)
        )
      when 'connect'
        connect(
          :client_id => args.fetch(:client_id_hex),
          :version => args.fetch(:version, '3.1.1'),
          :clean_session => args.fetch(:clean_session, true),
          :keep_alive => args.fetch(:keep_alive, 15),
          :will_topic => args[:will_topic_hex],
          :will_payload => args.fetch(:will_payload_hex, ''.b),
          :will_qos => args.fetch(:will_qos, 0),
          :will_retain => args.fetch(:will_retain, false),
          :username => args[:username_hex],
          :password => args[:password_hex]
        )
      when 'subscribe'
        subscribe(:id => args.fetch(:id, 1), :filters => args.fetch(:filters))
      when 'unsubscribe'
        unsubscribe(:id => args.fetch(:id, 1), :filters => args.fetch(:filters).map(&:first))
      else
        raise ArgumentError, "Unknown packet kind: #{entry['packet']}"
      end
    end

    def decode_hex_args(args)
      args.each_with_object({}) do |(key, value), result|
        result[key.to_sym] =
          case key
          when /_hex$/
            [value].pack('H*')
          when 'filters'
            value.map { |filter| [filter['filter_hex'].then { |hex| [hex].pack('H*') }, filter['qos']] }
          else
            value
          end
      end
    end
  end

  # Deterministic atoms shared by the replay-corpus generator and the specs.
  module Atoms
    INVALID_TEXT = {
      'lone continuation byte' => "\x80".b,
      'overlong two byte sequence' => "\xC0\xAF".b,
      'overlong three byte sequence' => "\xE0\x80\xAF".b,
      'UTF-16 surrogate' => "\xED\xA0\x80".b,
      'code point above U+10FFFF' => "\xF4\x90\x80\x80".b,
      'invalid byte 0xFF' => "\xFF".b,
      'truncated multi byte sequence' => "\xE2\x91".b,
      'embedded NUL' => "a\x00b".b,
      'only NUL' => "\x00".b
    }.freeze

    WILDCARD_TOPICS = [
      '+', '#', 'a/+', 'a/#', 'a/+/b', 'a/b#', '+a', '#a', 'a/#/b'
    ].freeze

    VALID_FILTERS = [
      '#', '+', 'a/#', 'a/+/b', '+/tennis/#', 'sport/tennis/+', 'sport/+',
      '/finance', 'sport/', '/', 'a//b', '$SYS/#', 'sport/tennis/player1/#'
    ].freeze

    INVALID_FILTERS = [
      '', 'a/#/b', 'a/b#', 'a/+b', '#/a', 'a#', '#a', '+a', 'a+/b', 'sport/tennis#', 'sport+'
    ].freeze

    BINARY_PAYLOADS = {
      'empty' => ''.b,
      'NUL 0x00' => "\x00".b,
      '0xFF' => "\xFF".b,
      'invalid UTF-8 sequence' => "\xED\xA0\x80\xC0\xAF\xFF".b,
      'all byte values' => (0..255).to_a.pack('C*')
    }.freeze
  end
end

require 'json'

module MQTTFieldSemantics
  # Replays corpus entries through the library codec without interpreting them.
  module Replay
    module_function

    def decode_args(args)
      Builder.decode_hex_args(args || {})
    end

    def packet_for(entry)
      args = decode_args(entry['args'])
      case entry.fetch('packet')
      when 'publish'
        MQTT::Packet::Publish.new(
          :topic => args.fetch(:topic_hex),
          :payload => args.fetch(:payload_hex, ''),
          :qos => args.fetch(:qos, 0),
          :id => args.fetch(:id, 0),
          :retain => args.fetch(:retain, false),
          :duplicate => args.fetch(:duplicate, false)
        )
      when 'connect'
        MQTT::Packet::Connect.new(
          :version => args.fetch(:version, '3.1.1'),
          :client_id => args.fetch(:client_id_hex),
          :clean_session => args.fetch(:clean_session, true),
          :keep_alive => args.fetch(:keep_alive, 15),
          :will_topic => args[:will_topic_hex],
          :will_payload => args.fetch(:will_payload_hex, ''),
          :will_qos => args.fetch(:will_qos, 0),
          :will_retain => args.fetch(:will_retain, false),
          :username => args[:username_hex],
          :password => args[:password_hex]
        )
      when 'subscribe'
        MQTT::Packet::Subscribe.new(
          :id => args.fetch(:id, 1),
          :topics => args.fetch(:filters)
        )
      when 'unsubscribe'
        MQTT::Packet::Unsubscribe.new(
          :id => args.fetch(:id, 1),
          :topics => args.fetch(:filters).map(&:first)
        )
      else
        raise ArgumentError, "Unknown packet kind: #{entry['packet']}"
      end
    end

    def wire_for(entry)
      entry['wire_hex'] && [entry['wire_hex']].pack('H*')
    end

    def encode(entry)
      packet_for(entry).to_s
    end

    def parse(entry)
      wire = wire_for(entry)
      raise ArgumentError, "No wire bytes for #{entry['id']}" if wire.nil?

      MQTT::Packet.parse(wire)
    end

    # Returns a hash of observed outcomes. Exceptions are returned as objects so
    # callers can assert on them without treating expected rejection as a crash.
    def replay(entry)
      result = {}
      if entry.dig('expect', 'encode') != 'n/a'
        result[:encode] = begin
          encode(entry)
        rescue ArgumentError, MQTT::ProtocolException => exp
          exp
        end
      end
      if entry.dig('expect', 'parse') != 'n/a'
        result[:parse] = begin
          parse(entry)
        rescue MQTT::ProtocolException => exp
          exp
        end
      end
      result
    end

    # Compare a parsed packet against the independent logical fields that
    # generated the wire bytes.
    def field_mismatches(entry, packet)
      args = decode_args(entry['args'])
      mismatches = []
      case entry['packet']
      when 'publish'
        mismatches << 'topic' unless bytes(packet.topic) == bytes(args[:topic_hex])
        mismatches << 'payload' unless bytes(packet.payload) == bytes(args.fetch(:payload_hex, ''))
        mismatches << 'qos' unless packet.qos == args.fetch(:qos, 0)
        mismatches << 'id' unless packet.id == args.fetch(:id, 0)
        mismatches << 'retain' unless packet.retain == args.fetch(:retain, false)
      when 'connect'
        mismatches << 'client_id' unless bytes(packet.client_id) == bytes(args[:client_id_hex])
        mismatches << 'username' unless bytes(packet.username) == bytes(args[:username_hex])
        mismatches << 'will_topic' unless bytes(packet.will_topic) == bytes(args[:will_topic_hex])
        mismatches << 'will_payload' unless bytes(packet.will_payload) == bytes(args.fetch(:will_payload_hex, ''))
        mismatches << 'password' unless bytes(packet.password) == bytes(args[:password_hex])
        mismatches << 'clean_session' unless packet.clean_session == args.fetch(:clean_session, true)
        mismatches << 'keep_alive' unless packet.keep_alive == args.fetch(:keep_alive, 15)
      when 'subscribe'
        expected = args.fetch(:filters).map { |filter, qos| [bytes(filter), qos] }
        actual = packet.topics.map { |filter, qos| [bytes(filter), qos] }
        mismatches << 'filters' unless actual == expected
      when 'unsubscribe'
        expected = args.fetch(:filters).map { |filter, _qos| bytes(filter) }
        actual = packet.topics.map { |filter| bytes(filter) }
        mismatches << 'filters' unless actual == expected
      end
      mismatches
    end

    def bytes(value)
      value.nil? ? nil : value.to_s.b
    end

    def failures(entry)
      expected = entry.fetch('expect')
      observed = replay(entry)
      failures = []

      if expected['encode'] == 'accept'
        if observed[:encode].is_a?(Exception)
          failures << "encode unexpectedly rejected: #{observed[:encode].class}: #{observed[:encode].message}"
        elsif entry['wire_hex'] && observed[:encode].b != wire_for(entry).b
          failures << 'encode bytes differ from independent builder'
        end
      elsif expected['encode'] == 'reject'
        unless observed[:encode].is_a?(ArgumentError) || observed[:encode].is_a?(MQTT::ProtocolException)
          failures << "encode unexpectedly accepted: #{observed[:encode].inspect}"
        end
      end

      if expected['parse'] == 'accept'
        if observed[:parse].is_a?(Exception)
          failures << "parse unexpectedly rejected: #{observed[:parse].class}: #{observed[:parse].message}"
        else
          field_mismatches(entry, observed[:parse]).each do |field|
            failures << "parsed #{field} differs from logical field"
          end
        end
      elsif expected['parse'] == 'reject'
        unless observed[:parse].is_a?(MQTT::ProtocolException)
          failures << "parse unexpectedly accepted: #{observed[:parse].inspect}"
        end
      end

      failures
    end
  end
end

module MQTTFieldSemantics
  # Independent semantic oracle for MQTT v3.1.1 text fields. None of these
  # methods call into MQTT::Packet, so agreement with the library is meaningful.
  module Oracle
    module_function

    def valid_utf8?(bytes)
      bytes.to_s.dup.force_encoding(Encoding::UTF_8).valid_encoding?
    end

    def null?(bytes)
      bytes.to_s.b.include?("\x00".b)
    end

    def text_error(bytes, field)
      return "#{field} must be at least one character" if bytes.to_s.b.empty?
      return "#{field} contains ill-formed UTF-8" unless valid_utf8?(bytes)
      return "#{field} contains U+0000" if null?(bytes)
      return "#{field} exceeds 65535 encoded bytes" if bytes.to_s.b.bytesize > 0xFFFF

      nil
    end

    def topic_name_error(bytes, field = 'Topic Name')
      error = text_error(bytes, field)
      return error if error

      text = bytes.to_s.b
      return "#{field} contains wildcard characters" if text.include?('+') || text.include?('#')

      nil
    end

    def topic_filter_error(bytes, field = 'Topic Filter')
      error = text_error(bytes, field)
      return error if error

      levels = bytes.to_s.b.split('/', -1)
      levels.each_with_index do |level, index|
        if level.include?('#') && !(level == '#' && index == levels.length - 1)
          return "#{field} has a misplaced multi-level wildcard"
        end
        return "#{field} has a single-level wildcard sharing a level" if level.include?('+') && level != '+'
      end
      nil
    end

    def connect_identity_error(version:, client_id:, clean_session:, username:,
                               will_topic:)
      if client_id.to_s.b.empty?
        return 'empty ClientId requires CleanSession=1' unless clean_session
      end
      if version == '3.1.0' && !(1..23).cover?(client_id.to_s.b.bytesize)
        return 'MQTT 3.1.0 ClientId must be 1..23 bytes'
      end

      error = text_error(client_id, 'ClientId')
      return error if error

      unless username.nil?
        error = text_error(username, 'User Name')
        return error if error
      end

      unless will_topic.nil?
        error = topic_name_error(will_topic, 'Will Topic')
        return error if error
      end

      nil
    end
  end
end
