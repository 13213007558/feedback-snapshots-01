# encoding: BINARY

$:.unshift(File.dirname(__FILE__))

require 'spec_helper'
require 'json'
require_relative 'support/field_semantics_builder'

# Field-semantics generation tests.
#
# These specs keep each logical field independent from the wire representation
# and check both directions: the encoder must not emit bytes that it would
# itself reject as a different meaning, and the parser must not silently
# reinterpret them.
describe 'MQTT field semantics' do
  CORPUS = JSON.parse(
    File.read(File.expand_path('fixtures/field_semantics/cases.json', __dir__))
  ).freeze

  def self.cases_for(category)
    CORPUS.select { |entry| entry['category'] == category }
  end

  def cases_for(category)
    self.class.cases_for(category)
  end

  describe 'replay corpus' do
    it 'contains every category and a replayable corpus entry for each rejection' do
      categories = CORPUS.map { |entry| entry['category'] }.uniq.sort
      expect(categories).to eq(%w[connect-identity publish-payload publish-topic topic-filter])
      expect(CORPUS.length).to be > 100
      CORPUS.each do |entry|
        next unless entry['wire_hex']

        expect([entry['wire_hex']].pack('H*').b.bytesize).to be > 0
      end
    end

    it 'has a minimal replayable input for each rejected parse case' do
      rejected = CORPUS.select { |entry| entry['expect']['parse'] == 'reject' }
      expect(rejected).not_to be_empty
      rejected.each do |entry|
        expect(entry['wire_hex']).not_to be_nil, "missing replay bytes for #{entry['id']}"
        expect(entry['args']).not_to be_empty, "missing logical fields for #{entry['id']}"
      end
    end

    CORPUS.each do |entry|
      it "replays #{entry['id']}: #{entry['note']}" do
        failures = MQTTFieldSemantics::Replay.failures(entry)
        expect(failures).to be_empty, failures.join('; ')
      end
    end
  end

  describe 'PUBLISH topic name oracle' do
    it 'agrees with the independent oracle for every corpus topic' do
      cases_for('publish-topic').each do |entry|
        topic = [entry['args']['topic_hex']].pack('H*')
        expected = MQTTFieldSemantics::Oracle.topic_name_error(topic).nil? ? 'accept' : 'reject'
        expect(entry['expect']['encode']).to eq(expected), entry['id']
      end
    end

    it 'never lets a wildcard PUBLISH topic survive either direction' do
      MQTTFieldSemantics::Atoms::WILDCARD_TOPICS.each do |topic|
        wire = MQTTFieldSemantics::Builder.publish(:topic => topic)
        expect { MQTT::Packet.parse(wire) }.to raise_error(MQTT::ProtocolException)
        expect {
          MQTT::Packet::Publish.new(:topic => topic, :payload => '').to_s
        }.to raise_error(ArgumentError)
      end
    end

    it 'keeps wildcard bytes in the topic distinct from a legal filter' do
      filter_wire = MQTTFieldSemantics::Builder.subscribe(
        :id => 1, :filters => [['a/#', 0]]
      )
      filter_packet = MQTT::Packet.parse(filter_wire)
      expect(filter_packet.topics).to eq([['a/#', 0]])

      publish_wire = MQTTFieldSemantics::Builder.publish(:topic => 'a/#')
      expect { MQTT::Packet.parse(publish_wire) }.to raise_error(MQTT::ProtocolException)
    end

    it 'accepts valid boundary lengths and rejects one byte more' do
      at_limit = MQTTFieldSemantics::Builder.publish(:topic => 'a' * 65_535)
      parsed = MQTT::Packet.parse(at_limit.dup)
      expect(parsed.topic.bytesize).to eq(65_535)
      expect(parsed.topic.encoding).to eq(Encoding::UTF_8)
      expect(parsed.to_s.b).to eq(at_limit.b)

      utf8_at_limit = MQTTFieldSemantics::Builder.publish(:topic => "é" * 32_767 + 'a')
      expect(MQTT::Packet.parse(utf8_at_limit.dup).topic.bytesize).to eq(65_535)

      expect {
        MQTT::Packet::Publish.new(:topic => 'a' * 65_536).to_s
      }.to raise_error(ArgumentError)
      expect {
        MQTT::Packet::Publish.new(:topic => "é" * 32_768).to_s
      }.to raise_error(ArgumentError)
    end
  end

  describe 'PUBLISH payload transparency' do
    it 'round-trips every binary payload byte-for-byte' do
      MQTTFieldSemantics::Atoms::BINARY_PAYLOADS.each_value do |payload|
        wire = MQTTFieldSemantics::Builder.publish(
          :topic => 'binary/data', :payload => payload, :qos => 1, :id => 42
        )
        packet = MQTT::Packet.parse(wire)
        expect(packet.payload.b).to eq(payload.b)
        expect(packet.payload.encoding).to eq(Encoding::ASCII_8BIT)
      end
    end

    it 'does not force arbitrary bytes through a text encoding' do
      payload = (0..255).to_a.pack('C*')
      packet = MQTT::Packet::Publish.new(:topic => 'raw', :payload => payload)
      expect(packet.to_s.b.bytes.last(256)).to eq(payload.bytes)
      expect(MQTT::Packet.parse(packet.to_s).payload.b).to eq(payload)
    end

    it 'never accepts or rejects a PUBLISH merely because the payload is not text' do
      MQTTFieldSemantics::Atoms::BINARY_PAYLOADS.each_value do |payload|
        wire = MQTTFieldSemantics::Builder.publish(:topic => 'binary', :payload => payload)
        packet = MQTT::Packet.parse(wire.dup)
        expect(packet.payload.b).to eq(payload.b)
        expect(packet.to_s.b).to eq(wire.b)
      end
    end

    it 'does not let a binary payload change the parsed topic or QoS' do
      payload = "\x00\x05relay".b
      [0, 1, 2].each do |qos|
        wire = MQTTFieldSemantics::Builder.publish(
          :topic => 'outer', :payload => payload, :qos => qos, :id => 0x1234
        )
        packet = MQTT::Packet.parse(wire)
        expect(packet.topic).to eq('outer')
        expect(packet.qos).to eq(qos)
        expect(packet.id).to eq(qos.zero? ? 0 : 0x1234)
        expect(packet.payload.b).to eq(payload)
      end
    end
  end

  describe 'SUBSCRIBE and UNSUBSCRIBE topic filters' do
    it 'accepts every legal wildcard placement' do
      MQTTFieldSemantics::Atoms::VALID_FILTERS.each do |filter|
        subscribe = MQTT::Packet.parse(
          MQTTFieldSemantics::Builder.subscribe(:id => 3, :filters => [[filter, 1]])
        )
        expect(subscribe.topics).to eq([[filter, 1]])

        unsubscribe = MQTT::Packet.parse(
          MQTTFieldSemantics::Builder.unsubscribe(:id => 3, :filters => [filter])
        )
        expect(unsubscribe.topics).to eq([filter])
      end
    end

    it 'rejects every illegal wildcard placement on both ends' do
      MQTTFieldSemantics::Atoms::INVALID_FILTERS.each do |filter|
        wire = MQTTFieldSemantics::Builder.subscribe(:id => 1, :filters => [[filter, 0]])
        expect { MQTT::Packet.parse(wire) }.to raise_error(MQTT::ProtocolException)
        expect {
          MQTT::Packet::Subscribe.new(:id => 1, :topics => [[filter, 0]]).to_s
        }.to raise_error(ArgumentError)
      end
    end

    it 'does not treat a closed socket as an empty payload or field' do
      require 'stringio'
      expect {
        MQTT::Packet.read(StringIO.new("\x30\x11".b))
      }.to raise_error(MQTT::ProtocolException, /truncated/)
    end

    it 'rejects a filter packet with an unmatched trailing length prefix' do
      # Body: id=1, filter 'a/b' with QoS 0, then a two-byte length claiming 3
      # bytes that are absent. A receiver must not treat the dangling prefix as
      # an empty filter or silently drop it.
      wire = MQTTFieldSemantics::Builder.fixed_header(
        8, 0x2, "\x00\x01\x00\x03a/b\x00\x00\x03".b
      )
      expect { MQTT::Packet.parse(wire) }.to raise_error(MQTT::ProtocolException)
    end

    it 'keeps a valid wildcard filter and a literal filter distinct' do
      wire = MQTTFieldSemantics::Builder.subscribe(
        :id => 2, :filters => [['a/+/b', 0], ['a/+/b', 2]]
      )
      packet = MQTT::Packet.parse(wire)
      expect(packet.topics).to eq([['a/+/b', 0], ['a/+/b', 2]])
      expect(packet.topics.map(&:first).uniq).to eq(['a/+/b'])
    end

    it 'rejects a mixed filter list without dropping the valid wildcard entry' do
      wire = MQTTFieldSemantics::Builder.subscribe(
        :id => 9, :filters => [['a/+/b', 1], ["bad\xFF".b, 0]]
      )
      expect { MQTT::Packet.parse(wire) }.to raise_error(MQTT::ProtocolException)
    end

    it 'accepts a 65535-byte filter and rejects one byte more' do
      at_limit = MQTTFieldSemantics::Builder.subscribe(
        :id => 1, :filters => [['a' * 65_535, 0]]
      )
      packet = MQTT::Packet.parse(at_limit.dup)
      expect(packet.topics).to eq([['a' * 65_535, 0]])
      expect(packet.to_s.b).to eq(at_limit.b)

      expect {
        MQTT::Packet::Subscribe.new(:topics => [['a' * 65_536, 0]]).to_s
      }.to raise_error(ArgumentError)
    end
  end

  describe 'CONNECT identity fields' do
    it 'rejects NUL in the will topic but allows NUL in the will message' do
      body = "\x00\x04MQTT".b + "\x04\x06".b + "\x00\x0f".b +
             "\x00\x03cid".b + "\x00\x05will\x00".b + "\x00\x02a\x00".b
      wire = MQTTFieldSemantics::Builder.fixed_header(1, 0, body)
      expect { MQTT::Packet.parse(wire) }.to raise_error(MQTT::ProtocolException, /NUL/)

      body = "\x00\x04MQTT".b + "\x04\x06".b + "\x00\x0f".b +
             "\x00\x03cid".b + "\x00\x04will".b + "\x00\x02a\x00".b
      wire = MQTTFieldSemantics::Builder.fixed_header(1, 0, body)
      packet = MQTT::Packet.parse(wire)
      expect(packet.will_payload.b).to eq("a\x00".b)
    end

    it 'rejects bytes after the last CONNECT payload field' do
      body = MQTTFieldSemantics::Builder.connect(:client_id => 'cid').b.byteslice(2..-1)
      wire = MQTTFieldSemantics::Builder.fixed_header(1, 0, body + "\x00".b)
      expect { MQTT::Packet.parse(wire) }.to raise_error(MQTT::ProtocolException)
    end

    it 'treats the password and will message as binary, not text' do
      MQTTFieldSemantics::Atoms::BINARY_PAYLOADS.each_value do |bytes|
        wire = MQTTFieldSemantics::Builder.connect(
          :client_id => 'client', :will_topic => 'will/topic',
          :will_payload => bytes, :username => 'user', :password => bytes
        )
        packet = MQTT::Packet.parse(wire)
        expect(packet.password.b).to eq(bytes.b)
        expect(packet.will_payload.b).to eq(bytes.b)
        expect(packet.password.encoding).to eq(Encoding::ASCII_8BIT)
        expect(packet.will_payload.encoding).to eq(Encoding::ASCII_8BIT)
      end
    end

    it 'accepts a 65535-byte will message and rejects one byte more' do
      at_limit = ("\x00\xFF".b * 32_767) + "\x00".b
      wire = MQTTFieldSemantics::Builder.connect(
        :client_id => 'client', :will_topic => 'will/topic', :will_payload => at_limit
      )
      packet = MQTT::Packet.parse(wire)
      expect(packet.will_payload.b).to eq(at_limit)
      expect(packet.will_payload.bytesize).to eq(65_535)

      expect {
        MQTT::Packet::Connect.new(
          :version => '3.1.1', :client_id => 'client',
          :will_topic => 'will/topic', :will_payload => 'x' * 65_536
        ).to_s
      }.to raise_error(ArgumentError)
    end

    it 'keeps the binary password distinguishable from the UTF-8 username' do
      binary = "\x00\xFF\xFE".b
      wire = MQTTFieldSemantics::Builder.connect(
        :client_id => 'client', :username => 'user', :password => binary
      )
      packet = MQTT::Packet.parse(wire)
      expect(packet.username).to eq('user')
      expect(packet.username.encoding).to eq(Encoding::UTF_8)
      expect(packet.password.b).to eq(binary)
    end

    it 'rejects ill-formed UTF-8 in each identity field on both ends' do
      MQTTFieldSemantics::Atoms::INVALID_TEXT.each do |note, bytes|
        wire = MQTTFieldSemantics::Builder.connect(:client_id => 'client', :username => bytes)
        expect { MQTT::Packet.parse(wire) }.to raise_error(MQTT::ProtocolException), note
        expect {
          MQTT::Packet::Connect.new(:version => '3.1.1', :client_id => 'client', :username => bytes).to_s
        }.to raise_error(ArgumentError), note
      end
    end

    it 'rejects a wildcard will topic but allows a legal filter for a subscription' do
      wire = MQTTFieldSemantics::Builder.connect(
        :client_id => 'client', :will_topic => 'will/#'
      )
      expect { MQTT::Packet.parse(wire) }.to raise_error(MQTT::ProtocolException)
      expect {
        MQTT::Packet::Subscribe.new(:topics => 'will/#').to_s
      }.not_to raise_error
    end

    it 'enforces version-specific client identifier limits' do
      expect {
        MQTT::Packet::Connect.new(
          :version => '3.1.0', :client_id => 'a' * 23
        ).to_s
      }.not_to raise_error
      expect {
        MQTT::Packet::Connect.new(
          :version => '3.1.0', :client_id => 'a' * 24
        ).to_s
      }.to raise_error(ArgumentError)

      wire = MQTTFieldSemantics::Builder.connect(
        :version => '3.1.0', :client_id => 'a' * 24
      )
      expect { MQTT::Packet.parse(wire) }.to raise_error(MQTT::ProtocolException)
    end

    it 'rejects an empty client id when clean session is off' do
      wire = MQTTFieldSemantics::Builder.connect(
        :client_id => '', :clean_session => false
      )
      expect { MQTT::Packet.parse(wire) }.to raise_error(MQTT::ProtocolException)
      expect {
        MQTT::Packet::Connect.new(
          :version => '3.1.1', :client_id => '', :clean_session => false
        ).to_s
      }.to raise_error(ArgumentError)
    end
  end

  describe 'generated independent field combinations' do
    # A deterministic generator: each iteration builds independent logical
    # fields, renders them with the reference Builder, and checks that encode
    # and parse agree with the semantic oracle.
    it 'never accepts on one side what the oracle rejects on the other' do
      random = Random.new(20_261_114)
      text_atoms = [
        'a', 'a/b', '/', 'a//b', 'café', "A\u{2A6D4}",
        '+', '#', 'a/+', 'a/#', 'sport/tennis/+', '/finance',
        '', "a\x00b".b, "\x80".b, "\xC0\xAF".b, "\xED\xA0\x80".b,
        "\xFF".b, "\xF4\x90\x80\x80".b, 'a' * 65_535
      ]

      200.times do
        kind = %i[publish subscribe unsubscribe connect].sample(random: random)
        topic = text_atoms.sample(random: random)

        wire = case kind
               when :publish
                 MQTTFieldSemantics::Builder.publish(:topic => topic, :payload => "\x00\xFF".b)
               when :subscribe
                 MQTTFieldSemantics::Builder.subscribe(:id => 1, :filters => [[topic, 0]])
               when :unsubscribe
                 MQTTFieldSemantics::Builder.unsubscribe(:id => 1, :filters => [topic])
               when :connect
                 MQTTFieldSemantics::Builder.connect(
                   :client_id => 'client', :will_topic => topic, :will_payload => "\x00\xFF".b
                 )
               end

        error = case kind
                when :publish then MQTTFieldSemantics::Oracle.topic_name_error(topic)
                when :subscribe, :unsubscribe then MQTTFieldSemantics::Oracle.topic_filter_error(topic)
                when :connect then MQTTFieldSemantics::Oracle.connect_identity_error(
                  :version => '3.1.1', :client_id => 'client', :clean_session => true,
                  :username => nil, :will_topic => topic
                )
                end

        encoder = case kind
                  when :publish
                    -> { MQTT::Packet::Publish.new(:topic => topic, :payload => "\x00\xFF".b).to_s }
                  when :subscribe
                    -> { MQTT::Packet::Subscribe.new(:id => 1, :topics => [topic]).to_s }
                  when :unsubscribe
                    -> { MQTT::Packet::Unsubscribe.new(:id => 1, :topics => [topic]).to_s }
                  when :connect
                    -> {
                      MQTT::Packet::Connect.new(
                        :version => '3.1.1', :client_id => 'client',
                        :will_topic => topic, :will_payload => "\x00\xFF".b
                      ).to_s
                    }
                  end

        if error.nil?
          expect { MQTT::Packet.parse(wire) }.not_to raise_error, "parse: #{error}"
          expect { encoder.call }.not_to raise_error, "encode: #{error}"
        else
          expect { MQTT::Packet.parse(wire) }.to raise_error(MQTT::ProtocolException), error
          expect { encoder.call }.to raise_error(ArgumentError), error
        end
      end
    end

    it 'replays the smallest rejected input to reproduce the same rejection' do
      rejected = CORPUS.select { |entry| entry['expect']['parse'] == 'reject' && entry['wire_hex'] }
      expect(rejected).not_to be_empty

      rejected.first(40).each do |entry|
        wire = [entry['wire_hex']].pack('H*')
        errors = 3.times.map do
          begin
            MQTT::Packet.parse(wire.dup)
            nil
          rescue MQTT::ProtocolException => exp
            exp.message
          end
        end
        expect(errors.uniq.compact.length).to eq(1), "#{entry['id']} is not deterministic"
        expect(errors.first).not_to be_nil, "#{entry['id']} unexpectedly parsed"
        expect(wire.bytesize).to be > 0
      end
    end
  end
end
