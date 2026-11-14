# encoding: BINARY

require 'mqtt'
require 'mqtt/forensics/capture'

module MQTT
  module Forensics
    # Generates a deterministic, deliberately imperfect synthetic capture used
    # to demonstrate the analyser without any network access. It intentionally
    # contains:
    #   * a clean CONNECT/CONNACK and SUBSCRIBE/SUBACK pair,
    #   * a fully completed QoS 2 publish handshake,
    #   * a duplicated PUBACK (provable protocol violation),
    #   * an unsolicited PINGRESP whose request is absent,
    #   * a truncated trailing frame (capture cut mid-packet),
    #   * arbitrary fragmentation on both directions.
    module Demo
      module_function

      def packet_bytes(packet)
        packet.to_s.dup.force_encoding('ASCII-8BIT')
      end

      def build_capture
        client = ''.b
        broker = ''.b

        client << packet_bytes(MQTT::Packet::Connect.new(
          :client_id => 'sensor-7', :username => 'maint', :clean_session => false,
          :keep_alive => 30, :version => '3.1.1'
        ))
        broker << packet_bytes(MQTT::Packet::Connack.new(:return_code => 0, :session_present => true))

        client << packet_bytes(MQTT::Packet::Subscribe.new(
          :id => 100, :topics => { 'factory/line1/+' => 1 }
        ))
        broker << packet_bytes(MQTT::Packet::Suback.new(:id => 100, :return_codes => [1]))

        # QoS 2 flow, broker is the publisher (id 200)
        broker << packet_bytes(MQTT::Packet::Publish.new(
          :id => 200, :qos => 2, :topic => 'factory/line1/temp', :payload => '47.1'
        ))
        client << packet_bytes(MQTT::Packet::Pubrec.new(:id => 200))
        broker << packet_bytes(MQTT::Packet::Pubrel.new(:id => 200))
        client << packet_bytes(MQTT::Packet::Pubcomp.new(:id => 200))

        # QoS 1 publish from client, then a duplicated broker PUBACK
        client << packet_bytes(MQTT::Packet::Publish.new(
          :id => 300, :qos => 1, :topic => 'factory/line1/cmd', :payload => 'stop'
        ))
        broker << packet_bytes(MQTT::Packet::Puback.new(:id => 300))
        broker << packet_bytes(MQTT::Packet::Puback.new(:id => 300))

        # Unsolicited PINGRESP (no PINGREQ present in the capture)
        broker << packet_bytes(MQTT::Packet::Pingresp.new)

        # Truncated trailing client frame: a valid DISCONNECT header whose body
        # length announces more bytes than were captured.
        client << packet_bytes(MQTT::Packet::Disconnect.new).slice(0, 1)

        capture = Capture.new
        fragment_bytes(client, 7).each_with_index do |bytes, idx|
          capture.add(:client, bytes, 1000.0 + idx, "demo/client-#{idx}")
        end
        fragment_bytes(broker, 5).each_with_index do |bytes, idx|
          capture.add(:broker, bytes, 1000.5 + idx, "demo/broker-#{idx}")
        end
        capture
      end

      # Split a byte string into fixed-size chunks to emulate arbitrary
      # wire-level fragmentation with no packet-boundary alignment.
      def fragment_bytes(bytes, chunk_size)
        bytes.bytes.each_slice(chunk_size).map { |slice| slice.pack('C*') }
      end
    end
  end
end
