# encoding: BINARY

$LOAD_PATH.unshift(File.expand_path('../../../lib', __dir__))
$LOAD_PATH.unshift(File.expand_path('../..', __FILE__))

require 'spec_helper'
require 'mqtt/forensics'

module MQTT
  module Forensics
    describe Analyzer do
      def wire(packet)
        packet.to_s.dup.force_encoding('ASCII-8BIT')
      end

      def capture_from(client_packets, broker_packets, client_chunk = 4, broker_chunk = 4)
        capture = Capture.new
        blob(client_packets, client_chunk).each_with_index do |bytes, idx|
          capture.add(:client, bytes, nil, "c#{idx}")
        end
        blob(broker_packets, broker_chunk).each_with_index do |bytes, idx|
          capture.add(:broker, bytes, nil, "b#{idx}")
        end
        capture
      end

      def blob(packets, chunk)
        packets.map { |p| wire(p) }.join.bytes.each_slice(chunk).map { |s| s.pack('C*') }
      end

      def codes(report)
        report.findings.map(&:code)
      end

      def find(report, code)
        report.findings.find { |f| f.code == code }
      end

      describe 'clean session' do
        it 'reports no violations or gaps for a complete QoS1 exchange' do
          report = Analyzer.new(capture_from(
            [
              MQTT::Packet::Connect.new(:client_id => 'd', :username => 'u', :version => '3.1.1'),
              MQTT::Packet::Subscribe.new(:id => 1, :topics => { 't' => 1 }),
              MQTT::Packet::Publish.new(:id => 9, :qos => 1, :topic => 't', :payload => 'v'),
              MQTT::Packet::Disconnect.new
            ],
            [
              MQTT::Packet::Connack.new(:return_code => 0),
              MQTT::Packet::Suback.new(:id => 1, :return_codes => [1]),
              MQTT::Packet::Puback.new(:id => 9)
            ]
          )).analyze

          expect(report.violations).to be_empty
          expect(report.gaps).to be_empty
          expect(report.events.map(&:kind)).to include('CONNECT', 'CONNACK', 'SUBSCRIBE', 'SUBACK',
                                                       'PUBLISH', 'PUBACK', 'DISCONNECT')
        end
      end

      describe 'duplicate acknowledgements' do
        it 'flags a repeated PUBACK as a proven violation' do
          report = Analyzer.new(capture_from(
            [MQTT::Packet::Publish.new(:id => 5, :qos => 1, :topic => 't', :payload => 'x')],
            [MQTT::Packet::Puback.new(:id => 5), MQTT::Packet::Puback.new(:id => 5)]
          )).analyze
          finding = find(report, 'DUPLICATE_ACK')
          expect(finding.severity).to eq(:violation)
          expect(finding.status).to eq('proven')
          expect(finding.refs.size).to eq(2)
        end

        it 'flags duplicate steps in a QoS2 handshake' do
          report = Analyzer.new(capture_from(
            [MQTT::Packet::Publish.new(:id => 7, :qos => 2, :topic => 't', :payload => 'x'),
             MQTT::Packet::Pubrel.new(:id => 7)],
            [MQTT::Packet::Pubrec.new(:id => 7), MQTT::Packet::Pubrec.new(:id => 7),
             MQTT::Packet::Pubcomp.new(:id => 7)]
          )).analyze
          expect(find(report, 'DUPLICATE_ACK').message).to include('PUBREC')
        end
      end

      describe 'unsolicited responses' do
        it 'treats a PUBACK without a PUBLISH as unproven, not an attack' do
          report = Analyzer.new(capture_from(
            [],
            [MQTT::Packet::Puback.new(:id => 99)]
          )).analyze
          finding = find(report, 'UNSOLICITED_ACK')
          expect(finding.severity).to eq(:evidence)
          expect(finding.status).to eq('unproven')
        end

        it 'marks a SUBACK with no SUBSCRIBE as unproven' do
          report = Analyzer.new(capture_from(
            [],
            [MQTT::Packet::Suback.new(:id => 3, :return_codes => [0])]
          )).analyze
          expect(find(report, 'UNSOLICITED_SUBACK').status).to eq('unproven')
        end

        it 'counts an unmatched PINGRESP as unproven' do
          report = Analyzer.new(capture_from(
            [],
            [MQTT::Packet::Pingresp.new]
          )).analyze
          expect(find(report, 'UNSOLICITED_PINGRESP').status).to eq('unproven')
        end
      end

      describe 'capture gaps' do
        it 'reports NO_CONNECT when the capture starts mid-session' do
          report = Analyzer.new(capture_from(
            [MQTT::Packet::Publish.new(:topic => 't', :payload => 'q', :qos => 0)],
            []
          )).analyze
          expect(find(report, 'NO_CONNECT').severity).to eq(:gap)
        end

        it 'records a missing SUBACK as a gap rather than a violation' do
          report = Analyzer.new(capture_from(
            [MQTT::Packet::Connect.new(:client_id => 'd', :version => '3.1.1'),
             MQTT::Packet::Subscribe.new(:id => 2, :topics => { 't' => 0 })],
            [MQTT::Packet::Connack.new(:return_code => 0)]
          )).analyze
          expect(find(report, 'SUBACK_MISSING').severity).to eq(:gap)
        end

        it 'records an incomplete QoS2 handshake as a gap' do
          report = Analyzer.new(capture_from(
            [MQTT::Packet::Publish.new(:id => 8, :qos => 2, :topic => 't', :payload => 'x')],
            [MQTT::Packet::Pubrec.new(:id => 8)]
          )).analyze
          finding = find(report, 'QOS2_INCOMPLETE')
          expect(finding.severity).to eq(:gap)
          expect(finding.message).to include('PUBREL', 'PUBCOMP')
        end

        it 'does not flag a complete QoS2 flow as missing anything' do
          report = Analyzer.new(capture_from(
            [MQTT::Packet::Publish.new(:id => 8, :qos => 2, :topic => 't', :payload => 'x'),
             MQTT::Packet::Pubrel.new(:id => 8)],
            [MQTT::Packet::Pubrec.new(:id => 8), MQTT::Packet::Pubcomp.new(:id => 8)]
          )).analyze
          expect(codes(report)).not_to include('QOS2_INCOMPLETE')
        end
      end

      describe 'truncation and malformed input' do
        it 'surfaces a truncated final frame as evidence without crashing' do
          capture = Capture.new
          full = wire(MQTT::Packet::Connect.new(:client_id => 'd', :version => '3.1.1'))
          capture.add(:client, full.byteslice(0, 5), nil, 'partial')
          report = Analyzer.new(capture).analyze
          expect(find(report, 'MALFORMED_FRAME').severity).to eq(:evidence)
          expect(report.events.map(&:kind)).to include('MALFORMED')
        end
      end

      describe 'identity handling' do
        it 'never treats a declared username as an authenticated identity' do
          report = Analyzer.new(capture_from(
            [MQTT::Packet::Connect.new(:client_id => 'd', :username => 'root', :version => '3.1.1')],
            [MQTT::Packet::Connack.new(:return_code => 0)]
          )).analyze
          hash = report.to_h
          expect(hash['identity']['username']).to eq('root')
          expect(hash['identity']['state']).to eq('declared_only')
          expect(hash['identity']['authentication_note']).to include('declaration')
        end

        it 'reports identity as unknown when no CONNECT is present' do
          report = Analyzer.new(capture_from(
            [MQTT::Packet::Pingreq.new],
            []
          )).analyze
          expect(report.to_h['identity']['state']).to eq('unknown')
        end
      end

      describe 'traceability' do
        it 'gives every event a frame reference and provenance' do
          report = Analyzer.new(capture_from(
            [MQTT::Packet::Connect.new(:client_id => 'd', :version => '3.1.1')],
            [MQTT::Packet::Connack.new(:return_code => 0)]
          )).analyze
          report.to_h['timeline'].each do |event|
            expect(event['frame_ref']).not_to be_nil
            expect(event['provenance']).not_to be_empty
          end
        end
      end

      describe 'empty and illegal input' do
        it 'reports EMPTY_CAPTURE instead of inventing a session when no frames exist' do
          report = Analyzer.new(Capture.new).analyze
          expect(report.events).to be_empty
          expect(find(report, 'EMPTY_CAPTURE').severity).to eq(:gap)
          expect(codes(report)).not_to include('NO_CONNECT')
        end

        it 'flags a control packet sent from the illegal endpoint' do
          report = Analyzer.new(capture_from(
            [MQTT::Packet::Connack.new(:return_code => 0)],
            []
          )).analyze
          expect(find(report, 'WRONG_DIRECTION').severity).to eq(:violation)
        end

        it 'does not expect an acknowledgement for a QoS 0 publish' do
          report = Analyzer.new(capture_from(
            [MQTT::Packet::Publish.new(:topic => 't', :payload => 'x', :qos => 0)],
            []
          )).analyze
          expect(codes(report)).not_to include('QOS1_NO_ACK', 'QOS2_INCOMPLETE')
        end
      end
    end
  end
end
