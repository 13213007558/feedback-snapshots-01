# encoding: BINARY

$LOAD_PATH.unshift(File.expand_path('../../../lib', __dir__))
$LOAD_PATH.unshift(File.expand_path('../..', __FILE__))

require 'spec_helper'
require 'mqtt/forensics'
require 'tempfile'

module MQTT
  module Forensics
    describe Loader do
      let(:connect_hex) do
        MQTT::Packet::Connect.new(:client_id => 'loader', :version => '3.1.1').to_s.b.unpack1('H*')
      end

      def write_temp(name, content)
        path = File.join(Dir.tmpdir, "mqtt-forensics-#{$$}-#{name}")
        File.binwrite(path, content)
        path
      end

      it 'loads a JSON document of hex fragments and reassembles packets' do
        json = JSON.generate('fragments' => [
          { 'direction' => 'client', 'encoding' => 'hex', 'data' => connect_hex, 'source' => 'c0' }
        ])
        path = write_temp('frag.json', json)
        capture = Loader.load(path)
        report = Analyzer.new(capture).analyze
        expect(report.events.map(&:kind)).to include('CONNECT')
      end

      it 'loads JSON Lines with one fragment per line' do
        lines = [
          JSON.generate('direction' => 'client', 'encoding' => 'hex',
                        'data' => connect_hex[0, 10], 'source' => 'a'),
          JSON.generate('direction' => 'client', 'encoding' => 'hex',
                        'data' => connect_hex[10..-1], 'source' => 'b')
        ]
        path = write_temp('frag.jsonl', lines.join("\n"))
        report = Analyzer.new(Loader.load(path)).analyze
        expect(report.events.map(&:kind)).to include('CONNECT')
      end

      it 'defaults to hex when no encoding is given' do
        json = JSON.generate('fragments' => [
          { 'direction' => 'broker', 'data' => MQTT::Packet::Pingresp.new.to_s.b.unpack1('H*') }
        ])
        path = write_temp('default.json', json)
        report = Analyzer.new(Loader.load(path)).analyze
        expect(report.events.map(&:kind)).to include('PINGRESP')
      end

      it 'decodes binary data passed straight to the Capture API' do
        capture = Capture.new
        capture.add(:broker, MQTT::Packet::Pingresp.new.to_s.b, nil, 'raw')
        report = Analyzer.new(capture).analyze
        expect(report.events.map(&:kind)).to include('PINGRESP')
      end

      it 'rejects an unknown direction' do
        expect { Loader.resolve_direction('mystery') }.to raise_error(ArgumentError)
      end

      it 'rejects hex with an odd number of nibbles' do
        expect { Loader.decode('hex', 'abc') }.to raise_error(ArgumentError)
      end
    end

    describe Demo do
      it 'builds a fragmented capture containing the intended anomaly mix' do
        report = Analyzer.new(Demo.build_capture).analyze
        codes = report.findings.map(&:code)
        expect(codes).to include('DUPLICATE_ACK')
        expect(codes).to include('UNSOLICITED_PINGRESP')
        expect(codes).to include('MALFORMED_FRAME')
        # a complete QoS2 handshake must not be misreported
        expect(codes).not_to include('QOS2_INCOMPLETE')
      end
    end
  end
end
