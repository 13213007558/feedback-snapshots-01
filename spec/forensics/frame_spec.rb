# encoding: BINARY

$LOAD_PATH.unshift(File.expand_path('../../../lib', __dir__))
$LOAD_PATH.unshift(File.expand_path('../..', __FILE__))

require 'spec_helper'
require 'mqtt/forensics'

module MQTT
  module Forensics
    describe FrameSplitter do
      let(:connect) do
        MQTT::Packet::Connect.new(:client_id => 'c1', :version => '3.1.1').to_s.b
      end

      let(:pingreq) { MQTT::Packet::Pingreq.new.to_s.b }

      it 'decodes a complete single-fragment packet' do
        splitter = FrameSplitter.new(:client)
        frames = splitter.push(Fragment.new(:client, connect, nil, 'f0'))
        expect(frames.size).to eq(1)
        expect(frames.first.packet).to be_a(MQTT::Packet::Connect)
        expect(frames.first.type_name).to eq('CONNECT')
        expect(frames.first.byte_offset).to eq(0)
      end

      it 'reassembles a packet split across arbitrary byte boundaries' do
        splitter = FrameSplitter.new(:client)
        produced = []
        connect.bytes.each_slice(2).with_index do |slice, idx|
          produced.concat(splitter.push(Fragment.new(:client, slice.pack('C*'), nil, "f#{idx}")))
        end
        expect(produced.size).to eq(1)
        expect(produced.first.packet).to be_a(MQTT::Packet::Connect)
      end

      it 'decodes several packets sharing one fragment' do
        splitter = FrameSplitter.new(:broker)
        frames = splitter.push(Fragment.new(:broker, pingreq + pingreq, nil, 'f0'))
        # pingreq bytes are identical and legal from either splitter here
        expect(frames.size).to eq(2)
        expect(frames.map(&:byte_offset)).to eq([0, pingreq.bytesize])
      end

      it 'withholds a frame until the full body arrives' do
        splitter = FrameSplitter.new(:client)
        expect(splitter.push(Fragment.new(:client, connect.byteslice(0, 3), nil, 'a'))).to be_empty
        frames = splitter.push(Fragment.new(:client, connect.byteslice(3..-1), nil, 'b'))
        expect(frames.size).to eq(1)
        expect(frames.first.complete?).to be(true)
      end

      it 'emits a malformed frame for a truncated trailing stream on flush' do
        splitter = FrameSplitter.new(:client)
        splitter.push(Fragment.new(:client, connect.byteslice(0, 4), nil, 'a'))
        frames = splitter.flush
        expect(frames.size).to eq(1)
        expect(frames.first.parse_error?).to be(true)
        expect(frames.first.type_name).to eq('MALFORMED')
        expect(frames.first.parse_error).to include('truncated')
      end

      it 'rejects a reserved control packet type' do
        splitter = FrameSplitter.new(:client)
        frames = splitter.push(Fragment.new(:client, "\xF0\x00".b, nil, 'bad'))
        expect(frames.size).to eq(1)
        expect(frames.first.parse_error?).to be(true)
        expect(frames.first.parse_error).to include('forbidden control packet type')
        splitter.flush
        expect(splitter.frames.size).to eq(1) # no double registration
      end

      it 'registers an invalid remaining-length frame exactly once' do
        splitter = FrameSplitter.new(:broker)
        splitter.push(Fragment.new(:broker, "\x10\x80\x80\x80\x80\x00".b, nil, 'bad'))
        splitter.flush
        expect(splitter.frames.size).to eq(1)
        expect(splitter.frames.first.parse_error).to include('remaining-length')
      end

      it 'records provenance spanning multiple fragments' do
        splitter = FrameSplitter.new(:client)
        connect.bytes.each_slice(3).with_index do |slice, idx|
          splitter.push(Fragment.new(:client, slice.pack('C*'), nil, "src-#{idx}"))
        end
        frame = splitter.frames.first
        sources = frame.fragments.map { |prov| prov[:source] }
        expect(sources).to include('src-0', 'src-1')
        total = frame.fragments.sum { |prov| prov[:length] }
        expect(total).to eq(frame.raw.bytesize)
      end
    end

    describe Fragment do
      it 'forces binary encoding and rejects unknown directions' do
        fragment = Fragment.new(:client, 'abc')
        expect(fragment.bytes.encoding.to_s).to eq('ASCII-8BIT')
        expect(fragment.bytesize).to eq(3)
        expect { Fragment.new(:sideways, 'x') }.to raise_error(ArgumentError)
      end
    end
  end
end
