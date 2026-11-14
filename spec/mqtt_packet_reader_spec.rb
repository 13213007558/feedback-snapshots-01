# encoding: BINARY
#
# Tests for the buffered, timeout-aware MQTT::PacketReader.
#
# Nothing here really waits on the network: a controllable fake clock is
# advanced whenever IO.select would block, and the socket only hands out the
# next pre-scripted chunk once that (stubbed) select has "woken" it.

$:.unshift(File.dirname(__FILE__))

require 'spec_helper'
require 'mqtt'

# A socket that serves a queue of chunks one at a time. After handing out a
# chunk it blocks again until release is called, so every chunk models a real
# wake-up of the socket. A chunk of +nil+ models EOF; close?/close model the
# connection being torn down.
class GatedSocket
  def initialize(chunks = [])
    @chunks = chunks
    @blocked = false
    @closed = false
  end

  # Make the next queued chunk available (optionally queueing a new one first).
  def release(chunk = :none)
    @chunks << chunk unless chunk == :none
    @blocked = false
  end

  def closed?
    @closed
  end

  def close
    @closed = true
  end

  def read_nonblock(_max, exception: false)
    raise IOError, 'stream was closed' if @closed
    return :wait_readable if @blocked || @chunks.empty?

    @blocked = true
    @chunks.shift
  end
end

describe MQTT::PacketReader do
  # A QoS 0 publish packet (topic "test", payload "hello world"), 19 bytes.
  let(:full_packet) { "\x30\x11\x00\x04testhello world".b }

  # Build a reader driven by a controllable clock. The returned callable
  # advances the fake clock by a number of (fake) seconds.
  def build_reader(socket, idle: nil, packet: nil)
    time = 0.0
    reader = MQTT::PacketReader.new(
      socket,
      :read_idle_timeout => idle,
      :packet_timeout => packet,
      :select_timeout => 0.5
    ) { time }
    [reader, ->(seconds) { time += seconds }]
  end

  # Stub a blocking IO.select: advance the fake clock by +wait+ seconds, then
  # wake the socket so its next queued chunk becomes readable.
  def stub_select(socket, advance, wait)
    allow(IO).to receive(:select) do |_reads, _writes, _errors, _timeout|
      advance.call(wait)
      socket.release
      [[socket], [], []]
    end
  end

  # Stub a blocking IO.select that never receives any more data, simply
  # advancing the fake clock each time it is called.
  def stub_quiet_select(advance, wait)
    allow(IO).to receive(:select) do |_reads, _writes, _errors, _timeout|
      advance.call(wait)
      nil
    end
  end

  it 'reads a complete packet delivered in one chunk' do
    socket = GatedSocket.new([full_packet])
    reader, = build_reader(socket)
    packet = reader.read
    expect(packet).to be_a(MQTT::Packet::Publish)
    expect(packet.topic).to eq('test')
    expect(packet.payload).to eq('hello world')
  end

  it 'tolerates normal short reads spread across many calls' do
    socket = GatedSocket.new(full_packet.bytes.map { |byte| byte.chr })
    reader, advance = build_reader(socket)
    stub_select(socket, advance, 0.0)

    packet = reader.read
    expect(packet).to be_a(MQTT::Packet::Publish)
    expect(packet.payload).to eq('hello world')
  end

  it 'returns several complete packets from one continuous stream' do
    socket = GatedSocket.new([full_packet * 3])
    reader, = build_reader(socket)
    packets = Array.new(3) { reader.read }
    expect(packets.map(&:class)).to eq([MQTT::Packet::Publish] * 3)
    expect(packets.map(&:payload)).to eq(['hello world'] * 3)
  end

  it 'returns complete packets one at a time as bytes trickle in' do
    socket = GatedSocket.new([full_packet])
    reader, advance = build_reader(socket)
    stub_select(socket, advance, 0.0)

    expect(reader.read.payload).to eq('hello world')

    socket.release(full_packet)
    expect(reader.read.payload).to eq('hello world')
  end

  it 'raises when no further byte arrives before the reading-progress deadline' do
    # One header byte arrives, then the stream stays quiet forever.
    socket = GatedSocket.new(["\x30".b])
    reader, advance = build_reader(socket, :idle => 5.0, :packet => 100.0)
    stub_quiet_select(advance, 2.0)

    expect { reader.read }.to raise_error(
      MQTT::ProtocolException,
      'Timed out waiting for packet data after 5.0 seconds'
    )
  end

  it 'keeps accepting a packet while bytes keep making reading progress' do
    # A blocking wait (4 fake seconds) before every single byte. The 5 second
    # idle limit is never hit and the total assembly budget is generous.
    socket = GatedSocket.new(full_packet.bytes.map { |byte| byte.chr })
    reader, advance = build_reader(socket, :idle => 5.0, :packet => 100.0)
    stub_select(socket, advance, 4.0)

    packet = reader.read
    expect(packet).to be_a(MQTT::Packet::Publish)
    expect(packet.payload).to eq('hello world')
  end

  it 'raises when one packet cannot be assembled before the whole-packet deadline' do
    # Steady 6 second progress beats the 10 second idle limit, yet the 19 byte
    # packet cannot finish within the 10 second total assembly budget.
    socket = GatedSocket.new(full_packet.bytes.map { |byte| byte.chr })
    reader, advance = build_reader(socket, :idle => 10.0, :packet => 10.0)
    stub_select(socket, advance, 6.0)

    expect { reader.read }.to raise_error(
      MQTT::ProtocolException,
      'Timed out waiting for a complete packet after 10.0 seconds'
    )
  end

  it 'gives every packet a fresh whole-packet deadline' do
    # Each 19 byte packet takes 18 waits of 0.5s = 9 fake seconds, inside its
    # own 10 second budget. The two packets together take 18 seconds, which a
    # single global (non resetting) 10 second deadline would reject. The
    # second packet must still succeed because the deadline resets per packet.
    chunks = full_packet.bytes.map { |byte| byte.chr }
    socket = GatedSocket.new(chunks + chunks)
    reader, advance = build_reader(socket, :idle => 10.0, :packet => 10.0)
    stub_select(socket, advance, 0.5)

    expect(reader.read.payload).to eq('hello world')
    expect(reader.read.payload).to eq('hello world')
  end

  it 'raises on EOF in the middle of a packet' do
    socket = GatedSocket.new(["\x30\x11\x00\x04te".b, nil])
    reader, advance = build_reader(socket)
    stub_select(socket, advance, 0.0)

    expect { reader.read }.to raise_error(
      MQTT::ProtocolException,
      'Failed to read byte from socket'
    )
  end

  it 'returns nil on a clean EOF at a packet boundary' do
    socket = GatedSocket.new([nil])
    reader, = build_reader(socket)
    expect(reader.read).to be_nil
  end

  it 'discards buffered half-packet bytes when reset is called' do
    socket = GatedSocket.new(["\x30".b])
    reader, advance = build_reader(socket, :idle => 1.0)
    stub_quiet_select(advance, 2.0)

    expect { reader.read }.to raise_error(MQTT::ProtocolException)
    expect(reader.instance_variable_get(:@buffer)).not_to be_empty

    reader.reset
    expect(reader.instance_variable_get(:@buffer)).to be_empty
  end
end
