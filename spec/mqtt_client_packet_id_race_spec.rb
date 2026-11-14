# encoding: BINARY

$:.unshift(File.dirname(__FILE__))

require 'spec_helper'
require 'mqtt'

# End-to-end checks for ownership of the shared packet identifier space.
# The space is deliberately shrunk to a handful of identifiers so that wrap
# around, exhaustion and late acknowledgements can be driven deterministically
# without any real network connection.
describe MQTT::Client do
  let(:socket) { StringIO.new.tap { |io| io.set_encoding('binary') if io.respond_to?(:set_encoding) } }
  let(:client) do
    client = MQTT::Client.new(:host => 'localhost', :ack_timeout => 5, :keep_alive => 0)
    client.packet_id_space = MQTT::Client::PacketIdSpace.new(2)
    client.instance_variable_set('@socket', socket)
    client
  end

  def run_async
    thread = Thread.new { yield }
    Thread.pass until thread.status == 'sleep'
    thread
  end

  def wait_until(timeout = 2)
    deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + timeout
    loop do
      result = yield
      return result if result
      raise 'condition not met in time' if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
      Thread.pass
    end
  end

  describe 'wrap-around against an in-flight request' do
    it 'never reuses an identifier still owned by another request' do
      first = run_async { client.publish('safety/door', 'locked', false, 1) }
      wait_until { client.packet_id_space.in_flight?(1) }

      second = run_async { client.publish('safety/alarm', 'armed', false, 1) }
      wait_until { client.packet_id_space.in_flight?(2) }

      # Both identifiers are owned; a third request must fail loudly instead
      # of overwriting one of the waiting requests.
      expect { client.publish('safety/flood', 'wet', false, 1) }
        .to raise_error(MQTT::Client::PacketIdExhausted)
      expect(client.packet_id_space.in_flight_count).to eq(2)

      client.send(:handle_packet, MQTT::Packet::Puback.new(:id => 1))
      client.send(:handle_packet, MQTT::Packet::Puback.new(:id => 2))
      expect(first.value).to be_a(Integer)
      expect(second.value).to be_a(Integer)
      expect(client.packet_id_space.in_flight_count).to eq(0)
    end

    it 'wraps to a freed identifier and only accepts its matching acknowledgement' do
      first = run_async { client.publish('safety/door', 'locked', false, 1) }
      wait_until { client.packet_id_space.in_flight?(1) }
      second = run_async { client.publish('safety/alarm', 'armed', false, 1) }
      wait_until { client.packet_id_space.in_flight?(2) }

      # Complete the first request so identifier 1 can wrap around.
      client.send(:handle_packet, MQTT::Packet::Puback.new(:id => 1))
      wait_until { !first.alive? }

      third = run_async { client.publish('safety/fire', 'smoke', false, 1) }
      wait_until { client.packet_id_space.in_flight?(1) }
      expect(third).to be_alive

      # An acknowledgement of the wrong operation for id 1 must not complete
      # the new publish (it owns a PUBLISH, expecting a PUBACK).
      client.send(:handle_packet, MQTT::Packet::Suback.new(:id => 1, :return_codes => 0))
      sleep 0.1
      expect(third).to be_alive
      expect(client.packet_id_space.in_flight?(1)).to be(true)

      client.send(:handle_packet, MQTT::Packet::Puback.new(:id => 1))
      wait_until { !third.alive? }

      client.send(:handle_packet, MQTT::Packet::Puback.new(:id => 2))
      expect(second.value).to be_a(Integer)
      expect(third.value).to be_a(Integer)
    end
  end

  describe 'a late acknowledgement' do
    it 'cannot report success for a different safety notification' do
      # The first publish times out and gives up on identifier 1.
      client.ack_timeout = 0.2
      timed_out = client.publish('safety/gas', 'leak', false, 1)
      expect(timed_out).to eq(-1)
      expect(client.packet_id_space.quarantined?(1)).to be(true)

      # Hold identifier 2 so that freeing identifier 1 makes the next
      # allocation wrap around onto it rather than simply taking id 2.
      holder = run_async { client.publish('safety/intrusion', 'motion', false, 1) }
      wait_until { client.packet_id_space.in_flight?(2) }

      # The stale PUBACK arrives after the timeout: it is swallowed and only
      # clears the quarantine, it never resolves a request as successful.
      expect(client.send(:handle_packet, MQTT::Packet::Puback.new(:id => 1))).to be(false)
      expect(client.packet_id_space.quarantined?(1)).to be(false)

      # A fresh subscribe now wraps onto the recovered identifier 1.
      subscribe = run_async { client.subscribe('safety/+/event') }
      wait_until { client.packet_id_space.in_flight?(1) }

      # A duplicate/late PUBACK for the same identifier must not complete the
      # subscribe; the live subscribe keeps ownership until its SUBACK arrives.
      client.send(:handle_packet, MQTT::Packet::Puback.new(:id => 1))
      sleep 0.1
      expect(subscribe).to be_alive
      expect(client.packet_id_space.in_flight?(1)).to be(true)

      client.send(:handle_packet, MQTT::Packet::Suback.new(:id => 1, :return_codes => 0))
      wait_until { !subscribe.alive? }
      expect(subscribe.value).to be(true)

      client.send(:handle_packet, MQTT::Packet::Puback.new(:id => 2))
      expect(holder.value).to be_a(Integer)
    end
  end

  describe 'send failures' do
    it 'release the reserved identifier so it stays allocatable' do
      allow(client).to receive(:connected?).and_return(false)
      expect { client.publish('safety/door', 'locked', false, 1) }
        .to raise_error(MQTT::NotConnectedException)
      expect(client.packet_id_space.in_flight_count).to eq(0)
      expect(client.packet_id_space.quarantined_count).to eq(1)

      # A reconnect clears the quarantine and the identifier is usable again.
      client.packet_id_space.reset
      id, = client.packet_id_space.reserve(:publish)
      expect(id).to eq(1)
    end

    it 'propagates the write error without leaving the request waiting' do
      allow(client).to receive(:connected?).and_return(true)
      allow(client).to receive(:send_packet).and_raise(IOError, 'broken pipe')
      expect { client.subscribe('a/b') }.to raise_error(IOError, 'broken pipe')
      expect(client.packet_id_space.in_flight_count).to eq(0)
    end
  end

  describe 'disconnect' do
    it 'isolates every waiting request and clears the quarantine on reconnect' do
      publish = run_async { client.publish('safety/door', 'locked', false, 1) }
      subscribe = run_async { client.subscribe('safety/alarm') }
      wait_until { client.packet_id_space.in_flight_count == 2 }

      client.disconnect(false)

      expect(publish.value).to eq(-1)
      expect(subscribe.value).to be(false)
      expect(client.packet_id_space.in_flight_count).to eq(0)
      expect(client.packet_id_space.quarantined_count).to eq(2)

      # Late acks from the dead connection cannot complete anything.
      expect(client.send(:handle_packet, MQTT::Packet::Puback.new(:id => 1))).to be(false)
      expect(client.send(:handle_packet, MQTT::Packet::Suback.new(:id => 2, :return_codes => 0))).to be(false)

      # A fresh connection starts with an empty, fully allocatable space.
      client.packet_id_space.reset
      expect(client.packet_id_space.quarantined_count).to eq(0)
      expect(client.packet_id_space.reserve(:publish).first).to eq(1)
    end
  end
end
