# encoding: BINARY

$:.unshift(File.dirname(__FILE__))

require 'spec_helper'
require 'mqtt'

describe MQTT::Client::PacketIdSpace do
  # A deliberately tiny space so wrap-around, exhaustion and quarantining can
  # be exercised without allocating 65535 requests.
  let(:space) { described_class.new(3) }

  describe '#reserve' do
    it 'hands out identifiers starting at one' do
      id, = space.reserve(:publish)
      expect(id).to eq(1)
    end

    it 'shares the one space between publish, subscribe and unsubscribe' do
      ids = []
      ids << space.reserve(:publish).first
      ids << space.reserve(:subscribe).first
      ids << space.reserve(:unsubscribe).first
      expect(ids).to eq([1, 2, 3])
      expect(space.in_flight_count).to eq(3)
    end

    it 'records the owning operation for every identifier' do
      id, entry = space.reserve(:subscribe)
      expect(entry.operation).to eq(:subscribe)
      expect(space.in_flight[id].operation).to eq(:subscribe)
    end

    it 'wraps around instead of handing out an in-flight identifier' do
      first = space.reserve(:publish).first
      space.reserve(:publish)
      space.reserve(:publish)
      expect { space.reserve(:publish) }.to raise_error(MQTT::Client::PacketIdExhausted)

      # Free the middle identifier; the next allocation must pick that one and
      # never the identifier still owned by the first request.
      space.acknowledge(MQTT::Packet::Puback.new(:id => 2))
      reused, = space.reserve(:publish)
      expect(reused).to eq(2)
      expect(space.in_flight?(first)).to be(true)
    end

    it 'raises rather than overwriting a request when the space is exhausted' do
      entries = 3.times.map { space.reserve(:publish) }
      expect { space.reserve(:publish) }.to raise_error(MQTT::Client::PacketIdExhausted)
      expect(space.in_flight_count).to eq(3)
      expect(entries.map { |id, _| space.in_flight?(id) }).to all(eq(true))
    end
  end

  describe '#acknowledge' do
    it 'completes only the request matching identifier and operation' do
      pub_id, pub_entry = space.reserve(:publish)
      sub_id, sub_entry = space.reserve(:subscribe)

      # A SUBACK for the publish identifier must not complete the publish.
      expect(space.acknowledge(MQTT::Packet::Suback.new(:id => pub_id, :return_codes => 0))).to be(false)
      expect(space.in_flight?(pub_id)).to be(true)

      # A PUBACK for the subscribe identifier must not complete the subscribe.
      expect(space.acknowledge(MQTT::Packet::Puback.new(:id => sub_id))).to be(false)
      expect(space.in_flight?(sub_id)).to be(true)

      expect(space.acknowledge(MQTT::Packet::Puback.new(:id => pub_id))).to be(true)
      expect(space.acknowledge(MQTT::Packet::Suback.new(:id => sub_id, :return_codes => 0))).to be(true)
      expect(space.in_flight_count).to eq(0)
      expect(pub_entry.queue.pop).to be_a(MQTT::Packet::Puback)
      expect(sub_entry.queue.pop).to be_a(MQTT::Packet::Suback)
    end

    it 'rejects an UNSUBACK that does not match an unsubscribe request' do
      id, = space.reserve(:subscribe)
      expect(space.acknowledge(MQTT::Packet::Unsuback.new(:id => id))).to be(false)
      expect(space.in_flight?(id)).to be(true)
    end

    it 'ignores an acknowledgement for an identifier it never allocated' do
      expect(space.acknowledge(MQTT::Packet::Puback.new(:id => 999))).to be(false)
    end

    it 'swallows a late acknowledgement and releases the quarantine' do
      id, entry = space.reserve(:publish)
      space.release(id)
      expect(space.quarantined?(id)).to be(true)

      expect(space.acknowledge(MQTT::Packet::Puback.new(:id => id))).to be(false)
      expect(space.quarantined?(id)).to be(false)
      expect(space.in_flight?(id)).to be(false)
      expect(entry.queue).to be_empty
    end
  end

  describe '#release and #fail_all' do
    it 'quarantines a released identifier so it cannot be reallocated immediately' do
      id, = space.reserve(:publish)
      space.reserve(:publish)
      space.reserve(:publish)
      space.release(id)
      expect(space.in_flight?(id)).to be(false)
      expect(space.quarantined?(id)).to be(true)
      expect { space.reserve(:publish) }.to raise_error(MQTT::Client::PacketIdExhausted)
    end

    it 'delivers a close event to every failed request and quarantines all ids' do
      first, first_entry = space.reserve(:publish)
      second, second_entry = space.reserve(:subscribe)
      space.fail_all(:close)

      expect(space.in_flight_count).to eq(0)
      expect(space.quarantined.keys.sort).to eq([first, second])
      expect(first_entry.queue.pop).to eq(:close)
      expect(second_entry.queue.pop).to eq(:close)
    end
  end

  describe '#reset' do
    it 'clears in-flight requests and quarantines and advances the generation' do
      id, = space.reserve(:publish)
      space.release(id)
      old_generation = space.generation

      space.reset

      expect(space.generation).to eq(old_generation + 1)
      expect(space.in_flight_count).to eq(0)
      expect(space.quarantined_count).to eq(0)
      expect(space.reserve(:publish).first).to eq(1)
    end

    it 'isolates acknowledgements left over from a previous connection' do
      id, = space.reserve(:publish)
      space.reset
      # The stale PUBACK belongs to the previous generation and must not match
      # anything in the fresh connection.
      expect(space.acknowledge(MQTT::Packet::Puback.new(:id => id))).to be(false)
      expect(space.in_flight_count).to eq(0)
    end
  end

  describe 'full lifecycle with a tiny space' do
    it 'never leaves an identifier permanently unallocatable' do
      # Use up the space, time one out, then recover via the late ack.
      first, = space.reserve(:publish)
      space.reserve(:publish)
      space.reserve(:publish)
      expect { space.reserve(:publish) }.to raise_error(MQTT::Client::PacketIdExhausted)

      space.release(first)
      expect { space.reserve(:publish) }.to raise_error(MQTT::Client::PacketIdExhausted)

      # The late acknowledgement frees the quarantined identifier for reuse.
      space.acknowledge(MQTT::Packet::Puback.new(:id => first))
      reused, reused_entry = space.reserve(:publish)
      expect(reused).to eq(first)
      expect(space.acknowledge(MQTT::Packet::Puback.new(:id => reused))).to be(true)
      expect(reused_entry.queue.pop).to be_a(MQTT::Packet::Puback)
    end
  end
end
