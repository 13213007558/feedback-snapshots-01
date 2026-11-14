# encoding: BINARY

$:.unshift(File.dirname(__FILE__))

require 'spec_helper'

describe MQTT::SN::SessionParser do

  let(:parser) { MQTT::SN::SessionParser.new }

  def connect(client_id)
    MQTT::SN::Packet::Connect.new(:client_id => client_id)
  end

  def register(id, topic_name, topic_id = 0)
    MQTT::SN::Packet::Register.new(:id => id, :topic_id => topic_id, :topic_name => topic_name)
  end

  def regack(id, topic_id, return_code = 0x00)
    MQTT::SN::Packet::Regack.new(:id => id, :topic_id => topic_id, :return_code => return_code)
  end

  def publish(topic_id, type = :normal)
    MQTT::SN::Packet::Publish.new(:topic_id_type => type, :topic_id => topic_id, :data => 'x')
  end

  def feed(packet, direction, gateway, client)
    parser.process(packet, :direction => direction, :gateway => gateway, :client => client)
  end

  describe "direction validation" do
    it "should reject an invalid direction" do
      expect {
        feed(publish(1), :sideways, 'gw1', 'client-a')
      }.to raise_error(ArgumentError)
    end
  end

  describe "dynamic registration" do
    it "should resolve a topic id only after a successful REGISTER/REGACK pair" do
      feed(connect('client-a'), :from_client, 'gw1', 'client-a')
      feed(register(10, 'devices/a'), :from_client, 'gw1', 'client-a')
      feed(regack(10, 1), :to_client, 'gw1', 'client-a')

      result = feed(publish(1), :from_client, 'gw1', 'client-a')
      expect(result.topic).to eq('devices/a')
      expect(result.source).to eq(:register)
      expect(result.session).to eq(1)
      expect(result.gateway).to eq('gw1')
      expect(result.client).to eq('client-a')
    end

    it "should not resolve a topic id when the REGACK is missing" do
      feed(connect('client-a'), :from_client, 'gw1', 'client-a')
      feed(register(10, 'devices/a'), :from_client, 'gw1', 'client-a')

      result = feed(publish(1), :from_client, 'gw1', 'client-a')
      expect(result.topic).to be_nil
      expect(result.source).to eq(:unknown)
    end

    it "should not resolve a topic id when the registration was rejected" do
      feed(connect('client-a'), :from_client, 'gw1', 'client-a')
      feed(register(10, 'devices/a'), :from_client, 'gw1', 'client-a')
      feed(regack(10, 1, 0x02), :to_client, 'gw1', 'client-a')

      result = feed(publish(1), :from_client, 'gw1', 'client-a')
      expect(result.topic).to be_nil
      expect(result.source).to eq(:unknown)
      expect(result.detail).to include('rejected')
    end

    it "should not resolve a topic id when only the REGACK was captured" do
      feed(connect('client-a'), :from_client, 'gw1', 'client-a')
      feed(regack(10, 1), :to_client, 'gw1', 'client-a')

      result = feed(publish(1), :from_client, 'gw1', 'client-a')
      expect(result.topic).to be_nil
      expect(result.source).to eq(:unknown)
      expect(result.detail).to include('without a captured REGISTER')
    end

    it "should resolve gateway-initiated registrations" do
      feed(connect('client-a'), :from_client, 'gw1', 'client-a')
      feed(register(7, 'alerts/a'), :to_client, 'gw1', 'client-a')
      feed(regack(7, 3), :from_client, 'gw1', 'client-a')

      result = feed(publish(3), :to_client, 'gw1', 'client-a')
      expect(result.topic).to eq('alerts/a')
      expect(result.source).to eq(:register)
    end

    it "should flag a conflict when one topic id is confirmed for two names in a session" do
      feed(connect('client-a'), :from_client, 'gw1', 'client-a')
      feed(register(10, 'devices/a'), :from_client, 'gw1', 'client-a')
      feed(regack(10, 1), :to_client, 'gw1', 'client-a')
      feed(register(11, 'devices/b'), :from_client, 'gw1', 'client-a')
      feed(regack(11, 1), :to_client, 'gw1', 'client-a')

      result = feed(publish(1), :from_client, 'gw1', 'client-a')
      expect(result.topic).to be_nil
      expect(result.source).to eq(:conflict)
      expect(result.detail).to include('devices/a')
      expect(result.detail).to include('devices/b')
    end
  end

  describe "session boundaries" do
    it "should forget mappings when the client reconnects" do
      feed(connect('client-a'), :from_client, 'gw1', 'client-a')
      feed(register(10, 'devices/a'), :from_client, 'gw1', 'client-a')
      feed(regack(10, 1), :to_client, 'gw1', 'client-a')
      feed(connect('client-a'), :from_client, 'gw1', 'client-a')

      result = feed(publish(1), :from_client, 'gw1', 'client-a')
      expect(result.topic).to be_nil
      expect(result.source).to eq(:unknown)
      expect(result.session).to eq(2)
    end

    it "should forget mappings when the client disconnects" do
      feed(connect('client-a'), :from_client, 'gw1', 'client-a')
      feed(register(10, 'devices/a'), :from_client, 'gw1', 'client-a')
      feed(regack(10, 1), :to_client, 'gw1', 'client-a')
      feed(MQTT::SN::Packet::Disconnect.new, :from_client, 'gw1', 'client-a')

      result = feed(publish(1), :from_client, 'gw1', 'client-a')
      expect(result.topic).to be_nil
      expect(result.source).to eq(:unknown)
    end
  end

  describe "interleaved sessions reusing the same topic id" do
    it "should never attribute one session's topic name to another session" do
      forbidden = ['forbidden/zone']

      feed(connect('sensor-a'), :from_client, 'gw1', 'sensor-a')
      feed(connect('sensor-b'), :from_client, 'gw1', 'sensor-b')

      feed(register(10, 'forbidden/zone'), :from_client, 'gw1', 'sensor-a')
      feed(register(20, 'allowed/zone'), :from_client, 'gw1', 'sensor-b')
      feed(regack(20, 1), :to_client, 'gw1', 'sensor-b')
      feed(regack(10, 1), :to_client, 'gw1', 'sensor-a')

      result_b = feed(publish(1), :from_client, 'gw1', 'sensor-b')
      result_a = feed(publish(1), :from_client, 'gw1', 'sensor-a')
      result_b2 = feed(publish(1), :from_client, 'gw1', 'sensor-b')

      expect(result_a.topic).to eq('forbidden/zone')
      expect(result_b.topic).to eq('allowed/zone')
      expect(result_b2.topic).to eq('allowed/zone')

      expect(forbidden.include?(result_a.topic)).to be_truthy
      expect(forbidden.include?(result_b.topic)).to be_falsey
      expect(forbidden.include?(result_b2.topic)).to be_falsey
    end

    it "should keep the same client id on different gateways independent" do
      feed(connect('sensor-a'), :from_client, 'gw1', 'sensor-a')
      feed(connect('sensor-a'), :from_client, 'gw2', 'sensor-a')
      feed(register(10, 'devices/gw1'), :from_client, 'gw1', 'sensor-a')
      feed(regack(10, 1), :to_client, 'gw1', 'sensor-a')
      feed(register(10, 'devices/gw2'), :from_client, 'gw2', 'sensor-a')
      feed(regack(10, 1), :to_client, 'gw2', 'sensor-a')

      expect(feed(publish(1), :from_client, 'gw1', 'sensor-a').topic).to eq('devices/gw1')
      expect(feed(publish(1), :from_client, 'gw2', 'sensor-a').topic).to eq('devices/gw2')
    end

    it "should not leak a mapping to a client that never registered" do
      feed(connect('sensor-a'), :from_client, 'gw1', 'sensor-a')
      feed(register(10, 'devices/a'), :from_client, 'gw1', 'sensor-a')
      feed(regack(10, 1), :to_client, 'gw1', 'sensor-a')

      result = feed(publish(1), :from_client, 'gw1', 'sensor-b')
      expect(result.topic).to be_nil
      expect(result.source).to eq(:unknown)
    end
  end

  describe "short topics" do
    it "should resolve a short topic name directly from the packet" do
      result = feed(publish('ab', :short), :from_client, 'gw1', 'client-a')
      expect(result.topic).to eq('ab')
      expect(result.source).to eq(:short)
    end

    it "should not be affected by dynamic registrations" do
      feed(connect('client-a'), :from_client, 'gw1', 'client-a')
      feed(register(10, 'devices/a'), :from_client, 'gw1', 'client-a')
      feed(regack(10, 1), :to_client, 'gw1', 'client-a')

      result = feed(publish('ab', :short), :from_client, 'gw1', 'client-a')
      expect(result.topic).to eq('ab')
      expect(result.source).to eq(:short)
    end
  end

  describe "predefined topics" do
    let(:parser) do
      MQTT::SN::SessionParser.new(
        :predefined => {
          'gw1' => { 7 => 'predefined/gw1' },
          :default => { 9 => 'predefined/shared' }
        }
      )
    end

    it "should resolve a predefined topic id via the gateway's table" do
      result = feed(publish(7, :predefined), :from_client, 'gw1', 'client-a')
      expect(result.topic).to eq('predefined/gw1')
      expect(result.source).to eq(:predefined)
    end

    it "should fall back to the default table" do
      result = feed(publish(9, :predefined), :from_client, 'gw2', 'client-a')
      expect(result.topic).to eq('predefined/shared')
      expect(result.source).to eq(:predefined)
    end

    it "should report unknown predefined ids instead of guessing" do
      result = feed(publish(8, :predefined), :from_client, 'gw1', 'client-a')
      expect(result.topic).to be_nil
      expect(result.source).to eq(:unknown)
    end
  end

  describe "other topic-carrying packets" do
    it "should resolve a Subscribe with a full topic name as explicit" do
      packet = MQTT::SN::Packet::Subscribe.new(
        :id => 1, :topic_id_type => :normal, :topic_name => 'devices/a'
      )
      result = feed(packet, :from_client, 'gw1', 'client-a')
      expect(result.topic).to eq('devices/a')
      expect(result.source).to eq(:explicit)
    end

    it "should resolve a Puback through the dynamic mapping" do
      feed(connect('client-a'), :from_client, 'gw1', 'client-a')
      feed(register(10, 'devices/a'), :from_client, 'gw1', 'client-a')
      feed(regack(10, 1), :to_client, 'gw1', 'client-a')

      packet = MQTT::SN::Packet::Puback.new(:id => 5, :topic_id => 1, :return_code => 0)
      result = feed(packet, :to_client, 'gw1', 'client-a')
      expect(result.topic).to eq('devices/a')
      expect(result.source).to eq(:register)
    end

    it "should return nil for packets without topic information" do
      expect(feed(MQTT::SN::Packet::Pingreq.new, :from_client, 'gw1', 'client-a')).to be_nil
      expect(feed(connect('client-a'), :from_client, 'gw1', 'client-a')).to be_nil
    end
  end
end
