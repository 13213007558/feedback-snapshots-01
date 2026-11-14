$:.unshift(File.dirname(__FILE__))

require 'spec_helper'
require 'mqtt'
require 'socket'

# A tiny scripted broker that drives the client through two disconnections.
#
# It uses a socketpair so the demonstration does not need to bind a TCP port
# and runs the real MQTT packet parser and serialiser.
class ScriptedSessionBroker
  attr_reader :packets

  def initialize(io)
    @io = io
    @packets = []
  end

  def read_packet(timeout = 2)
    raise 'timed out waiting for a packet from the client' unless IO.select([@io], nil, nil, timeout)

    packet = MQTT::Packet.read(@io)
    @packets << packet
    packet
  end

  def read_packet_if_any(timeout = 0.2)
    return nil unless IO.select([@io], nil, nil, timeout)

    packet = MQTT::Packet.read(@io)
    @packets << packet
    packet
  end

  def write_packet(packet)
    @io.write(packet.to_s)
  end

  def handshake(session_present:)
    connect = read_packet
    raise "expected CONNECT, got #{connect.class}" unless connect.is_a?(MQTT::Packet::Connect)

    write_packet(
      MQTT::Packet::Connack.new(
        :return_code => 0,
        :session_present => session_present
      )
    )
    connect
  end

  def accept_subscribe
    subscribe = read_packet
    raise "expected SUBSCRIBE, got #{subscribe.class}" unless subscribe.is_a?(MQTT::Packet::Subscribe)

    write_packet(
      MQTT::Packet::Suback.new(
        :id => subscribe.id,
        :return_codes => subscribe.topics.map { 0 }
      )
    )
    subscribe
  end

  def accept_publish
    publish = read_packet
    raise "expected PUBLISH, got #{publish.class}" unless publish.is_a?(MQTT::Packet::Publish)

    publish
  end

  def close
    @io.close unless @io.closed?
  rescue IOError
    nil
  end
end

describe "a persistent MQTT consumer recovering from disconnections" do
  let(:client) do
    MQTT::Client.new(
      :host => 'broker.example.com',
      :port => 1883,
      :clean_session => false,
      :ack_timeout => 5
    )
  end
  let(:available_sockets) { [] }

  before(:each) do
    allow(client).to receive(:open_tcp_socket) { available_sockets.shift }
  end

  after(:each) do
    client.disconnect(false) if client.connected?
  end

  def next_broker
    client_side, broker_side = UNIXSocket.pair
    available_sockets << client_side
    ScriptedSessionBroker.new(broker_side)
  end

  def connect_client(session_present:)
    broker = next_broker
    connect_thread = Thread.new { client.connect('secure-consumer') }
    broker.handshake(:session_present => session_present)
    [connect_thread.value, broker]
  end

  def wait_for_publish_to_block(broker)
    publish_result = nil
    thread = Thread.new do
      publish_result = client.publish('secure/commands', 'unlock', false, 1)
    end
    publish = broker.accept_publish
    [thread, publish]
  end

  it "re-establishes the security subscription after two disconnections" do
    # --- Connection 1: a brand new session ------------------------------
    result, broker = connect_client(:session_present => false)
    expect(result.status).to eq(:new_session)
    expect(result.local_state_discarded?).to be_falsey

    client.subscribe('secure/commands')
    expect(broker.accept_subscribe.topics).to eq([['secure/commands', 0]])

    # A QoS 1 operation is in flight when the connection drops.
    publish_thread, publish = wait_for_publish_to_block(broker)
    old_publish_id = publish.id
    client.disconnect(false)
    expect(publish_thread.value).to eq(-1)
    broker.close

    # --- Recovery 1: the broker resumed the session ---------------------
    result, broker = connect_client(:session_present => true)
    expect(result.status).to eq(:resumed)
    expect(result.identity_changed?).to be_falsey
    expect(result.pending_acknowledgements_lost?).to be_truthy

    # No SUBSCRIBE is sent: the broker kept the subscription and the client
    # knows that from the explicit recovery result.
    expect(broker.read_packet_if_any).to be_nil

    # A delayed PUBACK from the old connection must not complete a new
    # operation, even when it carries the id of the abandoned publish.
    publish_thread, publish = wait_for_publish_to_block(broker)
    expect(publish.id).not_to eq(old_publish_id)
    broker.write_packet(MQTT::Packet::Puback.new(:id => old_publish_id))
    sleep 0.15
    expect(publish_thread).to be_alive

    broker.write_packet(MQTT::Packet::Puback.new(:id => publish.id))
    expect(publish_thread.value).to be_truthy

    # Leave another operation in flight and lose the connection again.
    publish_thread, publish = wait_for_publish_to_block(broker)
    lost_publish_id = publish.id
    client.disconnect(false)
    expect(publish_thread.value).to eq(-1)
    broker.close

    # --- Recovery 2: the server lost the session ------------------------
    result, broker = connect_client(:session_present => false)
    expect(result.status).to eq(:new_session)
    expect(result.resumed?).to be_falsey
    expect(result.identity_changed?).to be_falsey

    # The application explicitly re-establishes its security subscription.
    client.resubscribe
    expect(broker.accept_subscribe.topics).to eq([['secure/commands', 0]])

    # A delayed PUBACK from the lost session must not complete a fresh
    # command simply because it reuses the id of the abandoned publish.
    publish_thread, publish = wait_for_publish_to_block(broker)
    expect(publish.id).not_to eq(lost_publish_id)
    broker.write_packet(MQTT::Packet::Puback.new(:id => lost_publish_id))
    sleep 0.15
    expect(publish_thread).to be_alive

    broker.write_packet(MQTT::Packet::Puback.new(:id => publish.id))
    expect(publish_thread.value).to be_truthy

    # Old queued messages from the lost session were not delivered.
    expect(client.queue_empty?).to be_truthy
    expect(client.subscriptions).to eq('secure/commands' => 0)

    broker.close
  end

  it "does not present old queued messages as new session messages when the target changes" do
    result, broker = connect_client(:session_present => false)
    expect(result.new_session?).to be_truthy
    broker.close
    client.disconnect(false)

    # Queue a message while disconnected, as if it belonged to the old target.
    client.instance_variable_get('@read_queue').push(
      MQTT::Packet::Publish.new(:topic => 'secure/commands', :payload => 'stale')
    )

    # Point the client at a different broker, which claims to have a session.
    client.host = 'other-broker.example.com'
    result, broker = connect_client(:session_present => true)

    expect(result.identity_changed?).to be_truthy
    expect(result.local_state_discarded?).to be_truthy
    expect(client.queue_empty?).to be_truthy

    broker.close
  end
end
