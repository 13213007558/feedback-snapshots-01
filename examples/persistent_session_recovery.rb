#!/usr/bin/env ruby
#
# Demonstrate a persistent MQTT session recovering from two disconnections.
#
# The consumer keeps clean_session=false, so the broker might resume the
# session. The application must not assume that it did:
#
#   Disconnection 1: the broker resumes the session (Session Present 1).
#                    The security subscription is still active, but any
#                    acknowledgement from the old connection is abandoned.
#   Disconnection 2: the broker has lost the session (Session Present 0).
#                    The application re-subscribes before handling commands.
#
# Expected output is printed, no external broker is required: a small
# in-process broker is used so the script is self-contained.
#

$:.unshift File.dirname(__FILE__)+'/../lib'

require 'mqtt'
require 'socket'

# A minimal broker that lets the script control Session Present and simulates
# a lost PUBACK across each disconnection.
class DemoBroker
  attr_reader :io

  def initialize(client_io)
    @io = client_io
  end

  def read
    MQTT::Packet.read(@io)
  end

  def write(packet)
    @io.write(packet.to_s)
  end

  def accept_connect(session_present)
    connect = read
    raise 'expected CONNECT' unless connect.is_a?(MQTT::Packet::Connect)

    write(MQTT::Packet::Connack.new(:return_code => 0, :session_present => session_present))
    connect
  end

  def accept_subscribe
    subscribe = read
    raise 'expected SUBSCRIBE' unless subscribe.is_a?(MQTT::Packet::Subscribe)

    write(MQTT::Packet::Suback.new(:id => subscribe.id, :return_codes => subscribe.topics.map { 0 }))
    subscribe
  end

  def accept_publish
    publish = read
    raise 'expected PUBLISH' unless publish.is_a?(MQTT::Packet::Publish)

    publish
  end

  def close
    @io.close unless @io.closed?
  end
end

def next_connection(client)
  client_side, broker_side = UNIXSocket.pair
  client.instance_variable_set(:@next_socket, client_side)
  client.define_singleton_method(:open_tcp_socket) { @next_socket }

  broker = DemoBroker.new(broker_side)
  thread = Thread.new { client.connect('secure-consumer') }
  [thread, broker]
end

def connect_and_handshake(client, session_present)
  thread, broker = next_connection(client)
  broker.accept_connect(session_present)
  [thread.value, broker]
end

def publish_without_reply(client, broker, payload)
  thread = Thread.new { client.publish('secure/commands', payload, false, 1) }
  packet = broker.accept_publish
  [thread, packet]
end

client = MQTT::Client.new(
  :host => 'demo-broker.local',
  :port => 1883,
  :clean_session => false,
  :keep_alive => 0
)

puts "== Connection 1: establish the security subscription =="
result, broker = connect_and_handshake(client, false)
puts "recovery=#{result.recovery} status=#{result.status} " \
     "session_present=#{result.session_present}"

client.subscribe('secure/commands')
broker.accept_subscribe
puts "subscribed: #{client.subscriptions.inspect}"

publish_thread, publish = publish_without_reply(client, broker, 'unlock-door')
lost_id = publish.id
client.disconnect(false)
puts "disconnected with publish #{lost_id} still awaiting PUBACK " \
     "(result=#{publish_thread.value})"
broker.close

puts
puts "== Disconnection 1: broker resumed the session =="
result, broker = connect_and_handshake(client, true)
puts "recovery=#{result.recovery} status=#{result.status} " \
     "identity_changed=#{result.identity_changed?} " \
     "pending_acks_lost=#{result.pending_acknowledgements_lost?}"

if result.resumed?
  puts "subscription still valid, not re-subscribing"
else
  client.resubscribe
  broker.accept_subscribe
end

publish_thread, publish = publish_without_reply(client, broker, 'open-gate')
puts "new publish #{publish.id} (old id #{lost_id} is abandoned)"

# The broker re-sends the PUBACK it queued for the old connection.
broker.write(MQTT::Packet::Puback.new(:id => lost_id))
sleep 0.1
puts "late PUBACK for #{lost_id} ignored: publish still pending=#{publish_thread.alive?}"

broker.write(MQTT::Packet::Puback.new(:id => publish.id))
puts "PUBACK for #{publish.id} accepted: result=#{publish_thread.value}"

publish_thread, publish = publish_without_reply(client, broker, 'arm-alarm')
lost_id = publish.id
client.disconnect(false)
puts "disconnected with publish #{lost_id} still awaiting PUBACK " \
     "(result=#{publish_thread.value})"
broker.close

puts
puts "== Disconnection 2: broker lost the session =="
result, broker = connect_and_handshake(client, false)
puts "recovery=#{result.recovery} status=#{result.status} " \
     "identity_changed=#{result.identity_changed?}"

puts 'no Session Present: re-establishing the security subscription'
client.resubscribe
subscribe = broker.accept_subscribe
puts "subscribed again: #{subscribe.topics.inspect}"

publish_thread, publish = publish_without_reply(client, broker, 'disarm-alarm')
puts "new publish #{publish.id} (old id #{lost_id} is abandoned)"

broker.write(MQTT::Packet::Puback.new(:id => lost_id))
sleep 0.1
puts "late PUBACK for #{lost_id} ignored: publish still pending=#{publish_thread.alive?}"

broker.write(MQTT::Packet::Puback.new(:id => publish.id))
puts "PUBACK for #{publish.id} accepted: result=#{publish_thread.value}"

puts "queued messages from lost sessions: #{client.queue_length}"

client.disconnect(false)
broker.close
