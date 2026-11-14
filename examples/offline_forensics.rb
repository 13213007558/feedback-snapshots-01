#!/usr/bin/env ruby
#
# Offline analysis of a captured MQTT session from raw byte fragments.
# No network connection is opened.
#
# The fragments below stand in for bytes sniffed off the wire in two
# directions. They are deliberately fragmented and start mid-session so the
# analyser's gap handling and provenance tracking are easy to see.

$LOAD_PATH.unshift File.expand_path('../lib', __dir__)

require 'mqtt'

def wire(packet)
  packet.to_s.dup.force_encoding('ASCII-8BIT')
end

client_stream =
  wire(MQTT::Packet::Subscribe.new(:id => 10, :topics => { 'telemetry/+' => 1 })) +
  wire(MQTT::Packet::Publish.new(:id => 20, :qos => 1, :topic => 'telemetry/a', :payload => '12'))

broker_stream =
  wire(MQTT::Packet::Suback.new(:id => 10, :return_codes => [1])) +
  wire(MQTT::Packet::Puback.new(:id => 20)) +
  wire(MQTT::Packet::Puback.new(:id => 20)) # duplicated acknowledgement

capture = MQTT::Forensics::Capture.new
client_stream.bytes.each_slice(4).with_index do |slice, idx|
  capture.add(:client, slice.pack('C*'), nil, "capture/client-#{idx}")
end
broker_stream.bytes.each_slice(4).with_index do |slice, idx|
  capture.add(:broker, slice.pack('C*'), nil, "capture/broker-#{idx}")
end

report = MQTT::Forensics::Analyzer.new(capture).analyze
puts report.to_text
