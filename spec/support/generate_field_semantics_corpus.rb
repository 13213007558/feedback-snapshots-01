#!/usr/bin/env ruby
# encoding: BINARY
#
# Generates the deterministic field-semantics corpus used by
# spec/mqtt_field_semantics_spec.rb.
#
# Each case keeps its logical fields separate from its wire bytes. The corpus
# is checked in so that every minimal failing input can be replayed directly:
#
#   ruby spec/support/generate_field_semantics_corpus.rb
#
# A rejected case records the raw bytes that triggered the rejection; accepted
# cases record bytes produced by the independent Builder, not by MQTT::Packet.

$LOAD_PATH.unshift(File.expand_path('../../lib', __dir__))
require 'json'
require 'mqtt'
require_relative 'field_semantics_builder'

include MQTTFieldSemantics

CASES = []

def hex(str)
  str.to_s.b.unpack1('H*')
end

def add(id:, packet:, args:, expect:, category:, note:)
  args = args.transform_values do |value|
    if value.is_a?(Array)
      value.map do |item|
        item.is_a?(Hash) ? item.transform_values { |v| v.is_a?(String) ? hex(v) : v } : item
      end
    elsif value.is_a?(String) && !value.match?(/\A(3\.1\.0|3\.1\.1)\z/)
      hex(value)
    else
      value
    end
  end
  CASES << {
    'id' => id,
    'category' => category,
    'packet' => packet,
    'note' => note,
    'args' => args,
    'wire_hex' => nil,
    'expect' => { 'encode' => expect[0], 'parse' => expect[1] }
  }
end

def topic_args(topic, payload = ''.b, qos: 0, id: 0)
  { 'topic_hex' => topic, 'payload_hex' => payload, 'qos' => qos, 'id' => id }
end

# ---- PUBLISH topic names: valid UTF-8 -------------------------------------
[
  ['ascii', 'a/b', 'plain ASCII topic'],
  ['utf8-two-byte', 'café', 'valid two byte UTF-8'],
  ['utf8-four-byte', "A\u{2A6D4}", 'valid four byte UTF-8'],
  ['topic-slash', '/', 'topic consisting only of the separator is valid'],
  ['empty-level', 'a//b', 'adjacent separators create a zero length level'],
  ['bom', "\xEF\xBB\xBF".b, 'leading BOM is preserved, not stripped']
].each do |suffix, topic, note|
  add(id: "publish-topic-valid-#{suffix}", packet: 'publish', category: 'publish-topic',
      args: topic_args(topic), expect: %w[accept accept], note: note)
end

# ---- PUBLISH topic names: semantic violations -----------------------------
Atoms::WILDCARD_TOPICS.each do |topic|
  suffix = topic.unpack1('H*')
  add(id: "publish-topic-wildcard-#{suffix}", packet: 'publish', category: 'publish-topic',
      args: topic_args(topic), expect: %w[reject reject],
      note: 'PUBLISH Topic Name must not contain wildcard characters')
end

Atoms::INVALID_TEXT.each do |note, bytes|
  suffix = bytes.unpack1('H*')
  add(id: "publish-topic-invalid-utf8-#{suffix}", packet: 'publish', category: 'publish-topic',
      args: topic_args(bytes), expect: %w[reject reject], note: note)
end

add(id: 'publish-topic-empty', packet: 'publish', category: 'publish-topic',
    args: topic_args(''), expect: %w[reject reject], note: 'Topic Name must be at least one character')

# ---- PUBLISH payload: opaque binary --------------------------------------
Atoms::BINARY_PAYLOADS.each do |note, payload|
  suffix = note.downcase.gsub(/[^a-z0-9]+/, '-').gsub(/-\z/, '')
  add(id: "publish-payload-#{suffix}", packet: 'publish', category: 'publish-payload',
      args: topic_args('binary/data', payload, qos: 0), expect: %w[accept accept],
      note: "payload must survive byte-for-byte (#{note})")
  add(id: "publish-payload-qos1-#{suffix}", packet: 'publish', category: 'publish-payload',
      args: topic_args('binary/data', payload, qos: 1, id: 7), expect: %w[accept accept],
      note: "payload must survive byte-for-byte with a packet id (#{note})")
end

# ---- CONNECT identity fields ---------------------------------------------
[
  ['ascii', 'client-1', 'plain ASCII client identifier'],
  ['utf8', 'café', 'valid non-ASCII UTF-8 client identifier'],
  ['one-byte', 'c', 'single byte client identifier'],
  ['empty-clean-session', '', 'zero byte ClientId allowed with CleanSession=1'],
  ['23-bytes', 'a' * 23, 'MQTT 3.1.0 permits exactly 23 bytes'],
].each do |suffix, client_id, note|
  version = suffix == '23-bytes' ? '3.1.0' : '3.1.1'
  clean = true
  add(id: "connect-client-id-valid-#{suffix}", packet: 'connect', category: 'connect-identity',
      args: { 'version' => version, 'client_id_hex' => client_id, 'clean_session' => clean },
      expect: %w[accept accept], note: note)
end

add(id: 'connect-client-id-empty-no-clean-session', packet: 'connect', category: 'connect-identity',
    args: { 'version' => '3.1.1', 'client_id_hex' => '', 'clean_session' => false },
    expect: %w[reject reject],
    note: 'zero byte ClientId requires CleanSession=1')

add(id: 'connect-client-id-too-long-3-1-0', packet: 'connect', category: 'connect-identity',
    args: { 'version' => '3.1.0', 'client_id_hex' => 'a' * 24, 'clean_session' => true },
    expect: %w[reject reject],
    note: 'MQTT 3.1.0 client identifiers are 1..23 bytes')

Atoms::INVALID_TEXT.each do |note, bytes|
  suffix = bytes.unpack1('H*')
  add(id: "connect-client-id-invalid-#{suffix}", packet: 'connect', category: 'connect-identity',
      args: { 'version' => '3.1.1', 'client_id_hex' => bytes, 'clean_session' => true },
      expect: %w[reject reject], note: note)
end

add(id: 'connect-username-invalid-utf8', packet: 'connect', category: 'connect-identity',
    args: { 'version' => '3.1.1', 'client_id_hex' => 'cid', 'clean_session' => true,
            'username_hex' => "\xFF".b, 'password_hex' => 'pass' },
    expect: %w[reject reject], note: 'User Name is a UTF-8 encoded string')

add(id: 'connect-username-nul', packet: 'connect', category: 'connect-identity',
    args: { 'version' => '3.1.1', 'client_id_hex' => 'cid', 'clean_session' => true,
            'username_hex' => "\x00".b },
    expect: %w[reject reject], note: 'User Name must not include U+0000')

add(id: 'connect-will-topic-wildcard', packet: 'connect', category: 'connect-identity',
    args: { 'version' => '3.1.1', 'client_id_hex' => 'cid', 'clean_session' => true,
            'will_topic_hex' => '#', 'will_payload_hex' => ''.b },
    expect: %w[reject reject], note: 'Will Topic is a Topic Name and cannot contain wildcards')

add(id: 'connect-will-topic-invalid-utf8', packet: 'connect', category: 'connect-identity',
    args: { 'version' => '3.1.1', 'client_id_hex' => 'cid', 'clean_session' => true,
            'will_topic_hex' => "\xFF".b, 'will_payload_hex' => ''.b },
    expect: %w[reject reject], note: 'Will Topic is a UTF-8 encoded string')

# Will Message and Password are binary, not UTF-8 strings.
Atoms::BINARY_PAYLOADS.each do |note, bytes|
  suffix = note.downcase.gsub(/[^a-z0-9]+/, '-').gsub(/-\z/, '')
  add(id: "connect-will-payload-#{suffix}", packet: 'connect', category: 'connect-identity',
      args: { 'version' => '3.1.1', 'client_id_hex' => 'cid', 'clean_session' => true,
              'will_topic_hex' => 'will/topic', 'will_payload_hex' => bytes },
      expect: %w[accept accept], note: "Will Message must survive byte-for-byte (#{note})")
  add(id: "connect-password-#{suffix}", packet: 'connect', category: 'connect-identity',
      args: { 'version' => '3.1.1', 'client_id_hex' => 'cid', 'clean_session' => true,
              'username_hex' => 'user', 'password_hex' => bytes },
      expect: %w[accept accept], note: "Password must survive byte-for-byte (#{note})")
end

# ---- SUBSCRIBE / UNSUBSCRIBE topic filters -------------------------------
Atoms::VALID_FILTERS.each do |filter|
  suffix = filter.unpack1('H*')
  add(id: "subscribe-filter-valid-#{suffix}", packet: 'subscribe', category: 'topic-filter',
      args: { 'id' => 1, 'filters' => [{ 'filter_hex' => filter, 'qos' => 1 }] },
      expect: %w[accept accept], note: 'legal wildcard filter must be accepted on both sides')
  add(id: "unsubscribe-filter-valid-#{suffix}", packet: 'unsubscribe', category: 'topic-filter',
      args: { 'id' => 1, 'filters' => [{ 'filter_hex' => filter, 'qos' => 0 }] },
      expect: %w[accept accept], note: 'legal wildcard filter must be accepted on both sides')
end

Atoms::INVALID_FILTERS.each do |filter|
  suffix = filter.unpack1('H*')
  add(id: "subscribe-filter-invalid-#{suffix}", packet: 'subscribe', category: 'topic-filter',
      args: { 'id' => 1, 'filters' => [{ 'filter_hex' => filter, 'qos' => 0 }] },
      expect: %w[reject reject], note: 'wildcards must occupy a whole level and # must be last')
  add(id: "unsubscribe-filter-invalid-#{suffix}", packet: 'unsubscribe', category: 'topic-filter',
      args: { 'id' => 1, 'filters' => [{ 'filter_hex' => filter, 'qos' => 0 }] },
      expect: %w[reject reject], note: 'wildcards must occupy a whole level and # must be last')
end

Atoms::INVALID_TEXT.each do |note, bytes|
  suffix = bytes.unpack1('H*')
  add(id: "subscribe-filter-invalid-utf8-#{suffix}", packet: 'subscribe', category: 'topic-filter',
      args: { 'id' => 1, 'filters' => [{ 'filter_hex' => bytes, 'qos' => 0 }] },
      expect: %w[reject reject], note: note)
end

# A filter list is made of independent logical fields; one bad filter must not
# make a preceding legal wildcard filter be reinterpreted or silently dropped.
add(id: 'subscribe-mixed-valid-and-invalid', packet: 'subscribe', category: 'topic-filter',
    args: { 'id' => 9, 'filters' => [
      { 'filter_hex' => 'a/+/b', 'qos' => 1 },
      { 'filter_hex' => "bad\xFF".b, 'qos' => 0 },
      { 'filter_hex' => 'c/#', 'qos' => 2 }
    ] },
    expect: %w[reject reject], note: 'one invalid filter rejects the whole packet')

# ---- Populate wire bytes and validate the corpus -------------------------
CASES.each do |entry|
  if entry['expect']['encode'] == 'accept'
    entry['wire_hex'] = hex(Builder.build(entry))
  else
    # Keep a minimal replayable input even for rejected cases by recording the
    # independent builder output when the builder can represent it.
    begin
      entry['wire_hex'] = hex(Builder.build(entry))
    rescue Builder::FieldTooLong
      entry['wire_hex'] = nil
    end
  end
end

failures = []
seen = {}
CASES.each do |entry|
  failures << "duplicate id #{entry['id']}" if seen[entry['id']]
  seen[entry['id']] = true
  failures.concat(Replay.failures(entry).map { |failure| "#{entry['id']}: #{failure}" })
end

if failures.empty?
  output = File.expand_path('../fixtures/field_semantics/cases.json', __dir__)
  File.write(output, JSON.pretty_generate(CASES) + "\n")
  puts "Wrote #{CASES.length} cases to #{output}"
else
  warn failures.join("\n")
  exit 1
end
