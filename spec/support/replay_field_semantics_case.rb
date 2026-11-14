#!/usr/bin/env ruby
# encoding: BINARY
#
# Replays one field-semantics case from the checked-in corpus.
#
#   ruby spec/support/replay_field_semantics_case.rb <case-id>
#   ruby spec/support/replay_field_semantics_case.rb --failed
#   ruby spec/support/replay_field_semantics_case.rb --list
#
# The logical fields (args), the independent reference wire bytes and the
# library's encode/parse outcome are printed so a failure can be copied into a
# bug report and reproduced without the generator.

$LOAD_PATH.unshift(File.expand_path('../../lib', __dir__))
require 'json'
require 'mqtt'
require_relative 'field_semantics_builder'

CASES = JSON.parse(
  File.read(File.expand_path('../fixtures/field_semantics/cases.json', __dir__))
).freeze

def describe(entry)
  args = MQTTFieldSemantics::Replay.decode_args(entry['args'])
  puts "case:     #{entry['id']}"
  puts "category: #{entry['category']}"
  puts "note:     #{entry['note']}"
  puts "logical:  #{args.inspect}"
  puts "expected: encode=#{entry['expect']['encode']} parse=#{entry['expect']['parse']}"
  puts "wire:     #{entry['wire_hex'] || '(not representable)'}"
  unless entry['wire_hex'].nil?
    wire = [entry['wire_hex']].pack('H*')
    puts "ruby:     #{wire.inspect}"
  end

  observed = MQTTFieldSemantics::Replay.replay(entry)
  observed.each do |direction, value|
    outcome = value.is_a?(Exception) ? "#{value.class}: #{value.message}" : value
    puts "#{direction}: #{outcome.inspect}"
  end

  failures = MQTTFieldSemantics::Replay.failures(entry)
  puts failures.empty? ? 'result:   pass' : "result:   FAIL - #{failures.join('; ')}"
  failures.empty?
end

mode = ARGV.first
case mode
when '--list'
  CASES.each { |entry| puts "#{entry['id']}\t#{entry['category']}\t#{entry['note']}" }
  exit 0
when '--failed'
  failed = CASES.reject { |entry| MQTTFieldSemantics::Replay.failures(entry).empty? }
  failed.each { |entry| puts; describe(entry) }
  puts
  puts "#{failed.length} of #{CASES.length} cases failed"
  exit(failed.empty? ? 0 : 1)
else
  entry = CASES.find { |item| item['id'] == mode }
  abort("Unknown or missing case id: #{mode.inspect}\nUse --list to see valid ids.") if entry.nil?
  exit(describe(entry) ? 0 : 1)
end
