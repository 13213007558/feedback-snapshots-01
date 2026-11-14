#!/usr/bin/env ruby
# frozen_string_literal: true

# Offline replay of a stored failing case.
#
#   ruby -Ilib test/stream_dom_consistency/bin/replay.rb failure.json
#   ruby -Ilib test/stream_dom_consistency/bin/replay.rb --seed 20261114
#
# No network, no database, no external service.  The stored case carries the
# exact XML bytes and the token tree, so replay is independent of the
# generator, the seed, and the REXML version used to find it.

$LOAD_PATH.unshift(File.expand_path("../../../lib", __dir__))

require "optparse"
require_relative "../model"
require_relative "../generator"
require_relative "../oracle"
require_relative "../runner"

module StreamDomConsistency
  module Replay
    module_function

    def replay_file(path)
      kase = Runner.load_replay(path)
      report(kase)
    end

    def report(kase)
      expected = Expected.compute(kase)
      findings = Oracle.new(banned: kase.policy.banned).evaluate(kase)
      puts "case: #{kase.id}"
      puts "seed: #{kase.seed}"
      puts "source form: #{kase.source_form}"
      puts "bytes: #{kase.xml_bytes.inspect}"
      puts "logical XML: #{kase.logical_xml.inspect}"
      puts "expected: #{expected.status}#{expected.reason ? " (#{expected.reason})" : ""}"
      puts "expected combined characters: #{expected.channel(:combined).inspect}"
      puts "expected attributes: #{expected.attributes.inspect}"
      if findings.empty?
        puts "RESULT: no findings"
      else
        puts "RESULT: #{findings.length} finding(s)"
        findings.each do |finding|
          puts "- #{finding.kind}: #{finding.message}"
          puts "  expected: #{finding.expected}"
          puts "  stream:   #{finding.stream_observed}"
          puts "  dom:      #{finding.dom_observed}"
        end
      end
      findings.empty?
    end
  end

  class ReplayCLI
    def self.run(argv)
      seed = DEFAULT_SEED
      category = nil
      OptionParser.new do |options|
        options.banner = "Usage: replay.rb [failure.json | --seed N]"
        options.on("--seed N", Integer, "Generate and replay one seeded case") { |value| seed = value }
        options.on("--category NAME", String, "Force a generator category") { |value| category = value.to_sym }
      end.parse!(argv)

      if argv.empty?
        kase = Generator.new(seed: seed).next_case(category: category)
        puts "generated case #{kase.id} from seed #{seed}"
        Replay.report(kase)
      else
        argv.each do |path|
          Replay.replay_file(path)
        end
      end
    end
  end
end

exit(StreamDomConsistency::ReplayCLI.run(ARGV) ? 0 : 1) if $PROGRAM_NAME == __FILE__
