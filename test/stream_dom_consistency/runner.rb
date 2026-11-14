# frozen_string_literal: true

require "json"

require_relative "model"
require_relative "generator"
require_relative "oracle"
require_relative "shrinker"

module StreamDomConsistency
  # Shared driver for the tests and the replay CLI.  Deterministic and
  # offline: no sockets, no child processes, no clock or environment input.
  class Runner
    Failure = Struct.new(:case, :findings, :shrunk, keyword_init: true)

    attr_reader :seed

    def initialize(seed: DEFAULT_SEED)
      @seed = seed
    end

    def oracle_for(kase)
      Oracle.new(banned: kase.policy.banned)
    end

    def evaluate(kase)
      oracle_for(kase).evaluate(kase)
    end

    def run_suite(iterations: 200, stop_after: nil)
      generator = Generator.new(seed: @seed)
      failures = []
      iterations.times do
        kase = generator.next_case
        findings = evaluate(kase)
        next if findings.empty?

        shrunk = Shrinker.new(oracle: oracle_for(kase)).shrink(kase)
        failures << Failure.new(case: kase, findings: findings, shrunk: shrunk)
        break if stop_after && failures.length >= stop_after
      end
      failures
    end

    # Replay is intentionally bytes-in: a stored case carries the exact XML
    # bytes that failed, so replay does not depend on the generator version.
    def self.load_replay(path)
      Case.from_h(JSON.parse(File.read(path)))
    end

    def self.dump_replay(kase, path)
      File.write(path, JSON.pretty_generate(kase.to_h) + "\n")
      path
    end

    def describe_failure(failure)
      lines = []
      shrunk = failure.shrunk
      lines << "case #{failure.case.id} (seed #{failure.case.seed})"
      lines << "original: #{failure.case.xml_bytes.inspect}"
      lines << "shrunk:   #{shrunk.xml_bytes.inspect}"
      failure.findings.each do |finding|
        lines << "  #{finding.kind}: #{finding.message}"
        lines << "    expected: #{finding.expected}"
        lines << "    stream:   #{finding.stream_observed}"
        lines << "    dom:      #{finding.dom_observed}"
      end
      lines.join("\n")
    end
  end
end
