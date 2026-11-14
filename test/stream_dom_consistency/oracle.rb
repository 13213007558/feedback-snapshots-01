# frozen_string_literal: true

require_relative "model"
require_relative "adapters"

module StreamDomConsistency
  # severity:
  #   :error   -- the filter/business contract is broken, or the oracle says a
  #               document was accepted that must be rejected (or vice versa).
  #   :warning -- both readers agree with each other but disagree with XML;
  #               reported as a shared deviation, not as a mutual pass.
  Finding = Struct.new(
    :kind,
    :severity,
    :case_id,
    :message,
    :expected,
    :stream_observed,
    :dom_observed,
    :case,
    keyword_init: true
  ) do
    def to_s
      "#{kind}: #{message}"
    end

    def to_h
      {
        "kind" => kind.to_s,
        "severity" => severity.to_s,
        "case_id" => case_id,
        "message" => message,
        "expected" => expected,
        "stream" => stream_observed,
        "dom" => dom_observed,
        "case" => @case&.to_h,
      }
    end
  end

  # Three independent layers:
  #
  # 1. Specification oracle (Expected): the character sequence XML 1.0
  #    defines, computed from the token tree, never by running REXML.
  # 2. Reader-vs-reader: the character sequence the streaming filter actually
  #    consumed vs the one the DOM business reader actually consumed.  Event
  #    counts and node splits are normalized away before this comparison.
  # 3. Consent rule: agreement between the two readers is not accepted as
  #    evidence when both are wrong.  For any input the oracle says must be
  #    rejected, two "allow" decisions are still a failure; and two "reject"
  #    decisions are only trusted when at least one reader consumed the
  #    spec-correct string.
  class Oracle
    def initialize(banned:)
      @banned = banned
    end

    attr_reader :banned

    def evaluate(kase)
      expected = Expected.compute(kase)
      stream = Adapters::StreamAdapter.run(kase)
      dom = Adapters::DomAdapter.run(kase)

      findings = []
      findings.concat(check_rejection(:stream, stream, expected, kase))
      findings.concat(check_rejection(:dom, dom, expected, kase))
      findings.concat(check_reader_divergence(stream, dom, expected, kase))
      findings.concat(check_policy(stream, dom, expected, kase))
      findings.concat(check_replacement(stream, dom, expected, kase))
      findings.concat(check_spec_deviation(:stream, stream, expected, kase))
      findings.concat(check_spec_deviation(:dom, dom, expected, kase))
      findings
    end

    def fails?(kase)
      evaluate(kase).any? { |finding| finding.severity == :error }
    end

    def fingerprints(kase)
      evaluate(kase).map { |finding| fingerprint(finding) }
    end

    # A stable identity for an allowlisted finding.
    #
    # Deliberately excludes generated text, seeds, and parser message wording,
    # but includes the channel (text/cdata/combined/attributes) so that a new
    # divergence in the same category cannot hide behind a known one.
    def fingerprint(finding)
      channel = finding.message[/different (.+?) character sequences/, 1]
      channel ||= finding.message[/attribute \"(.+?)\"/, 1] && "attribute"
      [finding.kind, finding.case&.category, channel].compact.join("|")
    end

    private

    def check_rejection(side, result, expected, kase)
      if expected.valid? && !result.ok
        return [finding(
          :"#{side}_rejected_valid_input",
          :error,
          kase,
          "#{side} rejected input the oracle accepts",
          expected: expected.reason.to_s,
          stream: describe(result),
          dom: describe(result),
        )]
      end

      if expected.invalid? && result.ok
        return [finding(
          :"#{side}_accepted_invalid_input",
          :error,
          kase,
          "#{side} accepted #{expected.status} input that must be rejected",
          expected: expected.reason.to_s,
          stream: describe(result),
          dom: describe(result),
        )]
      end
      []
    end

    def check_reader_divergence(stream, dom, expected, kase)
      return [] unless stream.ok && dom.ok

      findings = []
      %i[text cdata combined first_node].each do |channel|
        next if stream.channel(channel) == dom.channel(channel)

        findings << finding(
          :reader_divergence,
          :error,
          kase,
          "streaming filter and DOM reader consumed different #{channel} " \
          "character sequences (event/node counts are ignored)",
          expected: expected.valid? ? expected.channel(channel).inspect : expected.reason.to_s,
          stream: describe(stream),
          dom: describe(dom),
        )
      end

      (stream.attributes.keys | dom.attributes.keys).each do |name|
        next if stream.attributes[name] == dom.attributes[name]

        findings << finding(
          :reader_divergence,
          :error,
          kase,
          "streaming filter and DOM reader consumed different values for attribute #{name.inspect}",
          expected: expected.attributes[name].inspect,
          stream: describe(stream),
          dom: describe(dom),
        )
      end
      findings
    end

    def check_policy(stream, dom, expected, kase)
      return [] unless stream.ok && dom.ok

      stream_decision = decide(stream)
      dom_decision = decide(dom)
      expected_decision = expected.policy_decision
      findings = []

      if stream_decision != dom_decision
        findings << finding(
          :policy_divergence,
          :error,
          kase,
          "policy reached different decisions: stream=#{stream_decision}, dom=#{dom_decision}",
          expected: expected_decision.to_s,
          stream: describe(stream),
          dom: describe(dom),
        )
      end

      # A true smuggling bypass: the document is well formed, the spec-correct
      # character sequence contains the banned pattern, yet both readers
      # consumed a distorted sequence that does not.  Malformed documents are
      # already covered by the per-side accepted-invalid checks, so they are
      # not double-counted here.
      if expected.valid? && expected_decision == :reject &&
         stream_decision == :allow && dom_decision == :allow
        findings << finding(
          :policy_shared_bypass,
          :error,
          kase,
          "both readers allowed a well-formed document whose spec-correct " \
          "characters contain banned content; agreement between two distorted " \
          "readings is not a pass",
          expected: expected.policy_projection([:combined, :attributes]).inspect,
          stream: describe(stream),
          dom: describe(dom),
        )
      end

      if expected_decision == :allow && stream_decision == :reject &&
         dom_decision == :reject &&
         !literal_consent?(stream, expected) && !literal_consent?(dom, expected)
        findings << finding(
          :policy_shared_false_positive,
          :error,
          kase,
          "both readers rejected input on strings that are not spec-correct; " \
          "mutual agreement on a distorted reading is not correctness",
          expected: expected_decision.to_s,
          stream: describe(stream),
          dom: describe(dom),
        )
      end
      findings
    end

    # A literal U+FFFD is legal XML and a legitimate `&#xfffd;` reference is
    # not a decoding failure.  Only flag U+FFFD when the oracle's expected
    # character sequence does not contain it (or the input is invalid at
    # all): that means a decoder replaced bytes instead of rejecting them.
    def check_replacement(stream, dom, expected, kase)
      legitimate = expected.valid? && expected.channel(:combined).include?("�")

      findings = []
      return findings if legitimate

      [[:stream, stream], [:dom, dom]].each do |label, result|
        next unless result.ok
        next unless result.channel(:combined).include?("�")

        findings << finding(
          :silent_replacement_character,
          :error,
          kase,
          "#{label} produced U+FFFD although the input never contained one; " \
          "invalid bytes must be rejected, not replaced with different data",
          expected: "no replacement characters",
          stream: describe(stream),
          dom: describe(dom),
        )
      end
      findings
    end

    # When both readers agree with each other but not with XML, report it as a
    # warning.  It stays visible (and is explainable) without pretending the
    # pair is correct just because they agree.
    def check_spec_deviation(side, result, expected, kase)
      return [] unless expected.valid? && result.ok

      findings = []
      %i[text cdata combined first_node attributes].each do |channel|
        expected_value = expected.channel(channel)
        observed_value = result.channel(channel)
        next if expected_value == observed_value

        findings << finding(
          :shared_spec_deviation,
          :warning,
          kase,
          "#{side} reads #{channel} differently from XML 1.0 " \
          "(both readers may share this deviation)",
          expected: expected_value.inspect,
          stream: describe(result),
          dom: describe(result),
        )
      end
      findings
    end

    def literal_consent?(result, expected)
      result.policy_strings == expected.policy_projection([:combined, :attributes])
    end

    def decide(result)
      result.policy_strings.any? do |string|
        @banned.any? { |pattern| string.include?(pattern) }
      end ? :reject : :allow
    end

    def describe(result)
      result.describe
    end

    def finding(kind, severity, kase, message, expected:, stream:, dom:)
      Finding.new(
        kind: kind,
        severity: severity,
        case_id: kase.id,
        message: message,
        expected: expected.to_s,
        stream_observed: stream,
        dom_observed: dom,
        case: kase,
      )
    end
  end
end
