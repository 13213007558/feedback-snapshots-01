# frozen_string_literal: true

require "uri"

require_relative "csp_change_checker/effective_policy_parser"
require_relative "csp_change_checker/source_set_semantics"
require_relative "csp_change_checker/directive_comparison"

module SecureHeaders
  # A release-gate prototype that certifies whether a Content-Security-Policy
  # change can be *proven* to tighten the browser-enforced allow-lists.
  #
  # It never compares raw user-supplied config hashes: both sides are rendered
  # through SecureHeaders::ContentSecurityPolicy (the real generator, including
  # minification, scheme stripping, nonce injection and default handling) and
  # the resulting effective header values are what get compared.
  module CspChangeChecker
    module Verdict
      PROVABLY_TIGHTENED = "provably_tightened".freeze
      LOOSENED = "loosened".freeze
      CANNOT_DETERMINE = "cannot_determine".freeze
    end

    Report = Struct.new(
      :verdict, :enforced, :report_only, :notes,
      keyword_init: true
    )
    ChannelReport = Struct.new(
      :verdict, :header_name, :old_header_value, :new_header_value,
      :findings, :unsupported_tokens, :ignored_directives,
      keyword_init: true
    )

    module_function

    # Compare two full secure_headers config hashes (each may contain :csp and
    # :csp_report_only keys).
    def compare(old_config, new_config)
      enforced = compare_channel(
        old_config[:csp], new_config[:csp],
        ContentSecurityPolicyConfig
      )
      report_only = compare_channel(
        old_config[:csp_report_only], new_config[:csp_report_only],
        ContentSecurityPolicyReportOnlyConfig
      )

      Report.new(
        verdict: aggregate(enforced, report_only),
        enforced: enforced,
        report_only: report_only,
        notes: build_notes(enforced, report_only)
      )
    end

    # Convenience wrapper for a single enforced CSP config hash pair.
    def compare_csp(old_hash, new_hash)
      compare({ csp: old_hash }, { csp: new_hash })
    end

    def compare_channel(old_hash, new_hash, config_class)
      return nil if old_hash.nil? && new_hash.nil?

      old_value = render(old_hash, config_class)
      new_value = render(new_hash, config_class)

      if old_value.nil? || new_value.nil?
        return missing_header_report(config_class, old_value, new_value)
      end

      old_policy = EffectivePolicyParser.parse(old_value)
      new_policy = EffectivePolicyParser.parse(new_value)
      findings = DirectiveComparison.compare(old_policy, new_policy)

      ChannelReport.new(
        verdict: channel_verdict(findings),
        header_name: config_class::HEADER_NAME,
        old_header_value: old_value,
        new_header_value: new_value,
        findings: findings,
        unsupported_tokens: old_policy.unsupported + new_policy.unsupported,
        ignored_directives: (old_policy.ignored + new_policy.ignored).uniq
      )
    end

    # Render through the production generator so minification, scheme
    # stripping, nonce/unsafe-inline injection and 'none' handling are applied
    # identically to a real response.
    def render(hash, config_class)
      return nil if hash.nil? || hash == OPT_OUT
      ContentSecurityPolicy.new(config_class.new(hash)).value
    end

    def missing_header_report(config_class, old_value, new_value)
      removed = old_value && new_value.nil?
      ChannelReport.new(
        verdict: Verdict::CANNOT_DETERMINE,
        header_name: config_class::HEADER_NAME,
        old_header_value: old_value,
        new_header_value: new_value,
        findings: [
          DirectiveComparison::Finding.new(
            directive: :header,
            verdict: Verdict::CANNOT_DETERMINE,
            evidence: removed ?
              "the enforced header was removed (OPT_OUT); this cannot be certified as a tightening" :
              "an enforced header was introduced without a previous baseline to compare against",
            witness: nil,
            old_effective_sources: old_value ? [old_value] : [],
            new_effective_sources: new_value ? [new_value] : []
          )
        ],
        unsupported_tokens: [],
        ignored_directives: []
      )
    end

    def channel_verdict(findings)
      return Verdict::CANNOT_DETERMINE if findings.any? do |f|
        f.verdict == Verdict::CANNOT_DETERMINE
      end
      return Verdict::LOOSENED if findings.any? { |f| f.verdict == Verdict::LOOSENED }
      Verdict::PROVABLY_TIGHTENED
    end

    def aggregate(enforced, report_only)
      if enforced.nil? && report_only.nil?
        Verdict::CANNOT_DETERMINE
      elsif enforced.nil?
        # A report-only policy cannot enforce anything, so its "tightening" is
        # never an enforced tightening.
        Verdict::CANNOT_DETERMINE
      else
        enforced.verdict
      end
    end

    def build_notes(enforced, report_only)
      notes = []
      if report_only && enforced.nil?
        notes << "only a report-only policy changed; this does not tighten the enforced policy"
      elsif report_only && enforced.verdict == Verdict::PROVABLY_TIGHTENED
        notes << "report-only changes were assessed separately and do not count toward enforcement"
      end
      notes
    end
  end
end
