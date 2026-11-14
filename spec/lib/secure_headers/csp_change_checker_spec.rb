# frozen_string_literal: true
require "spec_helper"
require "secure_headers/csp_change_checker"

module SecureHeaders
  describe CspChangeChecker do
    describe "#compare_csp" do
      it "certifies a proven tightening when a host source is removed" do
        report = CspChangeChecker.compare_csp(
          { default_src: %w('self'), script_src: %w('self' cdn.example.com) },
          { default_src: %w('self'), script_src: %w('self') }
        )
        expect(report.verdict).to eq(CspChangeChecker::Verdict::PROVABLY_TIGHTENED)
        expect(report.enforced.findings.map(&:directive)).to include(:script_src)
      end

      it "cannot certify a port pinning as tightening without origin default-port evidence" do
        report = CspChangeChecker.compare_csp(
          { default_src: %w(api.example.com) },
          { default_src: %w(api.example.com:443) }
        )
        # The bare host is not proven to cover the port-pinned grant, so the
        # checker will not issue a green verdict; it reports the new grant.
        expect(report.verdict).to eq(CspChangeChecker::Verdict::LOOSENED)
        expect(report.enforced.findings.first.witness).to include("api.example.com:443")
      end

      it "treats an equivalent effective policy as tightened (scheme stripping)" do
        report = CspChangeChecker.compare_csp(
          { default_src: %w(https://cdn.example.com) },
          { default_src: %w(cdn.example.com) }
        )
        # Both render to "default-src cdn.example.com" via the real generator.
        expect(report.enforced.old_header_value).to eq(report.enforced.new_header_value)
        expect(report.verdict).to eq(CspChangeChecker::Verdict::PROVABLY_TIGHTENED)
      end

      it "detects a loosening hidden behind an append + default-src fallback" do
        old_hash = { default_src: %w('none'), script_src: %w('self') }
        # combine_policies copies default-src into the previously missing img-src,
        # then unions the new host. The effective img-src gains tracker.example.com.
        new_hash = ContentSecurityPolicy.combine_policies(
          old_hash, img_src: %w(tracker.example.com)
        )

        report = CspChangeChecker.compare_csp(old_hash, new_hash)

        expect(report.verdict).to eq(CspChangeChecker::Verdict::LOOSENED)
        finding = report.enforced.findings.find { |f| f.directive == :img_src }
        expect(finding.verdict).to eq(CspChangeChecker::Verdict::LOOSENED)
        expect(finding.witness).to include("tracker.example.com")
      end

      it "detects loosening when none is silently dropped by adding a source" do
        report = CspChangeChecker.compare_csp(
          { default_src: %w('self'), object_src: %w('none') },
          { default_src: %w('self'), object_src: %w('none' plugin.example.com) }
        )
        expect(report.verdict).to eq(CspChangeChecker::Verdict::LOOSENED)
        finding = report.enforced.findings.find { |f| f.directive == :object_src }
        expect(finding.old_effective_sources).to eq([])
        expect(finding.new_effective_sources).to eq(%w(plugin.example.com))
        expect(finding.witness).to include("plugin.example.com")
      end

      it "detects a wildcard expansion that a string diff would misorder" do
        report = CspChangeChecker.compare_csp(
          { default_src: %w(https://*.example.com) },
          { default_src: %w(*.example.com) }
        )
        expect(report.verdict).to eq(CspChangeChecker::Verdict::LOOSENED)
        expect(report.enforced.findings.first.witness).to include("sub.example.com")
      end

      it "detects removal of a fetch directive as loosening via default-src fallback" do
        report = CspChangeChecker.compare_csp(
          { default_src: %w('self'), img_src: %w('none') },
          { default_src: %w('self') }
        )
        expect(report.verdict).to eq(CspChangeChecker::Verdict::LOOSENED)
        finding = report.enforced.findings.find { |f| f.directive == :img_src }
        expect(finding.evidence).to include("'self'")
      end

      it "returns cannot_determine when a nonce appears in the effective policy" do
        report = CspChangeChecker.compare_csp(
          { default_src: %w('self'), script_src: %w('self') },
          {
            default_src: %w('self'),
            script_src: %w('self'),
            script_nonce: "abc123",
            disable_nonce_backwards_compatibility: true
          }
        )
        expect(report.verdict).to eq(CspChangeChecker::Verdict::CANNOT_DETERMINE)
        expect(report.enforced.unsupported_tokens.map(&:token)).to include("'nonce-abc123'")
      end

      it "returns cannot_determine for strict-dynamic instead of certifying it" do
        report = CspChangeChecker.compare_csp(
          { default_src: %w('self'), script_src: %w('self') },
          {
            default_src: %w('self'),
            script_src: [ContentSecurityPolicy::STRICT_DYNAMIC],
            script_nonce: "abc123",
            disable_nonce_backwards_compatibility: true
          }
        )
        expect(report.verdict).to eq(CspChangeChecker::Verdict::CANNOT_DETERMINE)
      end

      it "returns cannot_determine when an unsupported directive changes" do
        report = CspChangeChecker.compare_csp(
          { default_src: %w('self') },
          { default_src: %w('self'), sandbox: %w(allow-scripts) }
        )
        expect(report.verdict).to eq(CspChangeChecker::Verdict::CANNOT_DETERMINE)
        expect(report.enforced.findings.map(&:directive)).to include(:sandbox)
      end

      it "does not mistake report-only tightening for enforced tightening" do
        report = CspChangeChecker.compare(
          {
            csp: { default_src: %w('self'), img_src: %w(cdn.example.com) },
            csp_report_only: { default_src: %w('self'), img_src: %w(cdn.example.com tracker.example.com) }
          },
          {
            csp: { default_src: %w('self'), img_src: %w(cdn.example.com) },
            csp_report_only: { default_src: %w('self'), img_src: %w(cdn.example.com) }
          }
        )
        expect(report.report_only.verdict).to eq(CspChangeChecker::Verdict::PROVABLY_TIGHTENED)
        expect(report.verdict).to eq(CspChangeChecker::Verdict::PROVABLY_TIGHTENED)
        expect(report.notes.first).to include("report-only")
      end

      it "refuses a tightening verdict when only the report-only policy exists" do
        report = CspChangeChecker.compare(
          { csp_report_only: { default_src: %w('self' tracker.example.com) } },
          { csp_report_only: { default_src: %w('self') } }
        )
        expect(report.report_only.verdict).to eq(CspChangeChecker::Verdict::PROVABLY_TIGHTENED)
        expect(report.verdict).to eq(CspChangeChecker::Verdict::CANNOT_DETERMINE)
      end

      it "keeps enforced loosening decisive even when report-only tightens" do
        report = CspChangeChecker.compare(
          { csp: { default_src: %w('self') } },
          { csp: { default_src: %w('self' tracker.example.com) } }
        )
        expect(report.verdict).to eq(CspChangeChecker::Verdict::LOOSENED)
        expect(report.enforced.findings.first.witness).to include("tracker.example.com")
      end

      it "treats a newly added non-fetch directive as loosening without default-src fallback" do
        report = CspChangeChecker.compare_csp(
          { default_src: %w('none'), script_src: %w('self') },
          {
            default_src: %w('none'),
            script_src: %w('self'),
            form_action: %w(login.example.com)
          }
        )
        expect(report.verdict).to eq(CspChangeChecker::Verdict::LOOSENED)
        finding = report.enforced.findings.find { |f| f.directive == :form_action }
        expect(finding.old_effective_sources).to eq([])
        expect(finding.witness).to include("login.example.com")
      end

      it "refuses a green verdict when the enforced header is opted out" do
        report = CspChangeChecker.compare(
          { csp: { default_src: %w('self') } },
          { csp: SecureHeaders::OPT_OUT }
        )
        expect(report.verdict).to eq(CspChangeChecker::Verdict::CANNOT_DETERMINE)
        expect(report.enforced.new_header_value).to be_nil
      end

      it "compares effective headers, not raw config hashes, across override merges" do
        old_hash = {
          default_src: %w(https:),
          script_src: %w('self'),
          style_src: %w('self')
        }
        new_hash = old_hash.merge(style_src: %w('self'))
        # A no-op merge must not be reported as a change even though hashes differ in nesting.
        report = CspChangeChecker.compare_csp(old_hash, new_hash)
        expect(report.enforced.old_header_value).to eq(report.enforced.new_header_value)
        expect(report.verdict).to eq(CspChangeChecker::Verdict::PROVABLY_TIGHTENED)
      end
    end
  end
end
