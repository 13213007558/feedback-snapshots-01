# frozen_string_literal: true
require "spec_helper"

module SecureHeaders
  describe CspValidation do
    let(:policy_hash) do
      {
        default_src: %w('self'),
        script_src: ["https://tenant-acme.example.com/app.js;script-src 'unsafe-inline' *"],
        style_src: ["'nonce-secret-value'\nevil"],
        sandbox: ["allow-forms\rallow-scripts"],
        report_to: "endpoint; script-src *",
      }
    end

    describe ".resolve_mode" do
      after { Configuration.csp_validation_mode = :observe }

      it "defaults to :observe" do
        expect(described_class.resolve_mode(nil)).to eq(:observe)
      end

      it "prefers an explicit mode over the global setting" do
        Configuration.csp_validation_mode = :strict
        expect(described_class.resolve_mode(:observe)).to eq(:observe)
      end

      it "falls back to the global setting when no mode is given" do
        Configuration.csp_validation_mode = :strict
        expect(described_class.resolve_mode(nil)).to eq(:strict)
      end
    end

    describe ".validate_mode!" do
      it "accepts the known modes" do
        expect(described_class.validate_mode!(:observe)).to eq(:observe)
        expect(described_class.validate_mode!(:strict)).to eq(:strict)
      end

      it "rejects unknown modes" do
        expect { described_class.validate_mode!(:nope) }
          .to raise_error(ArgumentError, /Unknown CSP validation mode/)
      end
    end

    describe ".violations_for" do
      subject(:violations) { described_class.violations_for(policy_hash) }

      it "returns one violation per offending token" do
        expect(violations.map { |v| v[:directive] })
          .to eq(%i(report_to sandbox script_src style_src))
      end

      it "is a subclass of ContentSecurityPolicyConfigError" do
        expect(CspValidation::CspValidationError.superclass).to eq(ContentSecurityPolicyConfigError)
      end

      it "locates the offending character offsets and the offending bytes" do
        raw_token = policy_hash[:script_src].first
        script = violations.find { |v| v[:directive] == :script_src }
        expect(script[:offending_bytes]).to eq([";"])
        expect(script[:char_offsets]).to eq([raw_token.index(";")])
        expect(script[:token_index]).to eq(0)
      end

      it "records every offending offset when one token has several" do
        hash = { default_src: ["ab;cd\nef"] }
        result = described_class.violations_for(hash)
        expect(result.first[:char_offsets]).to eq([2, 5])
        expect(result.first[:offending_bytes]).to eq([";", "\n"])
      end

      it "redacts nonce material but keeps the nonce shape" do
        style = violations.find { |v| v[:directive] == :style_src }
        expect(style[:redacted_value]).to eq("'nonce-[REDACTED]'\nevil")
        expect(style[:redacted_value]).not_to include("secret-value")
      end

      it "redacts the host and port of an absolute tenant URL but keeps the path" do
        script = violations.find { |v| v[:directive] == :script_src }
        expect(script[:redacted_value]).to eq("https://[REDACTED]/app.js;script-src 'unsafe-inline' *")
        expect(script[:redacted_value]).not_to include("tenant-acme")
      end

      it "uses nil token_index for the scalar report-to directive" do
        report_to = violations.find { |v| v[:directive] == :report_to }
        expect(report_to[:token_index]).to be_nil
      end

      it "annotates the policy kind and source" do
        result = described_class.violations_for(
          policy_hash,
          policy_kind: CspValidation::REPORT_ONLY_POLICY,
          source: :request_append
        )
        expect(result.first[:policy]).to eq(:report_only)
        expect(result.first[:source]).to eq(:request_append)
      end

      it "does not flag syntactically legal but permissive policies" do
        loose = {
          default_src: %w(* 'unsafe-inline' 'unsafe-eval' data: blob: https:),
          script_src: %w('strict-dynamic' 'nonce-abc'),
        }
        expect(described_class.violations_for(loose)).to be_empty
      end

      it "ignores OPT_OUT and nil directive values" do
        hash = { default_src: OPT_OUT, script_src: nil, img_src: ["ok;x"] }
        expect(described_class.violations_for(hash).map { |v| v[:directive] }).to eq([:img_src])
      end

      it "orders results deterministically regardless of input hash order" do
        reversed = policy_hash.to_a.reverse.to_h
        expect(described_class.violations_for(reversed)).to eq(violations)
      end

      it "sorts report-only violations after enforced ones" do
        enforced = described_class.violations_for(
          { script_src: ["a;b"] }, policy_kind: CspValidation::ENFORCED_POLICY
        )
        report_only = described_class.violations_for(
          { style_src: ["c\nd"] }, policy_kind: CspValidation::REPORT_ONLY_POLICY
        )
        combined = described_class.strict_violation_error([report_only, enforced]).violations
        expect(combined.map { |v| v[:policy] }).to eq(%i(enforced report_only))
      end

      it "accepts a config object as well as a plain hash" do
        config = ContentSecurityPolicyConfig.new(default_src: %w('self'), script_src: ["a;b"])
        expect(described_class.violations_for(config).map { |v| v[:directive] }).to eq([:script_src])
      end
    end

    describe ".redact" do
      it "redacts a nonce without leaking its value" do
        expect(described_class.redact("'nonce-xyz123'")).to eq("'nonce-[REDACTED]'")
      end

      it "redacts the host of an absolute URL and keeps the path" do
        expect(described_class.redact("https://tenant.example.com:8443/path/file.js"))
          .to eq("https://[REDACTED]/path/file.js")
      end

      it "leaves ordinary host sources untouched" do
        expect(described_class.redact("cdn.example.com")).to eq("cdn.example.com")
      end
    end

    describe ".strict_violation_error" do
      it "returns nil when there are no violations" do
        expect(described_class.strict_violation_error([])).to be_nil
      end

      it "builds an error carrying every violation, flattened across policies" do
        violations = [
          described_class.violations_for({ script_src: ["a;b"] }, policy_kind: CspValidation::ENFORCED_POLICY),
          described_class.violations_for({ style_src: ["c\nd"] }, policy_kind: CspValidation::REPORT_ONLY_POLICY),
        ]
        error = described_class.strict_violation_error(violations)
        expect(error).to be_a(CspValidation::CspValidationError)
        expect(error.violations.map { |v| v[:directive] }).to eq(%i(script_src style_src))
      end
    end
  end
end
