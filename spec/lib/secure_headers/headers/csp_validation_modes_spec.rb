# frozen_string_literal: true
require "spec_helper"

module SecureHeaders
  describe ContentSecurityPolicy do
    describe "validation modes at the renderer" do
      let(:injecting_config) do
        {
          default_src: %w('self'),
          script_src: ["https://tenant.example.com/app.js; script-src 'unsafe-inline' *"],
          style_src: ["'nonce-secret'\nevil"],
        }
      end

      describe ":observe (default)" do
        it "keeps the legacy scrubbed output and emits the legacy warning" do
          expect(Kernel).to receive(:warn).twice
          csp = ContentSecurityPolicy.new(injecting_config)
          expect(csp.validation_mode).to eq(:observe)
          expect(csp.value).to eq(
            "default-src 'self'; script-src tenant.example.com/app.js  script-src 'unsafe-inline' *; " \
            "style-src 'nonce-secret' evil"
          )
        end

        it "exposes redacted violations without raising" do
          allow(Kernel).to receive(:warn)
          csp = ContentSecurityPolicy.new(injecting_config)
          expect { csp.value }.not_to raise_error
          directives = csp.violations.map { |v| v[:directive] }
          expect(directives).to eq(%i(script_src style_src))
          expect(csp.violations.map { |v| v[:redacted_value] }.join).not_to include("secret")
          expect(csp.violations.map { |v| v[:redacted_value] }.join).not_to include("tenant.example.com")
        end

        it "treats a permissive but syntactically legal policy as valid" do
          csp = ContentSecurityPolicy.new(default_src: %w(* 'unsafe-inline' 'unsafe-eval' data: blob:))
          expect(csp.violations).to be_empty
          expect(csp.value).to eq("default-src * 'unsafe-inline' 'unsafe-eval' data: blob:")
        end
      end

      describe ":strict" do
        it "raises before rendering and never produces a half-built header" do
          csp = ContentSecurityPolicy.new(injecting_config, validation_mode: :strict)
          expect do
            csp.value
          end.to raise_error(CspValidation::CspValidationError) do |error|
            expect(error.violations.map { |v| v[:directive] }).to eq(%i(script_src style_src))
          end
          expect(csp.instance_variable_get(:@value)).to be_nil
        end

        it "renders normally when every directive is clean" do
          csp = ContentSecurityPolicy.new(
            { default_src: %w('self'), script_src: %w(example.org) },
            validation_mode: :strict
          )
          expect(csp.value).to eq("default-src 'self'; script-src example.org")
        end

        it "does not reach the observe-mode scrubber" do
          expect(Kernel).not_to receive(:warn)
          csp = ContentSecurityPolicy.new(injecting_config, validation_mode: :strict)
          expect { csp.value }.to raise_error(CspValidation::CspValidationError)
        end

        it "rejects injection in non-source-list directives too" do
          config = {
            default_src: %w('self'),
            sandbox: ["allow-forms; script-src *"],
            report_to: "endpoint\rX",
          }
          csp = ContentSecurityPolicy.new(config, validation_mode: :strict)
          expect { csp.value }.to raise_error(CspValidation::CspValidationError) do |error|
            expect(error.violations.map { |v| v[:directive] }).to eq(%i(report_to sandbox))
          end
        end
      end

      describe "enforced vs report-only separation" do
        it "tags the report-only policy independently" do
          csp = ContentSecurityPolicy.new(injecting_config.merge(report_only: true))
          expect(csp.violations.map { |v| v[:policy] }.uniq).to eq([:report_only])
          expect(csp.name).to eq(ContentSecurityPolicyReportOnlyConfig::HEADER_NAME)
        end

        it "tags the enforced policy independently" do
          csp = ContentSecurityPolicy.new(injecting_config)
          expect(csp.violations.map { |v| v[:policy] }.uniq).to eq([:enforced])
        end

        it "lets report-only observe while enforced stays strict" do
          enforced = ContentSecurityPolicy.new(injecting_config, validation_mode: :strict)
          report_only = ContentSecurityPolicy.new(injecting_config.merge(report_only: true), validation_mode: :observe)
          allow(Kernel).to receive(:warn)
          expect { enforced.value }.to raise_error(CspValidation::CspValidationError)
          expect { report_only.value }.not_to raise_error
        end
      end

      describe "deterministic results" do
        it "returns identical violation locations across repeated and reordered builds" do
          first = ContentSecurityPolicy.new(injecting_config).violations
          reordered = ContentSecurityPolicy.new(injecting_config.to_a.reverse.to_h).violations
          expect(reordered).to eq(first)
          expect(ContentSecurityPolicy.new(injecting_config).violations).to eq(first)
        end
      end
    end
  end
end
