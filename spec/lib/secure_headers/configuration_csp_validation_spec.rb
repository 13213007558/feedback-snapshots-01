# frozen_string_literal: true
require "spec_helper"

module SecureHeaders
  describe Configuration, "CSP validation" do
    after { Configuration.csp_validation_mode = :observe }

    def build_config(&block)
      Configuration.new(&block)
    end

    describe ".csp_validation_mode" do
      it "defaults to :observe" do
        expect(Configuration.csp_validation_mode).to eq(:observe)
      end

      it "stores a valid mode and rejects an invalid one without changing it" do
        Configuration.csp_validation_mode = :strict
        expect(Configuration.csp_validation_mode).to eq(:strict)
        expect { Configuration.csp_validation_mode = :nope }.to raise_error(ArgumentError)
        expect(Configuration.csp_validation_mode).to eq(:strict)
      end
    end

    describe "#csp_violations" do
      it "collects enforced and report-only violations with distinct policy tags" do
        config = build_config do |c|
          c.csp = { default_src: %w('self'), script_src: ["a;b"] }
          c.csp_report_only = { default_src: %w('self'), style_src: ["c\nd"] }
        end
        violations = config.csp_violations
        expect(violations.map { |v| [v[:policy], v[:directive]] })
          .to eq([[:enforced, :script_src], [:report_only, :style_src]])
      end

      it "returns an empty array for a clean policy" do
        config = build_config { |c| c.csp = { default_src: %w('self'), script_src: %w('self') } }
        expect(config.csp_violations).to eq([])
      end

      it "ignores opted-out policies" do
        config = build_config do |c|
          c.csp = OPT_OUT
          c.csp_report_only = OPT_OUT
        end
        expect(config.csp_violations).to eq([])
      end
    end

    describe "#validate_config!" do
      it "returns violations in observe mode without raising" do
        config = build_config { |c| c.csp = { default_src: %w('self'), script_src: ["a;b"] } }
        expect(config.validate_config!.map { |v| v[:directive] }).to eq([:script_src])
      end

      it "raises in strict mode and keeps the structured violations" do
        Configuration.csp_validation_mode = :strict
        config = build_config { |c| c.csp = { default_src: %w('self'), script_src: ["a;b"] } }
        expect { config.validate_config! }
          .to raise_error(CspValidation::CspValidationError) do |error|
            expect(error.violations.map { |v| v[:directive] }).to eq([:script_src])
          end
      end
    end

    describe "header parity" do
      CASES = [
        nil,
        { default_src: %w('self'), script_src: %w('self') },
        { default_src: %w(https:), img_src: %w(https: data: 'self'), report_uri: %w(/csp), sandbox: true },
        {
          default_src: %w('self' https:),
          script_src: ["'strict-dynamic'"],
          script_nonce: "abc",
          plugin_types: %w(application/pdf),
          report_to: "endpoint",
        },
      ].freeze

      CASES.each_with_index do |policy, index|
        it "renders case #{index} identically in observe and strict mode" do
          observe = ContentSecurityPolicy.new(policy, validation_mode: :observe).value
          strict = ContentSecurityPolicy.new(policy, validation_mode: :strict).value
          expect(strict).to eq(observe)
        end
      end

      it "keeps the built-in default header identical across modes" do
        observe = ContentSecurityPolicy.new(nil, validation_mode: :observe).value
        strict = ContentSecurityPolicy.new(nil, validation_mode: :strict).value
        expect(strict).to eq(observe)
      end
    end
  end
end
