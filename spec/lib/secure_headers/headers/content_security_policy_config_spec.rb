# frozen_string_literal: true
require "spec_helper"

module SecureHeaders
  describe CspPolicyEntry do
    let(:enforced_hash) { { default_src: %w('self'), script_src: %w('self') } }
    let(:report_hash) { { default_src: %w('self'), script_src: %w(report.example) } }

    def build(hash)
      ContentSecurityPolicyConfig.new(hash)
    end

    it "builds an enforced header from a config hash" do
      entry = CspPolicyEntry.new(build(enforced_hash))
      name, value = entry.header(:enforced)
      expect(name).to eq(ContentSecurityPolicyConfig::HEADER_NAME)
      expect(value).to eq("default-src 'self'; script-src 'self'")
    end

    it "builds a report-only header from a report-only config" do
      report = ContentSecurityPolicyReportOnlyConfig.new(report_hash)
      entry = CspPolicyEntry.new(build(enforced_hash), report)
      name, value = entry.header(:report_only)
      expect(name).to eq(ContentSecurityPolicyReportOnlyConfig::HEADER_NAME)
      expect(value).to eq("default-src 'self'; script-src report.example")
    end

    it "coerces a plain hash assigned to report_only into a report-only config" do
      entry = CspPolicyEntry.new(build(enforced_hash))
      entry.report_only = report_hash
      expect(entry.report_only).to be_a(ContentSecurityPolicyReportOnlyConfig)
      expect(entry.report_only.report_only?).to be true
    end

    it "converts an enforced config assigned to report_only" do
      entry = CspPolicyEntry.new(build(enforced_hash))
      entry.report_only = build(enforced_hash)
      expect(entry.report_only).to be_a(ContentSecurityPolicyReportOnlyConfig)
    end

    it "returns no header for an opted-out mode" do
      entry = CspPolicyEntry.new(build(enforced_hash), OPT_OUT)
      expect(entry.header(:report_only)).to be_nil
      expect(entry.header(:enforced)).not_to be_nil
    end

    it "is opted out only when both modes are" do
      expect(CspPolicyEntry.new(OPT_OUT, OPT_OUT).opt_out?).to be true
      expect(CspPolicyEntry.new(build(enforced_hash), OPT_OUT).opt_out?).to be false
    end

    it "deep dups both configs" do
      entry = CspPolicyEntry.new(build(enforced_hash), ContentSecurityPolicyReportOnlyConfig.new(report_hash))
      copy = entry.dup
      expect(copy).to eq(entry)
      expect(copy.enforced).not_to be(entry.enforced)
      expect(copy.report_only).not_to be(entry.report_only)

      copy.enforced.update_directive(:script_src, %w(mutated.example))
      expect(entry.enforced.directive_value(:script_src)).to eq(%w('self'))
    end

    it "keeps OPT_OUT through dup" do
      entry = CspPolicyEntry.new(OPT_OUT, OPT_OUT)
      expect(entry.dup).to eq(entry)
    end

    it "rejects an unsupported enforced value" do
      expect { CspPolicyEntry.new(123) }.to raise_error(ArgumentError)
    end

    it "rejects an unsupported report_only value" do
      entry = CspPolicyEntry.new(build(enforced_hash))
      expect { entry.report_only = 123 }.to raise_error(ArgumentError)
    end
  end
end