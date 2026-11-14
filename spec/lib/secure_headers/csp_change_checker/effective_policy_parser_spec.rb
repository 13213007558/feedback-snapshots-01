# frozen_string_literal: true
require "spec_helper"
require "secure_headers/csp_change_checker"

module SecureHeaders
  module CspChangeChecker
    describe EffectivePolicyParser do
      it "parses supported scheme, host, port and keyword sources" do
        value = "default-src 'self' https: cdn.example.com:443; img-src data:"
        policy = EffectivePolicyParser.parse(value)

        default_src = policy.directives[:default_src]
        expect(default_src.map { |t| t[:kind] }).to eq(%i(keyword scheme host))
        expect(default_src.last[:host]).to eq("cdn.example.com")
        expect(default_src.last[:port]).to eq("443")
        expect(policy.unsupported).to be_empty
      end

      it "records wildcard hosts with their registrable domain" do
        policy = EffectivePolicyParser.parse("default-src *.cdn.example.com")
        token = policy.directives[:default_src].first
        expect(token[:wildcard]).to eq(true)
        expect(token[:host]).to eq("cdn.example.com")
      end

      it "flags nonce tokens as unsupported and keeps the directive uncertifiable" do
        policy = EffectivePolicyParser.parse("script-src 'nonce-abc123' 'unsafe-inline'")
        expect(policy.directives[:script_src].map { |t| t[:kind] }).to include(:unsupported)
        expect(policy.unsupported.first.reason).to include("nonce")
      end

      it "flags hash sources as unsupported" do
        policy = EffectivePolicyParser.parse("script-src 'sha256-abc'")
        expect(policy.unsupported.first.reason).to include("hash-source")
      end

      it "flags path-scoped hosts as unsupported" do
        policy = EffectivePolicyParser.parse("default-src cdn.example.com/assets/")
        expect(policy.unsupported.first.reason).to include("path-scoped")
      end

      it "ignores reporting directives rather than treating them as enforced allow-lists" do
        policy = EffectivePolicyParser.parse(
          "default-src 'self'; report-to endpoint; report-uri https://r.example/csp"
        )
        expect(policy.ignored).to contain_exactly(:report_to, :report_uri)
        expect(policy.directives).not_to have_key(:report_uri)
      end

      it "flags directives outside the supported set" do
        policy = EffectivePolicyParser.parse("sandbox allow-scripts; default-src 'none'")
        expect(policy.directives).to have_key(:sandbox)
        expect(policy.unsupported.map(&:directive)).to include(:sandbox)
      end
    end
  end
end
