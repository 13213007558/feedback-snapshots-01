# frozen_string_literal: true
require "spec_helper"
require "secure_headers/csp_change_checker"

module SecureHeaders
  module CspChangeChecker
    describe SourceSetSemantics do
      def host(raw)
        EffectivePolicyParser.parse("default-src #{raw}").directives[:default_src].first
      end

      def scheme(raw)
        EffectivePolicyParser.parse("default-src #{raw}").directives[:default_src].first
      end

      describe ".covers?" do
        it "treats identical hosts as covering" do
          expect(SourceSetSemantics.covers?(host("a.example.com"), host("a.example.com"))).to eq(true)
        end

        it "does not treat a registrable domain as covering its wildcard subdomains" do
          expect(SourceSetSemantics.covers?(host("example.com"), host("*.example.com"))).to eq(false)
        end

        it "treats a wildcard subdomain grant as covering an exact subdomain" do
          expect(SourceSetSemantics.covers?(host("*.example.com"), host("a.example.com"))).to eq(true)
        end

        it "does not let a wildcard cover its own registrable domain" do
          expect(SourceSetSemantics.covers?(host("*.example.com"), host("example.com"))).to eq(false)
        end

        it "treats a port-pinned host as narrower than an unpinned host" do
          expect(SourceSetSemantics.covers?(host("a.example.com"), host("a.example.com:443"))).to eq(false)
          expect(SourceSetSemantics.covers?(host("a.example.com:443"), host("a.example.com"))).to eq(false)
          expect(SourceSetSemantics.covers?(host("a.example.com:443"), host("a.example.com:443"))).to eq(true)
        end

        it "treats ** wildcard ports as covering a concrete port" do
          expect(SourceSetSemantics.covers?(host("a.example.com:**"), host("a.example.com:443"))).to eq(true)
        end

        it "does not let a bare host cover a scheme-pinned host" do
          expect(SourceSetSemantics.covers?(host("a.example.com"), host("https://a.example.com"))).to eq(false)
        end

        it "does not let a scheme grant cover a bare host source" do
          expect(SourceSetSemantics.covers?(scheme("https:"), host("a.example.com"))).to eq(false)
        end

        it "lets an https scheme grant cover an https-pinned host" do
          expect(SourceSetSemantics.covers?(scheme("https:"), host("https://a.example.com"))).to eq(true)
        end

        it "never treats * as covering data: or blob:" do
          star = EffectivePolicyParser.parse("default-src *").directives[:default_src].first
          expect(SourceSetSemantics.covers?(star, scheme("data:"))).to eq(false)
          expect(SourceSetSemantics.covers?(star, scheme("blob:"))).to eq(false)
        end

        it "compares discrete keywords by equality only" do
          old = EffectivePolicyParser.parse("script-src 'unsafe-inline'").directives[:script_src].first
          new = EffectivePolicyParser.parse("script-src 'unsafe-eval'").directives[:script_src].first
          expect(SourceSetSemantics.covers?(old, new)).to eq(false)
        end
      end

      describe ".normalize_none" do
        it "maps a lone none to an empty allow-set" do
          tokens = EffectivePolicyParser.parse("object-src 'none'").directives[:object_src]
          expect(SourceSetSemantics.normalize_none(tokens)).to eq([])
        end

        it "drops none when other sources survive minification" do
          tokens = EffectivePolicyParser.parse("child-src 'none' 'self'").directives[:child_src]
          normalized = SourceSetSemantics.normalize_none(tokens)
          expect(normalized.map { |t| t[:kind] }).to eq([:keyword])
        end
      end

      describe ".witness_for" do
        it "builds a concrete resource URL for a newly added host" do
          token = host("https://tracker.example.com:443")
          expect(SourceSetSemantics.witness_for(:img_src, token))
            .to eq("https://tracker.example.com:443/resource (newly allowed host in img_src)")
        end
      end
    end
  end
end
