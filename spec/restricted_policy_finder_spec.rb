# frozen_string_literal: true

require "spec_helper"

RSpec.describe Pundit::RestrictedPolicyFinder do
  let(:allowed) { [Partner::DocumentPolicy, AgreementPolicy] }
  let(:finder_class) { described_class.with_allowed(allowed) }

  describe ".with_allowed" do
    it "returns a distinct subclass per call" do
      other = described_class.with_allowed([Partner::DocumentPolicy])

      expect(finder_class).not_to eq(other)
      expect(finder_class).to be < described_class
    end

    it "records the approved policy names as strings" do
      expect(finder_class.allowed_policy_names).to eq(
        ["Partner::DocumentPolicy", "AgreementPolicy"]
      )
    end

    it "accepts string and symbol policy names" do
      finder = described_class.with_allowed(["Partner::DocumentPolicy", :"AgreementPolicy"])

      expect(finder.allowed_policy_names).to eq(
        ["Partner::DocumentPolicy", "AgreementPolicy"]
      )
    end

    it "deduplicates the allowlist" do
      finder = described_class.with_allowed([Partner::DocumentPolicy, "Partner::DocumentPolicy"])

      expect(finder.allowed_policy_names).to eq(["Partner::DocumentPolicy"])
    end
  end

  describe ".allowed_policy_names" do
    it "approves nothing on the base class" do
      expect(described_class.allowed_policy_names).to eq([])
    end
  end

  describe "#policy" do
    it "resolves an allowlisted policy" do
      expect(finder_class.new(Partner::Document).policy).to eq(Partner::DocumentPolicy)
    end

    it "resolves an allowlisted custom policy_class model" do
      expect(finder_class.new(Contract).policy).to eq(AgreementPolicy)
    end

    it "returns nil when no policy can be located" do
      expect(finder_class.new(Foo).policy).to be_nil
    end

    it "raises NotApprovedError when the policy exists but is not approved" do
      expect { finder_class.new(Internal::Document).policy }
        .to raise_error(Pundit::NotApprovedError, /Internal::DocumentPolicy/)
    end

    it "keeps the namespace lookup but still enforces the allowlist" do
      namespaced = described_class.with_allowed([Project::PostPolicy])

      expect(namespaced.new([:project, Post]).policy).to eq(Project::PostPolicy)
      expect { namespaced.new(Post).policy }.to raise_error(Pundit::NotApprovedError)
    end

    it "treats a located-but-unapproved policy differently from a missing one" do
      missing = begin
        finder_class.new(Foo).policy
      rescue StandardError => e
        e
      end
      unapproved = begin
        finder_class.new(Internal::Document).policy
      rescue StandardError => e
        e
      end

      expect(missing).to be_nil
      expect(unapproved).to be_a(Pundit::NotApprovedError)
      expect(unapproved).to be_a(Pundit::NotDefinedError)
    end
  end

  describe "#policy!" do
    it "resolves an allowlisted policy" do
      expect(finder_class.new(Partner::Document).policy!).to eq(Partner::DocumentPolicy)
    end

    it "raises NotDefinedError when the policy cannot be located" do
      expect { finder_class.new(Foo).policy! }
        .to raise_error(Pundit::NotDefinedError, /unable to find policy `FooPolicy`/)
    end

    it "raises NotApprovedError, not NotDefinedError, when the policy is unapproved" do
      expect { finder_class.new(Internal::Document).policy! }
        .to raise_error(Pundit::NotApprovedError, /not approved/)
    end
  end

  describe "#scope and #scope!" do
    it "resolves the scope of an allowlisted policy" do
      expect(finder_class.new(Partner::Document).scope).to eq(Partner::DocumentPolicy::Scope)
      expect(finder_class.new(Partner::Document).scope!).to eq(Partner::DocumentPolicy::Scope)
    end

    it "refuses the scope when its policy is not approved" do
      expect { finder_class.new(Internal::Document).scope! }
        .to raise_error(Pundit::NotApprovedError)
    end
  end
end
