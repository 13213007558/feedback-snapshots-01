# frozen_string_literal: true

require "spec_helper"
require "action_controller"

RSpec.describe PartnerController, type: :controller do
  let(:user) { double("partner user") }
  let(:controller) { Controller.new(user, "show", ActionController::Parameters.new) }
  let(:partner_controller) { described_class.new(user, "show", ActionController::Parameters.new) }

  describe "finder wiring" do
    it "uses the unrestricted PolicyFinder on the internal controller" do
      expect(controller.pundit.policy_finder_class).to eq(Pundit::PolicyFinder)
    end

    it "uses a restricted finder on the partner controller" do
      expect(partner_controller.pundit.policy_finder_class).to be < Pundit::RestrictedPolicyFinder
    end

    it "registers only the partner allowlist" do
      expect(partner_controller.pundit.policy_finder_class.allowed_policy_names).to eq(
        ["Partner::DocumentPolicy", "AgreementPolicy"]
      )
    end
  end

  describe "#authorize" do
    it "authorizes an allowlisted namespaced policy and hands back the record" do
      document = Partner::Document.new

      expect(partner_controller.authorize(document, :show?)).to be(document)
    end

    it "actually instantiates the allowed partner policy" do
      document = Partner::Document.new
      partner_controller.authorize(document, :show?)

      expect(partner_controller.pundit_policies[document]).to be_a(Partner::DocumentPolicy)
    end

    it "authorizes the model with a custom policy_class when it is allowlisted" do
      contract = Contract.new

      expect(partner_controller.authorize(contract, :show?)).to be(contract)
      expect(partner_controller.pundit_policies[contract]).to be_a(AgreementPolicy)
    end

    it "raises NotApprovedError for a policy the partner has not registered" do
      expect { partner_controller.authorize(Internal::Document, :show?) }
        .to raise_error(Pundit::NotApprovedError, /Internal::DocumentPolicy.*not approved/)
    end

    it "raises NotDefinedError for a policy that does not exist" do
      expect { partner_controller.authorize(Foo, :show?) }
        .to raise_error(Pundit::NotDefinedError, /unable to find policy `FooPolicy`/)
    end

    it "still permits the internal controller to use every policy" do
      internal = Controller.new(user, "show", ActionController::Parameters.new)

      expect(internal.authorize(Internal::Document, :show?)).to eq(Internal::Document)
      expect(internal.pundit_policies[Internal::Document]).to be_a(Internal::DocumentPolicy)
    end
  end

  describe "#policy_scope" do
    it "resolves through the allowlisted partner policy scope" do
      expect(partner_controller.policy_scope(Partner::Document)).to eq(:partner_published)
    end

    it "resolves the custom policy_class scope through the allowed policy" do
      expect(partner_controller.policy_scope(Contract)).to eq(:signed_contracts)
    end

    it "refuses to scope through an unregistered policy" do
      expect { partner_controller.policy_scope(Internal::Document) }
        .to raise_error(Pundit::NotApprovedError)
    end

    it "keeps policy_scope working without restriction on the internal controller" do
      internal = Controller.new(user, "index", ActionController::Parameters.new)

      expect(internal.policy_scope(Internal::Document)).to eq(:internal_published)
    end
  end

  describe "both entry points against the same model" do
    it "routes the partner and internal call to their own policies" do
      document = Partner::Document.new
      internal = Controller.new(user, "show", ActionController::Parameters.new)

      partner_controller.authorize(document, :show?)
      internal.authorize(Partner::Document, :show?)

      expect(partner_controller.pundit_policies[document]).to be_a(Partner::DocumentPolicy)
      expect(internal.pundit_policies[Partner::Document]).to be_a(Partner::DocumentPolicy)
    end
  end
end
