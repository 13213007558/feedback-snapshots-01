# frozen_string_literal: true

# A controller standing in for the external partner entry point. It reuses the
# standard Pundit controller DSL but swaps the policy finder for a restricted
# one that may only resolve the policy classes the partner has registered.
class PartnerController < Controller
  ALLOWED_POLICIES = [
    Partner::DocumentPolicy,
    AgreementPolicy
  ].freeze

  def self.policy_finder_class
    Pundit::RestrictedPolicyFinder.with_allowed(ALLOWED_POLICIES)
  end

  protected

  def pundit_policy_finder_class
    self.class.policy_finder_class
  end
end
