# frozen_string_literal: true

# A model that deliberately points at a policy whose name does not follow the
# `ModelNamePolicy` convention, to exercise the custom `policy_class` lookup
# path under a restricted finder.
class Contract
  def self.policy_class
    AgreementPolicy
  end

  def self.signed
    :signed_contracts
  end
end
