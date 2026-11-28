# frozen_string_literal: true

module Doorkeeper
  module OpenidConnect
    # Records the current request so the policy-aware Doorkeeper request
    # objects can resolve the registration space that received it. Prepended to
    # `Doorkeeper::AuthorizationsController` and `Doorkeeper::TokensController`
    # by the engine; those are the two controllers whose request strategies
    # enforce a space's capabilities.
    #
    # The name deliberately differs from `CapabilityPolicyContext` (the
    # `CurrentAttributes` store in lib/): both live under this namespace and a
    # collision would let one autoloader replace the other's constant.
    module CapabilityPolicyRequestContext
      def self.prepended(base)
        base.prepend_before_action :remember_capability_policy_request
      end

      private

      def remember_capability_policy_request
        OpenidConnect::CapabilityPolicyContext.request = request
      end
    end
  end
end
