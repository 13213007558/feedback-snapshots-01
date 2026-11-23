# frozen_string_literal: true

# Deliberately unsafe controller used to prove the regression tests fail when
# the submit action trusts the policy cached during page rendering instead of
# calling `authorize` after the current user changed. Pundit's legacy cache
# keys policies by record only, so a cached policy built for the previous user
# survives the user switch.
class StalePolicyApprovalController < ApprovalController
  def approve
    @approved_request = approval_request.approve! if policy(approval_request).approve?
    @approved_request
  end
end
