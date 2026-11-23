# frozen_string_literal: true

# Deliberately unsafe controller used to prove the regression tests fail when
# the submit action never calls `authorize`: the view's policy query alone does
# not satisfy the controller's authorization verification.
class UnauthorizedApprovalController < ApprovalController
  def approve
    @approved_request = approval_request.approve!
    verify_authorized
    @approved_request
  end
end
