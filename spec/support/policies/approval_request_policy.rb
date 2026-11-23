# frozen_string_literal: true

class ApprovalRequestPolicy < BasePolicy
  class Scope < BaseScope
    def resolve
      scope.pending
    end
  end

  alias_method :approval_request, :record

  def approve?
    approval_request.approver == user
  end
end
