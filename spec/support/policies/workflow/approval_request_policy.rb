# frozen_string_literal: true

module Workflow
  class ApprovalRequestPolicy < BasePolicy
    class Scope < BasePolicy::BaseScope
      def resolve
        scope.routed
      end
    end

    alias_method :approval_request, :record

    def approve?
      approval_request.approver == user
    end
  end
end
