# frozen_string_literal: true

class ApprovalController < Controller
  attr_reader :approved_request, :authorization_error

  def index
    policy_scope(ApprovalRequest)
    verify_policy_scoped
    render_decisions
  end

  def approve
    authorize(approval_request, :approve?)
    @approved_request = approval_request.approve!
    verify_authorized
    @approved_request
  rescue Pundit::NotAuthorizedError => error
    @authorization_error = error
    raise
  end

  private

  def approval_request
    params[:approval_request]
  end

  def requests
    params[:requests]
  end

  def render_decisions
    view = View.new(self)
    requests.map { |request| "#{request.state}:#{view.policy(request).approve?}" }.join(",")
  end
end
