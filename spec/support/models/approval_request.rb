# frozen_string_literal: true

class ApprovalRequest
  def self.pending
    :pending_requests
  end

  def self.routed
    :routed_requests
  end

  def initialize(approver:, state: "pending")
    @approver = approver
    @state = state
  end

  attr_reader :approver
  attr_accessor :state

  def approve!
    raise StandardError, "already decided" unless state == "pending"

    @state = "approved"
    self
  end
end
