# frozen_string_literal: true

class ApprovablePolicy < BasePolicy
  alias_method :approvable, :record

  def approve?
    approvable.owner == user
  end
end
