# frozen_string_literal: true

class ProfilePolicy < BasePolicy
  NORMAL_ATTRIBUTES = %i[name bio].freeze
  PROTECTED_ATTRIBUTES = %i[role verified].freeze

  alias_method :profile, :record

  def show?
    true
  end

  def update?
    profile.owner == user
  end

  def update_protected?
    user.respond_to?(:admin?) && user.admin?
  end

  def permitted_attributes
    NORMAL_ATTRIBUTES
  end

  def permitted_attributes_for_update_protected
    NORMAL_ATTRIBUTES + PROTECTED_ATTRIBUTES
  end
end
