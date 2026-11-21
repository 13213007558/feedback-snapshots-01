# frozen_string_literal: true

module Organization
  class ResourcePolicy < BasePolicy
    alias_method :resource, :record

    def approve?
      resource.owner == user
    end
  end
end
