# frozen_string_literal: true

class AgreementPolicy < BasePolicy
  class Scope < BaseScope
    def resolve
      scope.signed
    end
  end

  alias_method :contract, :record

  def show?
    true
  end
end
