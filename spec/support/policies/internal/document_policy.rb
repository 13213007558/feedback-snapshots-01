# frozen_string_literal: true

module Internal
  class DocumentPolicy < BasePolicy
    class Scope < BaseScope
      def resolve
        scope.published
      end
    end

    alias_method :document, :record

    def show?
      true
    end
  end
end
