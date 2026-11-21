# frozen_string_literal: true

module Partner
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
