# frozen_string_literal: true

module Grape
  module Exceptions
    # A request whose validation exceeded Grape.config.validation_work_budget.
    # A distinct class rather than a Validation keeps the category stable for
    # rescue_from handlers and for clients that branch on the error.
    class ValidationBudgetExceeded < Base
      attr_reader :limit, :spent

      def initialize(limit:, spent:)
        @limit = limit
        @spent = spent
        super(status: 400, message: compose_message(:validation_budget, limit:))
      end
    end
  end
end
