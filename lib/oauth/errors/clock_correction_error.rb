# frozen_string_literal: true

module OAuth
  # Raised when an opt-in clock correction run cannot safely complete.
  # The accompanying #outcome contains the audit trail and manual retry state.
  class ClockCorrectionError < OAuth::Error
    attr_reader :outcome

    def initialize(message = nil, outcome = nil)
      super(message)
      @outcome = outcome
    end
  end
end
