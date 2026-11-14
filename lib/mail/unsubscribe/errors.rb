# encoding: utf-8
# frozen_string_literal: true
module Mail
  module Unsubscribe
    class Error < StandardError; end

    # Raised when an action is confirmed without a transport adapter.
    class TransportRequiredError < Error; end

    # Raised when the supplied transport adapter cannot perform a POST.
    class InvalidTransportError < Error; end

    # Raised when an action that has already been confirmed is confirmed again.
    class AlreadyConfirmedError < Error; end

    # Raised by Mail::Unsubscribe.parse! when no one-click action qualifies.
    class NotEligibleError < Error; end
  end
end
