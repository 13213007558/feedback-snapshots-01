# frozen_string_literal: true

module JWT
  # @private
  class EncodedToken
    # Allow access to the unverified payload for claim verification.
    #
    # The context takes one snapshot of the token's diagnostic values for the
    # whole verification, so individual claim checks cannot observe different
    # contents. It is only used internally and never exposes the token's own
    # decoded objects.
    class ClaimsContext
      def initialize(token)
        @token = token
      end

      def header
        @header ||= @token.header
      end

      def payload
        @payload ||= @token.unverified_payload
      end
    end
  end
end
