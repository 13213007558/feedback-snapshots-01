# frozen_string_literal: true

module JWT
  module Policy
    # Verifies that the JWT `typ` header matches the type(s) the server policy
    # expects for a given purpose. This is the primary guard against a token
    # minted for one purpose being replayed for another.
    class TypVerifier
      # @param expected_types [String, Array<String>] the accepted `typ` values.
      def initialize(expected_types:)
        @expected_types = Array(expected_types).map(&:to_s)
      end

      # @param header [Hash] the decoded JWT header.
      # @raise [JWT::InvalidTypError] if the header's `typ` is not accepted.
      # @return [nil]
      def verify!(header:)
        actual = header['typ']
        return if @expected_types.include?(actual)

        raise JWT::InvalidTypError,
              "Invalid typ. Expected #{@expected_types}, received #{actual || '<none>'}"
      end
    end
  end
end
