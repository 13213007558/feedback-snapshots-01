# frozen_string_literal: true

module JWT
  module Policy
    # The usable identity returned only after every check in a verification
    # policy has passed. It is never instantiated on a partial failure.
    class VerifiedIdentity
      # @return [Symbol, String] the purpose the token was verified for.
      attr_reader :purpose

      # @return [Hash] the verified token payload.
      attr_reader :payload

      # @return [Hash] the verified token header.
      attr_reader :header

      # @return [VerificationPolicy] the policy that accepted the token.
      attr_reader :policy

      # @api private
      def initialize(purpose:, payload:, header:, policy:)
        @purpose = purpose
        @payload = payload
        @header  = header
        @policy  = policy
      end

      # Convenience accessor for the subject claim.
      # @return [Object] the `sub` claim, if present.
      def subject
        payload['sub']
      end
    end
  end
end
