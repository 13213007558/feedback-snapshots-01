module Devise
  module Strategies
    # Shared helper for strategies that establish a session. Records how the
    # session relates to the account's two-factor configuration so that later
    # requests can distinguish legacy, pending and confirmed sessions.
    module SessionStateRecording
      private

      def record_two_factor_session_state(resource, two_factor_used:)
        return unless successful?

        Devise::TwoFactorAuthentication::Session
          .new(env, scope: scope)
          .record_authentication!(resource, two_factor_used: two_factor_used)
      end
    end
  end
end
