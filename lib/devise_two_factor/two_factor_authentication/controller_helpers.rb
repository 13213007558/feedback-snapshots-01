module Devise
  module TwoFactorAuthentication
    # Helpers intended for controllers. Include into ApplicationController (or
    # a specific controller) to expose the session's real two-factor state.
    module ControllerHelpers
      extend ActiveSupport::Concern

      included do
        if respond_to?(:helper_method)
          helper_method :two_factor_status, :two_factor_read_only?,
                        :two_factor_restricted?, :two_factor_verification_prompt
        end
      end

      def two_factor_session
        Devise::TwoFactorAuthentication::Session.new(request.env, scope: two_factor_scope)
      end

      # The Warden scope to inspect. Override in a controller if the
      # authenticated model is not the default Devise scope.
      def two_factor_scope
        nil
      end

      def two_factor_status
        two_factor_session.status
      end

      # True when the signed-in account requires two-factor authentication
      # that this session has not yet confirmed.
      def two_factor_confirmation_required?
        two_factor_status.verification_required?
      end

      def two_factor_read_only?
        two_factor_status.read_only?
      end

      def two_factor_restricted?
        two_factor_status.restricted?
      end

      # The prompt the application should show: nil when verification is not
      # needed, otherwise :verify_two_factor or :reverify_two_factor.
      def two_factor_verification_prompt
        two_factor_status.prompt
      end

      # Confirms two-factor authentication for this session. Call with the
      # submitted OTP/backup code and the record.
      def confirm_two_factor_authentication!(code)
        two_factor_session.confirm_two_factor!(code)
      end

      # Whether the current session may submit a sensitive request. Records the
      # configuration the request was entered under.
      def begin_sensitive_request!
        two_factor_session.begin_sensitive_request!
      end

      def sensitive_request_submittable?
        two_factor_session.sensitive_request_status.eligible_for_sensitive_actions?
      end

      def sensitive_request_status
        two_factor_session.sensitive_request_status
      end

      def sensitive_request_verification_prompt
        two_factor_session.sensitive_request_status.prompt
      end
    end
  end
end
