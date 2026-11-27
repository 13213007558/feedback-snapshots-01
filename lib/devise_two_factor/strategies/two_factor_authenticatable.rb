require 'devise_two_factor/strategies/session_state_recording'

module Devise
  module Strategies
    class TwoFactorAuthenticatable < Devise::Strategies::DatabaseAuthenticatable
      include SessionStateRecording

      def authenticate!
        resource = mapping.to.find_for_database_authentication(authentication_hash)

        hashed = false
        # We authenticate in two cases:
        # 1. The password and the OTP are correct
        # 2. The password is correct, and OTP is not required for login
        # We check the OTP, then defer to DatabaseAuthenticatable
        if validate(resource) { hashed = true; validate_otp(resource) }
          super
          record_two_factor_session_state(resource, two_factor_used: @otp_used)
        else
          # Paranoid mode: do the expensive hash even when resource is nil,
          # to avoid timing-based user enumeration.
          mapping.to.new.password = password if !hashed && Devise.paranoid
        end

        fail(Devise.paranoid ? :invalid : :not_found_in_database) unless resource

        # We want to cascade to the next strategy if this one fails,
        # but database authenticatable automatically halts on a bad password
        @halted = false if @result == :failure
      end

      def validate_otp(resource)
        @otp_used = false
        return true unless resource.otp_required_for_login
        return if params[scope].nil? || params[scope]['otp_attempt'].nil?

        @otp_used = !!resource.validate_and_consume_otp!(params[scope]['otp_attempt'])
        @otp_used
      end
    end
  end
end

Warden::Strategies.add(:two_factor_authenticatable, Devise::Strategies::TwoFactorAuthenticatable)
