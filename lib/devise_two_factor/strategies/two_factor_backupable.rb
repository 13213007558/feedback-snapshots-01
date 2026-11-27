require 'devise_two_factor/strategies/session_state_recording'

module Devise
  module Strategies
    class TwoFactorBackupable < Devise::Strategies::DatabaseAuthenticatable
      include SessionStateRecording

      def authenticate!
        resource = mapping.to.find_for_database_authentication(authentication_hash)

        if validate(resource) { validate_backup_code(resource) }
          super
          record_two_factor_session_state(resource,
                                          two_factor_used: resource.otp_required_for_login)
        end

        fail(Devise.paranoid ? :invalid : :not_found_in_database) unless resource

        # We want to cascade to the next strategy if this one fails,
        # but database authenticatable automatically halts on a bad password
        @halted = false if @result == :failure
      end

      def validate_backup_code(resource)
        @backup_code_used = false
        return if params[scope].nil? || params[scope]['otp_attempt'].nil?

        @backup_code_used = !!resource.invalidate_otp_backup_code!(params[scope]['otp_attempt'])
        @backup_code_used
      end
    end
  end
end

Warden::Strategies.add(:two_factor_backupable, Devise::Strategies::TwoFactorBackupable)
