require 'digest'

module Devise
  module Models
    # Adds an account-level fingerprint of everything that affects two-factor
    # authentication: whether it is required, the shared OTP secret, and the
    # set of backup codes.
    #
    # A session that confirmed against an older fingerprint is considered out
    # of date once the account configuration changes again.
    module TwoFactorConfigurationTracking
      extend ActiveSupport::Concern

      def two_factor_configuration_fingerprint
        required = respond_to?(:otp_required_for_login) && otp_required_for_login
        parts = ["required=#{required ? 1 : 0}"]
        parts << "secret=#{Digest::SHA256.hexdigest(otp_secret.to_s)}" if respond_to?(:otp_secret)
        parts << "backup=#{two_factor_backup_codes_fingerprint}" if respond_to?(:otp_backup_codes)

        Digest::SHA256.hexdigest(parts.join('|'))[0, 32]
      end

      private

      def two_factor_backup_codes_fingerprint
        codes = otp_backup_codes
        return 'none' unless codes.respond_to?(:to_a)

        Digest::SHA256.hexdigest(Array(codes).sort.join(','))
      end
    end
  end
end
