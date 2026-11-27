module DeviseTwoFactor
  module OtpRotation
    # Immutable record of a single consumed TOTP code.
    #
    # Replay protection is keyed on the secret (i.e. the device) that produced
    # the code rather than on the numeric code itself. Two devices may emit
    # identical digits inside the same time window, so the source of every
    # consumed code has to be retained explicitly.
    class Consumption
      attr_reader :device_id, :otp_secret, :timestep, :timestamp, :consumed_at

      def initialize(device_id:, otp_secret:, timestep:, timestamp:, consumed_at: Time.now)
        @device_id = device_id
        @otp_secret = otp_secret
        @timestep = timestep
        @timestamp = timestamp
        @consumed_at = consumed_at
      end

      def source
        device_id
      end
    end
  end
end
