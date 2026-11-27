require 'rotp'

module DeviseTwoFactor
  module OtpRotation
    # A single TOTP authenticator (one physical device / one shared secret).
    #
    # Each device owns its secret, its replay state and its lifecycle flag.
    # Verification (cryptographic check) and consumption (writing the replay
    # marker) are deliberately separate so an in-flight verification can be
    # rejected at commit time if the device was retired in the meantime.
    class OtpDevice
      attr_reader :id, :otp_secret, :drift, :consumption_history

      def initialize(id:, otp_secret:, drift:, interval: nil, totp_factory: nil)
        @id = id
        @otp_secret = otp_secret
        @drift = drift
        @interval = interval
        @totp_factory = totp_factory
        @retired = false
        @consumed_timesteps = []
        @consumption_history = []
      end

      def totp
        @totp ||= build_totp
      end

      def interval
        @interval ||= totp.interval
      end

      def current_code(at = Time.now)
        totp.at(at)
      end

      def retired?
        @retired
      end

      def active?
        !retired?
      end

      def retire!
        @retired = true
      end

      # Cryptographic check only. Never mutates replay state, so a failed or
      # abandoned verification cannot consume one of the device's attempts.
      # A code matching an already consumed timestep is reported as a replay
      # rather than a generic invalid code.
      def verify(code, at: Time.now)
        timestamp = verify_without_replay(code, at: at)
        return nil unless timestamp

        raise ReplayDetected.new(id, timestep_for(timestamp)) if replay?(timestamp)

        timestamp
      end

      # Pure cryptographic check ignoring replay state. Used by the first half
      # of a two-phase verification so the replay decision is made at commit.
      def verify_without_replay(code, at: Time.now)
        return nil if code.nil? || code.to_s.strip.empty?

        totp.verify(
          code.to_s.gsub(/\s+/, ''),
          drift_behind: drift,
          drift_ahead: drift,
          at: at
        )
      end

      # True only when the code matches the device's current timestep, with no
      # forward/backward drift. Lets a retired device be identified as the
      # source of a presented code without it shadowing the active device.
      def current_window?(code, at: Time.now)
        return false if code.nil? || code.to_s.strip.empty?

        timestamp = totp.verify(code.to_s.gsub(/\s+/, ''), at: at)
        return false unless timestamp

        timestep_for(timestamp) == timestep_for(at.to_i)
      end

      def replay?(timestamp)
        consumed_timestep?(timestep_for(timestamp))
      end

      def timestep_for(timestamp)
        timestamp / interval
      end

      def consumed_timestep?(timestep)
        @consumed_timesteps.include?(timestep)
      end

      # Write the replay marker and append an attributed Consumption record.
      # Raises if the same timestep is presented twice or the device has been
      # retired, keeping old devices' already-submitted state immutable.
      def consume!(timestamp, at: Time.now)
        raise DeviceRetired, id if retired?

        timestep = timestep_for(timestamp)
        raise ReplayDetected.new(id, timestep) if consumed_timestep?(timestep)

        consumption = Consumption.new(
          device_id: id,
          otp_secret: otp_secret,
          timestep: timestep,
          timestamp: timestamp,
          consumed_at: at
        )

        @consumed_timesteps << timestep
        @consumption_history << consumption
        consumption
      end

      private

      def build_totp
        if @totp_factory
          @totp_factory.call(otp_secret)
        else
          ROTP::TOTP.new(otp_secret)
        end
      end
    end
  end
end
