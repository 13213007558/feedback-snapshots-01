module DeviseTwoFactor
  module OtpRotation
    class Error < StandardError; end

    # Raised when an in-flight or new verification tries to write a replay
    # marker for a device that has been retired by a completed rotation.
    class DeviceRetired < Error
      attr_reader :device_id

      def initialize(device_id)
        @device_id = device_id
        super("OTP device #{device_id.inspect} has been retired")
      end
    end

    # Raised when a device is asked to consume a timestep it already consumed.
    class ReplayDetected < Error
      attr_reader :device_id, :timestep

      def initialize(device_id, timestep)
        @device_id = device_id
        @timestep = timestep
        super("replayed TOTP timestep #{timestep} on device #{device_id.inspect}")
      end
    end

    # Raised when a submitted code fails the cryptographic check.
    class InvalidCode < Error
      attr_reader :device_id

      def initialize(device_id)
        @device_id = device_id
        super("invalid TOTP code for device #{device_id.inspect}")
      end
    end

    class NoPendingDevice < Error; end
    class PendingNotVerified < Error; end
    class DeviceAlreadyEnrolled < Error; end
    class RotationAlreadyCommitted < Error; end
    class UnknownDevice < Error; end
    class NoInFlightVerification < Error; end
  end
end
