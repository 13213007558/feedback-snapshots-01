module DeviseTwoFactor
  module OtpRotation
    # Outcome of attempting to authenticate with a TOTP code during a device
    # rotation. Carries enough context for a login flow to distinguish an
    # accepted code from every failure reason without inspecting exceptions.
    class LoginResult
      STATUSES = %i[success invalid_code replay retired no_active_device].freeze

      attr_reader :status, :device_id, :consumption, :error

      def initialize(status:, device_id: nil, consumption: nil, error: nil)
        raise ArgumentError, "unknown status #{status.inspect}" unless STATUSES.include?(status)

        @status = status
        @device_id = device_id
        @consumption = consumption
        @error = error
      end

      def success?
        status == :success
      end

      def self.success(device_id:, consumption: nil)
        new(status: :success, device_id: device_id, consumption: consumption)
      end

      def self.failure(status, device_id: nil, error: nil)
        new(status: status, device_id: device_id, error: error)
      end
    end
  end
end
