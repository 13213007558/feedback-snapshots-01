module DeviseTwoFactor
  module OtpRotation
    # Coordinates replacing one TOTP device with another.
    #
    # Lifecycle:
    #   * An old device stays usable until a rotation is committed.
    #   * A new device starts pending and is cryptographically checked before it
    #     can take over. A failed check never consumes one of its attempts.
    #   * Committing retires the old device immediately. Any old-device
    #     verification that was still in flight is then rejected at commit, so
    #     it has an explicit end instead of silently landing after the switch.
    class Rotation
      attr_reader :devices, :pending_device, :consumption_log

      def initialize(old_device:)
        @devices = {}
        @consumption_log = []
        @pending_device = nil
        @committed = false
        @in_flight = {}

        register(old_device)
        @active_device_id = old_device.id
      end

      def active_device
        @devices[@active_device_id]
      end

      def old_device
        @devices.fetch(:old)
      end

      def committed?
        @committed
      end

      # Begin enrolling a replacement. The device is registered so its codes can
      # be cryptographically checked, but it is held in a pending state and
      # cannot authenticate logins until its verification is committed.
      def enroll(new_device)
        raise RotationAlreadyCommitted if committed?
        raise DeviceAlreadyEnrolled if @pending_device

        register(new_device)
        @pending_device = new_device
      end

      # One-shot verification against the device that currently owns logins.
      # A pending replacement is intentionally excluded: it has to be verified
      # and committed before it can authenticate. If the code cryptographically
      # belongs to a retired device (e.g. the old one after a switch), that is
      # reported explicitly as :retired instead of a generic invalid code.
      # Replay state is per device, so identical digits from two devices remain
      # distinguishable and each keeps its own remaining attempts.
      def validate_and_consume(code, at: Time.now)
        device = active_device
        return LoginResult.failure(:no_active_device) unless device

        retired_owner = recognize_retired_device(code, at)
        return LoginResult.failure(:retired, device_id: retired_owner.id) if retired_owner

        timestamp = device.verify(code, at: at)
        return consume(device, timestamp, at) if timestamp

        # The active device rejected the code. If a rotation happened and a
        # retired predecessor still exists, attribute the failed login to that
        # predecessor so an old-device login has an explicit end even once its
        # code has aged out of the drift window.
        if rotated? && code && !code.to_s.strip.empty?
          return LoginResult.failure(:retired, device_id: old_device.id)
        end

        LoginResult.failure(:invalid_code, device_id: device.id)
      rescue ReplayDetected => e
        LoginResult.failure(:replay, device_id: e.device_id)
      end

      def rotated?
        committed? && old_device.retired? && active_device != old_device
      end

      # A code in the retired device's current window proves it came from that
      # retired source, so its login can be ended explicitly. Drift-only matches
      # are ignored here so they cannot shadow the active replacement device.
      # Never mutates replay state.
      def recognize_retired_device(code, at)
        @devices.values.find do |device|
          next false unless device.retired?

          device.current_window?(code, at: at)
        end
      end

      # First half of a two-phase verification: perform the cryptographic check
      # without writing anything, so the write can be interrupted by a rotation.
      def begin_verification(device_id, code, at: Time.now)
        device = require_device!(device_id)
        timestamp = device.verify_without_replay(code, at: at)

        raise InvalidCode, device_id unless timestamp

        @in_flight[device_id] = { timestamp: timestamp, started_at: at }
        timestamp
      end

      # Second half. Re-evaluates device state at write time, which is what lets
      # an old-device verification that lost the race against a rotation fail
      # explicitly rather than be consumed after the device was retired.
      def commit_verification(device_id, at: Time.now)
        device = require_device!(device_id)
        pending = @in_flight.delete(device_id)

        raise NoInFlightVerification, device_id unless pending
        return LoginResult.failure(:retired, device_id: device_id) if device.retired?

        consumption = device.consume!(pending.fetch(:timestamp), at: at)
        @consumption_log << consumption
        LoginResult.success(device_id: device_id, consumption: consumption)
      rescue ReplayDetected => e
        LoginResult.failure(:replay, device_id: e.device_id)
      rescue DeviceRetired
        LoginResult.failure(:retired, device_id: device_id)
      end

      # Verify the pending replacement before promoting it. Returns a
      # LoginResult. A failed check leaves the pending device's replay state
      # untouched, so it does not spend one of its verification opportunities.
      # The verified code is only written to the consumption log on commit.
      def verify_new_device(code, at: Time.now)
        raise RotationAlreadyCommitted if committed?
        raise NoPendingDevice unless @pending_device

        timestamp = @pending_device.verify(code, at: at)
        return LoginResult.failure(:invalid_code, device_id: @pending_device.id) unless timestamp

        @verified_pending_timestamp = timestamp
        LoginResult.success(device_id: @pending_device.id)
      rescue ReplayDetected => e
        LoginResult.failure(:replay, device_id: e.device_id)
      end

      # Confirm the switch. Requires the new device to have been verified first.
      # The old device is retired and the verified code is consumed on the new
      # device, which becomes active. The old device's submitted state is left
      # exactly as it was.
      def commit_rotation!(at: Time.now)
        raise RotationAlreadyCommitted if committed?
        raise PendingNotVerified unless @verified_pending_timestamp
        raise NoPendingDevice unless @pending_device

        consumption = @pending_device.consume!(@verified_pending_timestamp, at: at)
        @consumption_log << consumption

        old_device.retire!
        @active_device_id = @pending_device.id
        @pending_device = nil
        @verified_pending_timestamp = nil
        @committed = true

        consumption
      end

      def consumption_for(device_id)
        @consumption_log.select { |consumption| consumption.device_id == device_id }
      end

      private

      def register(device)
        @devices[device.id] = device
      end

      def require_device!(device_id)
        @devices.fetch(device_id) { raise UnknownDevice, device_id }
      end

      def consume(device, timestamp, at)
        consumption = device.consume!(timestamp, at: at)
        @consumption_log << consumption
        LoginResult.success(device_id: device.id, consumption: consumption)
      rescue ReplayDetected => e
        LoginResult.failure(:replay, device_id: e.device_id)
      rescue DeviceRetired
        LoginResult.failure(:retired, device_id: device.id)
      end
    end
  end
end
