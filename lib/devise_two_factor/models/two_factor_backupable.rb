require 'devise_two_factor/audit'

module Devise
  module Models
    # TwoFactorBackupable allows a user to generate backup codes which
    # provide one-time access to their account in the event that they have
    # lost access to their two-factor device
    module TwoFactorBackupable
      extend ActiveSupport::Concern

      included do
        if respond_to?(:after_commit)
          after_commit :__devise_two_factor_audit_regeneration_stored,
                       if: :__devise_two_factor_regeneration_pending?
          after_commit :__devise_two_factor_audit_consumption_stored,
                       if: :__devise_two_factor_consumption_pending?
          after_rollback :__devise_two_factor_audit_rolled_back
        elsif respond_to?(:after_save)
          after_save :__devise_two_factor_audit_regeneration_stored,
                     if: :__devise_two_factor_regeneration_pending?
          after_save :__devise_two_factor_audit_consumption_stored,
                     if: :__devise_two_factor_consumption_pending?
        end
      end

      def self.required_fields(klass)
        [:otp_backup_codes]
      end

      # Stable, non-secret reference suitable for an audit stream. Override in
      # the model if the application has its own opaque security identifier.
      def audit_security_identifier
        respond_to?(:id) && id ? id.to_s : object_id.to_s
      end

      # 1) Invalidates all existing backup codes
      # 2) Generates otp_number_of_backup_codes backup codes
      # 3) Stores the hashed backup codes in the database
      # 4) Returns a plaintext array of the generated backup codes
      def generate_otp_backup_codes!
        identifier = audit_security_identifier
        publish_regeneration(DeviseTwoFactor::Audit::STARTED, identifier)

        codes           = []
        number_of_codes = self.class.otp_number_of_backup_codes
        code_length     = self.class.otp_backup_code_length

        number_of_codes.times do
          codes << SecureRandom.hex(code_length)
        end

        hashed_codes = codes.map { |code| Devise::Encryptor.digest(self.class, code) }
        self.otp_backup_codes = hashed_codes
        @devise_two_factor_regeneration_identifier = identifier
        @devise_two_factor_regeneration_pending = true

        publish_regeneration(DeviseTwoFactor::Audit::GENERATED, identifier)

        codes
      end

      # Returns true and invalidates the given code
      # if that code is a valid backup code.
      def invalidate_otp_backup_code!(code)
        identifier = audit_security_identifier
        publish_consumption(DeviseTwoFactor::Audit::STARTED, identifier)

        codes = self.otp_backup_codes || []

        # Should we still have some other kind of non iterable result, terminate.
        raise TypeError.new("`otp_backup_codes` is expected to be an Array, got #{codes.class.name}. Hint: If your database does not support arrays, does your model correctly `serialize :otp_backup_codes, Array`?") unless codes.is_a?(Array)

        snapshot = codes.dup
        matched  = snapshot.find { |backup_code| Devise::Encryptor.compare(self.class, backup_code, code) }

        unless matched
          publish_consumption(DeviseTwoFactor::Audit::REJECTED, identifier)
          return false
        end

        # Verification succeeded against the codes this instance had loaded.
        # That alone is not a completed consumption; the stored and session
        # phases are reported only when the write and Warden succeed.
        publish_consumption(DeviseTwoFactor::Audit::VERIFIED, identifier)

        consumed = false
        superseded = false

        if persisted_record?
          # Re-read the row under a lock. A regeneration that interleaved with
          # the pending verification replaces the whole set, so the stale code
          # must not be written back over the new codes.
          with_lock do
            current = self.otp_backup_codes || []
            # Another consumption may have removed a different code; that is
            # compatible. A regeneration replaces the whole set, which is not.
            superseded = (current & snapshot).empty?
            next unless current.include?(matched)
            next unless (current - snapshot).empty?

            self.otp_backup_codes = current - [matched]
            __devise_two_factor_mark_consumption_attempt(identifier)
            save!(validate: false)
            consumed = true
          end
        else
          self.otp_backup_codes = snapshot - [matched]
          __devise_two_factor_mark_consumption_attempt(identifier)
          save!(validate: false)
          consumed = true
        end

        unless consumed
          publish_consumption(
            superseded ? DeviseTwoFactor::Audit::SUPERSEDED : DeviseTwoFactor::Audit::REJECTED,
            identifier
          )
          return false
        end

        # Models without transaction callbacks report storage here. Models with
        # after_commit report it from the commit callback instead, so the event
        # never precedes a durable write.
        unless self.class.respond_to?(:after_commit)
          @devise_two_factor_consumption_pending = false
          @devise_two_factor_consumption_committed = true
          publish_consumption(DeviseTwoFactor::Audit::STORED, identifier)
        end

        true
      rescue StandardError
        # Only report a failed write while the storage attempt is still
        # uncommitted. ActiveRecord rollbacks are reported by the after_rollback
        # callback; this branch covers models without transaction callbacks and
        # failures raised before a transaction exists.
        if @devise_two_factor_consumption_pending && !@devise_two_factor_consumption_committed
          @devise_two_factor_consumption_pending = false
          publish_consumption(DeviseTwoFactor::Audit::FAILED, identifier)
        end
        raise
      end

    protected

      def __devise_two_factor_regeneration_pending?
        @devise_two_factor_regeneration_pending == true
      end

      def __devise_two_factor_consumption_pending?
        @devise_two_factor_consumption_pending == true
      end

      def __devise_two_factor_mark_consumption_attempt(identifier)
        @devise_two_factor_consumption_identifier = identifier
        @devise_two_factor_consumption_pending = true
        @devise_two_factor_consumption_committed = false
      end

      def __devise_two_factor_audit_regeneration_stored
        return unless __devise_two_factor_regeneration_pending?

        @devise_two_factor_regeneration_pending = false
        publish_regeneration(
          DeviseTwoFactor::Audit::STORED,
          @devise_two_factor_regeneration_identifier || audit_security_identifier
        )
      end

      def __devise_two_factor_audit_consumption_stored
        return unless __devise_two_factor_consumption_pending?

        @devise_two_factor_consumption_pending = false
        @devise_two_factor_consumption_committed = true
        publish_consumption(
          DeviseTwoFactor::Audit::STORED,
          @devise_two_factor_consumption_identifier || audit_security_identifier
        )
      end

      def __devise_two_factor_audit_rolled_back
        if @devise_two_factor_regeneration_pending
          @devise_two_factor_regeneration_pending = false
          publish_regeneration(
            DeviseTwoFactor::Audit::FAILED,
            @devise_two_factor_regeneration_identifier || audit_security_identifier
          )
        end

        return unless @devise_two_factor_consumption_pending
        return if @devise_two_factor_consumption_committed

        @devise_two_factor_consumption_pending = false
        publish_consumption(
          DeviseTwoFactor::Audit::FAILED,
          @devise_two_factor_consumption_identifier || audit_security_identifier
        )
      end

      def publish_regeneration(phase, identifier)
        DeviseTwoFactor::Audit.publish(
          event: DeviseTwoFactor::Audit::REGENERATION,
          phase: phase,
          security_identifier: identifier
        )
      end

      def publish_consumption(phase, identifier)
        DeviseTwoFactor::Audit.publish(
          event: DeviseTwoFactor::Audit::CONSUMPTION,
          phase: phase,
          security_identifier: identifier
        )
      end

      def persisted_record?
        respond_to?(:persisted?) && persisted? &&
          respond_to?(:id) && id &&
          respond_to?(:with_lock)
      end

      module ClassMethods
        Devise::Models.config(self, :otp_backup_code_length,
                                    :otp_number_of_backup_codes,
                                    :pepper)
      end
    end
  end
end
