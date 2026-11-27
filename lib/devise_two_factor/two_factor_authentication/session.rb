require 'digest'

module Devise
  module TwoFactorAuthentication
    # Per-session two-factor authentication state.
    #
    # Everything is stored in the Rack session, never in the database. A
    # confirmation obtained in one session is therefore never visible to
    # another session of the same account.
    #
    # The recorded state is bound to the signed-in account identity. If the
    # same browser session is reused by a different account, the old state is
    # ignored rather than inherited.
    class Session
      DATA_KEY_PREFIX = 'devise_two_factor'.freeze
      STATE_KEY = 'state'.freeze
      FINGERPRINT_KEY = 'fingerprint'.freeze
      SUBJECT_KEY = 'subject'.freeze
      CONFIRMED_AT_KEY = 'confirmed_at'.freeze
      ENTRY_FINGERPRINT_KEY = 'sensitive_entry_fingerprint'.freeze

      attr_reader :warden, :scope

      def initialize(env, scope: nil)
        @warden = env['warden'] or raise ArgumentError, 'a Warden proxy is required'
        @scope = scope || @warden.config.default_scope
        @data_key = "#{DATA_KEY_PREFIX}.#{@scope}"
      end

      def resource
        return @resource if defined?(@resource) && @resource
        @resource = warden.user(scope: scope)
      end

      def status
        return Status.anonymous if resource.nil?

        unless two_factor_required?(resource)
          return Status.not_required
        end

        fingerprint = configuration_fingerprint(resource)
        state = valid_state_for(resource)

        case state
        when 'confirmed'
          if fingerprint && state_fingerprint == fingerprint
            Status.confirmed(fingerprint: fingerprint)
          else
            Status.configuration_changed(fingerprint: fingerprint)
          end
        when 'pending'
          if state_fingerprint.nil? || fingerprint.nil? || state_fingerprint == fingerprint
            Status.pending(fingerprint: fingerprint)
          else
            Status.configuration_changed(fingerprint: fingerprint)
          end
        else
          # No state (or state recorded while two-factor authentication was
          # disabled) means this session predates the requirement.
          Status.legacy(fingerprint: fingerprint)
        end
      end

      # Records the outcome of a sign-in performed by an authentication
      # strategy. Returns true when the state was written.
      def record_authentication!(resource, two_factor_used:)
        return false if resource.nil?

        if two_factor_required?(resource)
          if two_factor_used
            record_confirmed!(resource)
          else
            record_pending!(resource)
          end
        else
          write_state('not_required', resource: resource, fingerprint: nil, confirmed_at: nil)
        end
        true
      end

      def record_confirmed!(resource = self.resource)
        return false if resource.nil?

        write_state('confirmed',
                    resource: resource,
                    fingerprint: configuration_fingerprint(resource),
                    confirmed_at: Time.now.utc.to_i)
        true
      end

      def record_pending!(resource = self.resource)
        return false if resource.nil?

        write_state('pending',
                    resource: resource,
                    fingerprint: configuration_fingerprint(resource),
                    confirmed_at: nil)
        true
      end

      # Confirms this session with either a TOTP code or a backup code.
      # Returns true when a code was accepted. The confirmation is written to
      # this session only.
      def confirm_two_factor!(code, resource: self.resource)
        return false if code.blank? || resource.nil?
        return false unless two_factor_required?(resource)

        accepted = with_otp?(resource, code) || with_backup_code?(resource, code)

        if accepted
          record_confirmed!(resource)
        elsif !status.verified?
          record_pending!(resource)
        end

        accepted
      end

      # Marks the beginning of a sensitive request, remembering the account
      # configuration and the verification level the request was entered under.
      def begin_sensitive_request!
        current = status
        if current.authenticated? && two_factor_required?(resource)
          data[ENTRY_FINGERPRINT_KEY] = configuration_fingerprint(resource)
        else
          data.delete(ENTRY_FINGERPRINT_KEY)
        end
        persist_data!
        current
      end

      # Status used to decide whether a sensitive request that was already
      # entered may be submitted.
      #
      # When the account configuration changed after the request was entered,
      # the status is marked stale and the session is prompted to verify again.
      def sensitive_request_status
        current = status
        return current unless current.authenticated?
        return current if current.level == :not_required

        entry = data[ENTRY_FINGERPRINT_KEY]
        return current if entry.nil?

        current_fingerprint = configuration_fingerprint(resource)
        return current if entry == current_fingerprint

        Status.configuration_changed(fingerprint: current_fingerprint, stale: true)
      end

      def complete_sensitive_request!
        data.delete(ENTRY_FINGERPRINT_KEY)
        persist_data!
        true
      end

      def clear!
        rack_session.delete(@data_key)
        @stored = nil
        @data = nil
        true
      end

      # The account configuration a confirmation is valid for. Any change
      # rotates this value and invalidates earlier confirmations.
      def configuration_fingerprint(resource = self.resource)
        return nil unless resource
        return resource.two_factor_configuration_fingerprint if resource.respond_to?(:two_factor_configuration_fingerprint)

        digest_parts = ["required=#{two_factor_required?(resource) ? 1 : 0}"]
        digest_parts << "secret=#{Digest::SHA256.hexdigest(resource.otp_secret.to_s)}" if resource.respond_to?(:otp_secret)
        digest_parts << "backup=#{backup_codes_digest(resource)}" if resource.respond_to?(:otp_backup_codes)
        Digest::SHA256.hexdigest(digest_parts.join('|'))[0, 32]
      end

      private

      def with_otp?(resource, code)
        return false unless resource.respond_to?(:validate_and_consume_otp!)

        resource.validate_and_consume_otp!(code.to_s)
      end

      def with_backup_code?(resource, code)
        return false unless resource.respond_to?(:invalidate_otp_backup_code!)

        resource.invalidate_otp_backup_code!(code.to_s)
      end

      def backup_codes_digest(resource)
        codes = resource.otp_backup_codes
        return 'none' unless codes.respond_to?(:to_a)

        Digest::SHA256.hexdigest(Array(codes).sort.join(','))
      end

      def two_factor_required?(resource)
        resource.respond_to?(:otp_required_for_login) && !!resource.otp_required_for_login
      end

      def valid_state_for(resource)
        stored.key?(STATE_KEY) && subject_matches?(resource) ? stored[STATE_KEY] : nil
      end

      def subject_matches?(resource)
        stored_subject = stored[SUBJECT_KEY]
        current_subject = subject_identifier(resource)
        return true if stored_subject.nil? && current_subject.nil?

        !current_subject.nil? && stored_subject == current_subject
      end

      def subject_identifier(resource)
        if resource.respond_to?(:to_key)
          key = resource.to_key
          return key.map(&:to_s).join(':') unless key.nil?
        end
        if resource.respond_to?(:id) && !resource.id.nil?
          return resource.id.to_s
        end
        nil
      end

      def state_fingerprint
        stored[FINGERPRINT_KEY]
      end

      def stored
        @stored ||= begin
          value = rack_session[@data_key]
          value.is_a?(Hash) ? value.stringify_keys : {}
        end
      end

      def data
        @data ||= stored.dup
      end

      def persist_data!
        rack_session[@data_key] = data
        @stored = nil
      end

      def write_state(state, resource:, fingerprint:, confirmed_at:)
        data[STATE_KEY] = state
        data[SUBJECT_KEY] = subject_identifier(resource)
        data[FINGERPRINT_KEY] = fingerprint
        data[CONFIRMED_AT_KEY] = confirmed_at
        persist_data!
      end

      def rack_session
        warden.request.session
      end
    end
  end
end
