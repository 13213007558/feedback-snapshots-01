require 'active_support/notifications'

module DeviseTwoFactor
  # Publishes the small, non-secret audit facts that security operations need
  # in order to review recovery-code changes. The payload deliberately has a
  # fixed shape: only the subject identifier, the event category and the phase
  # are accepted. Plaintext codes, hashes and OTP seeds must never be passed
  # through this API.
  module Audit
    EVENT_NAME = 'devise_two_factor.audit'.freeze

    REGENERATION = 'recovery_code_regeneration'.freeze
    CONSUMPTION  = 'recovery_code_consumption'.freeze

    STARTED             = 'started'.freeze
    GENERATED           = 'generated'.freeze
    VERIFIED            = 'verified'.freeze
    STORED              = 'stored'.freeze
    SUPERSEDED          = 'superseded'.freeze
    SESSION_ESTABLISHED = 'session_established'.freeze
    FAILED              = 'failed'.freeze
    REJECTED            = 'rejected'.freeze

    EVENTS = [REGENERATION, CONSUMPTION].freeze
    PHASES = [STARTED, GENERATED, VERIFIED, STORED, SESSION_ESTABLISHED, FAILED, REJECTED, SUPERSEDED].freeze

    # Internal Warden env key used to carry the already-approved backup-code
    # consumption from the strategy to the after-authentication hook. It is
    # removed before the audit event is published.
    CONSUMPTION_CONTEXT_KEY = 'devise_two_factor.audit.consumption'.freeze

    class << self
      # Publish one audit fact.
      #
      # +security_identifier+ must be a stable, non-secret reference to the
      # account (the default model helper uses the record id). +event+ and
      # +phase+ must be one of the constants above. Any additional field is
      # rejected instead of being silently written to the audit stream.
      def publish(event:, phase:, security_identifier:, **extra)
        unless extra.empty?
          raise ArgumentError, "unsupported audit fields: #{extra.keys.map(&:inspect).join(', ')}"
        end

        event = normalize(event, EVENTS, 'event')
        phase = normalize(phase, PHASES, 'phase')
        identifier = security_identifier.to_s
        raise ArgumentError, 'security_identifier must not be blank' if identifier.empty?

        payload = {
          security_identifier: identifier,
          event: event,
          phase: phase
        }

        ActiveSupport::Notifications.instrument(EVENT_NAME, payload)
        payload
      end

      # Installs a Warden hook that reports the session phase only after Warden
      # has serialized the authenticated user into the request session. The
      # strategy marks the env when a backup code was accepted; the phase is
      # therefore independent from the earlier storage commit.
      def install_warden_session_hook!
        return if @warden_session_hook_installed
        return unless defined?(::Warden::Manager)

        @warden_session_hook_installed = true

        ::Warden::Manager.after_authentication do |_user, auth, opts|
          context = auth.env[CONSUMPTION_CONTEXT_KEY]
          next unless context
          next unless context[:scope].to_s == opts[:scope].to_s

          # The callback also runs when the session was intentionally not
          # stored. Only report the phase once Warden has a session key.
          next unless auth.session_serializer.stored?(opts[:scope])

          auth.env.delete(CONSUMPTION_CONTEXT_KEY)
          publish(
            event: CONSUMPTION,
            phase: SESSION_ESTABLISHED,
            security_identifier: context[:security_identifier]
          )
        end
      end

    private

      def normalize(value, allowed, label)
        normalized = value.to_s
        unless allowed.include?(normalized)
          raise ArgumentError, "unsupported audit #{label}: #{value.inspect}"
        end
        normalized
      end
    end
  end
end
