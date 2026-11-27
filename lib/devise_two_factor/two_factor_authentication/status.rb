module Devise
  module TwoFactorAuthentication
    # Immutable snapshot describing how far the current session has progressed
    # through two-factor authentication.
    #
    # The levels are:
    #
    # * +:anonymous+    - there is no authenticated user in this session.
    # * +:not_required+ - the user is signed in and two-factor authentication is
    #                     disabled for the account.
    # * +:legacy+       - the session was established while two-factor
    #                     authentication was disabled and it has not been
    #                     confirmed since the account started requiring it.
    # * +:pending+      - the account requires two-factor authentication and
    #                     this session has not confirmed it (or its previous
    #                     confirmation belongs to an older account
    #                     configuration).
    # * +:confirmed+    - this session confirmed two-factor authentication
    #                     against the account's current configuration.
    class Status
      LEVELS = %i[anonymous not_required legacy pending confirmed].freeze

      attr_reader :level, :reason, :prompt, :fingerprint

      def initialize(level:, reason: nil, prompt: nil, fingerprint: nil, stale: false)
        unless LEVELS.include?(level)
          raise ArgumentError, "unknown two-factor authentication level: #{level.inspect}"
        end

        @level = level
        @reason = reason
        @prompt = prompt
        @fingerprint = fingerprint
        @stale = stale
      end

      def self.anonymous
        new(level: :anonymous, reason: :not_authenticated, prompt: :authenticate)
      end

      def self.not_required(fingerprint: nil)
        new(level: :not_required, fingerprint: fingerprint)
      end

      def self.legacy(fingerprint: nil)
        new(level: :legacy, reason: :session_predates_two_factor,
            prompt: :verify_two_factor, fingerprint: fingerprint)
      end

      def self.pending(fingerprint: nil)
        new(level: :pending, reason: :two_factor_not_confirmed,
            prompt: :verify_two_factor, fingerprint: fingerprint)
      end

      def self.configuration_changed(fingerprint: nil, stale: false)
        new(level: :pending, reason: :two_factor_configuration_changed,
            prompt: :reverify_two_factor, fingerprint: fingerprint, stale: stale)
      end

      def self.confirmed(fingerprint: nil)
        new(level: :confirmed, fingerprint: fingerprint)
      end

      # Whether the session is authenticated but cannot perform writes or
      # restricted business actions until two-factor authentication is
      # confirmed.
      def read_only?
        level == :legacy || level == :pending
      end

      # Restricted business actions must not run while the session is
      # read-only.
      def restricted?
        read_only?
      end

      def authenticated?
        level != :anonymous
      end

      def verified?
        level == :not_required || level == :confirmed
      end

      def eligible_for_sensitive_actions?
        verified?
      end

      def verification_required?
        read_only?
      end

      # True when a request that was opened under one account configuration is
      # evaluated against a different (newer) one.
      def stale?
        !!@stale
      end

      def configuration_changed?
        reason == :two_factor_configuration_changed
      end

      def to_h
        {
          level: level,
          reason: reason,
          prompt: prompt,
          fingerprint: fingerprint,
          read_only: read_only?,
          restricted: restricted?,
          authenticated: authenticated?,
          eligible_for_sensitive_actions: eligible_for_sensitive_actions?,
          verification_required: verification_required?,
          stale: stale?
        }
      end

      alias as_json to_h
    end
  end
end
