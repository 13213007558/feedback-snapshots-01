# frozen_string_literal: true

require 'rack/protection'

module Rack
  module Protection
    ##
    # Prevented attack::   Session Hijacking
    # Supported browsers:: all
    # More infos::         http://en.wikipedia.org/wiki/Session_hijacking
    #
    # Tracks request properties like the user agent in the session and empties
    # the session if those properties change. This essentially prevents attacks
    # from Firesheep. Since all headers taken into consideration can be
    # spoofed, too, this will not prevent determined hijacking attempts.
    #
    # == Graded mode
    #
    # Mobile users legitimately change network traits (user agent after a
    # browser update, IP on a network switch, ...), so clearing the whole
    # session on every change both hurts real users and gives the application
    # no way to tell "needs re-authentication" apart from "session stolen".
    # Graded mode is enabled by configuring +identity_signals+ and/or
    # +weak_signals+ and splits the tracked properties in two tiers:
    #
    # [<tt>:identity_signals</tt>] Callables evaluated against the request env,
    #                             built from server-trusted data (e.g. a device
    #                             token the app issued at login, a TLS client
    #                             certificate fingerprint). A mismatch rejects
    #                             the request (default reaction drops the
    #                             session). Plain header names are refused:
    #                             client-forgeable headers must never be used
    #                             as identity credentials.
    # [<tt>:weak_signals</tt>]     Header names or callables that are easy to
    #                             spoof or change often (e.g. the user agent).
    #                             A mismatch only moves the session into the
    #                             *restricted* state; the request is allowed
    #                             through and the session is kept. Entries of
    #                             the legacy <tt>:track</tt> option are treated
    #                             as weak signals in graded mode.
    #
    # While restricted, the application must require re-authentication for
    # sensitive operations and then explicitly call
    # SessionHijacking.confirm_reauthentication(env). That call is the *only*
    # way the weak-signal baseline is updated after the session has been
    # established, so an attacker's requests cannot teach the middleware new
    # traits. On logout, account switch or session restore the application
    # rebuilds the baseline via SessionHijacking.reset_tracking(env) or
    # SessionHijacking.rebaseline(env).
    #
    # Without <tt>:identity_signals</tt>/<tt>:weak_signals</tt> the middleware
    # behaves exactly as before: any change to a <tt>:track</tt>ed header
    # empties the session.
    class SessionHijacking < Base
      # Env key holding the middleware instance, used by the class helpers.
      ENV_KEY = 'rack.protection.session_hijacking'
      # Env key set to true for requests served in restricted state.
      RESTRICTED_ENV_KEY = 'rack.protection.session_hijacking.restricted'

      WEAK_REACTIONS = %i[restrict report drop_session].freeze

      default_reaction :drop_session
      default_options tracking_key: :tracking,
                      track: %w[HTTP_USER_AGENT],
                      identity_signals: [],
                      weak_signals: [],
                      weak_reaction: :restrict

      class << self
        # True while the session is in restricted state, i.e. a weak signal
        # changed and the application has not confirmed re-authentication
        # yet. A false return value only means "no anomaly detected" -- it
        # is NOT proof that the user completed strong authentication.
        def restricted?(env)
          from(env).restricted?(env)
        end

        # Lift the restricted state after the application re-authenticated
        # the user (password, MFA, ...). Re-baselines the weak signals from
        # the current, now trusted, request. Never call this from a handler
        # that did not verify fresh credentials.
        def confirm_reauthentication(env)
          from(env).confirm_reauthentication(env)
        end

        # Forget the baseline entirely (logout, account switch). The next
        # request captures a fresh baseline for the new context.
        def reset_tracking(env)
          from(env).reset_tracking(env)
        end

        # Capture a fresh baseline immediately (session restore, e.g. a
        # remember-me token logging the user back in).
        def rebaseline(env)
          from(env).rebaseline(env)
        end

        private

        def from(env)
          env[ENV_KEY] ||
            raise("#{self} helpers require the middleware to run before the application")
        end
      end

      def initialize(app, options = {})
        super
        validate_options!
      end

      def call(env)
        env[ENV_KEY] = self
        super
      end

      def accepts?(env)
        graded? ? accepts_graded?(env) : accepts_legacy?(env)
      end

      def restricted?(env)
        env[RESTRICTED_ENV_KEY] == true || baseline(env).fetch('restricted', false) == true
      end

      def confirm_reauthentication(env)
        if graded?
          entry = tracking(env)
          entry['weak'] = capture_signals(weak_signals, env)
          entry['restricted'] = false
          env.delete(RESTRICTED_ENV_KEY)
        else
          rebaseline(env)
        end
        nil
      end

      def reset_tracking(env)
        session(env).delete(options[:tracking_key])
        env.delete(RESTRICTED_ENV_KEY)
        nil
      end

      def rebaseline(env)
        session(env)[options[:tracking_key]] = capture_baseline(env)
        env.delete(RESTRICTED_ENV_KEY)
        nil
      end

      def encode(value)
        value.to_s.downcase
      end

      private

      def accepts_legacy?(env)
        session = session env
        key     = options[:tracking_key]
        if session.include? key
          session[key].all? { |k, v| v == encode(env[k]) }
        else
          session[key] = {}
          options[:track].each { |k| session[key][k] = encode(env[k]) }
        end
      end

      def accepts_graded?(env)
        entry = tracking(env)
        unless entry.is_a?(Hash) && entry['identity'].is_a?(Hash)
          session(env)[options[:tracking_key]] = capture_baseline(env)
          return true
        end

        # Strong identity mismatch: the session was likely copied to another
        # context. Reject; the default reaction drops the session.
        return false unless signals_match?(entry['identity'], options[:identity_signals], env)

        # Weak signal mismatch: restrict only. The baseline is deliberately
        # NOT updated here, so attack requests cannot teach new traits.
        restrict!(env, entry) if entry['restricted'] || !signals_match?(entry['weak'], weak_signals, env)

        true
      end

      def graded?
        options[:identity_signals].any? || options[:weak_signals].any?
      end

      def weak_signals
        options[:track] + options[:weak_signals]
      end

      def tracking(env)
        session(env)[options[:tracking_key]] ||= {}
      end

      def baseline(env)
        entry = session?(env) && session(env)[options[:tracking_key]]
        entry.is_a?(Hash) ? entry : {}
      end

      def capture_baseline(env)
        if graded?
          {
            'identity' => capture_signals(options[:identity_signals], env),
            'weak' => capture_signals(weak_signals, env),
            'restricted' => false
          }
        else
          {}.tap { |base| options[:track].each { |k| base[k] = encode(env[k]) } }
        end
      end

      def capture_signals(signals, env)
        signals.each_with_index.to_h do |signal, index|
          [signal_label(signal, index), encode(resolve_signal(signal, env))]
        end
      end

      def signals_match?(captured, signals, env)
        signals.each_with_index.all? do |signal, index|
          captured[signal_label(signal, index)] == encode(resolve_signal(signal, env))
        end
      end

      def resolve_signal(signal, env)
        signal.respond_to?(:call) ? signal.call(env) : env[signal]
      end

      def signal_label(signal, index)
        signal.respond_to?(:call) ? "signal_#{index}" : signal.to_s
      end

      def restrict!(env, entry)
        already_restricted = entry['restricted'] == true
        entry['restricted'] = true
        env[RESTRICTED_ENV_KEY] = true
        return if already_restricted

        warn env, "session restricted by #{self.class}: weak signal mismatch"
        instrument env
        case options[:weak_reaction]
        when :report then report(env)
        when :drop_session then drop_session(env)
        end
      end

      def validate_options!
        options[:identity_signals].each do |signal|
          next if signal.respond_to?(:call)

          raise ArgumentError,
                "identity signals must be callables built from server-trusted data; " \
                "#{signal.inspect} is a client-forgeable header, configure it as a weak signal instead"
        end
        return if WEAK_REACTIONS.include?(options[:weak_reaction])

        raise ArgumentError, "weak_reaction must be one of #{WEAK_REACTIONS.inspect}"
      end
    end
  end
end
