module OmniAuth
  module Strategy
    # Binds a sign-in to the authentication intent the application started it
    # for, so a callback meant to link another identity provider can be told
    # apart from an ordinary login. At the request phase the application
    # supplies a context recording the local user and auth-session generation
    # it wants the external identity bound to. At the callback the context is
    # compared with the current session; if the intent, local user, or
    # generation changed while the provider had them, the callback fails
    # instead of handing the external identity to whoever is signed in now.
    #
    # A strategy opts in with the :auth_intent option, a Hash or a proc that
    # takes the Rack env. The proc runs in both phases. A Hash with a 'type'
    # of 'link' also needs a non-empty 'user_id' and 'session_generation', its
    # binding fields. A nil context is an ordinary login ('type' => 'login'),
    # so one strategy can serve both flows and a login started while signed
    # out cannot be completed after someone signed in. Additional context keys
    # travel to the application unchanged, but only the type and the binding
    # fields decide whether the callback is trusted. The strategy must call
    # remember_sign_in with a value the provider sends back, as for several
    # sign-ins at once.
    module AuthIntents
      LINK_INTENT = 'link'.freeze
      LOGIN_INTENT = 'login'.freeze

      # The fields a callback compares. The intent's type always comes from
      # the request phase, so external provider data cannot change it.
      BINDING_FIELDS = %w[user_id session_generation].freeze

      # Longest string value in a context, so an accidentally captured object
      # cannot fill the session and contexts stay comparable.
      MAX_AUTH_INTENT_VALUE_LENGTH = 256

      # Ends the transaction the key belongs to, and only that one, by
      # removing its remembered sign-in. Other transactions stay available
      # for their own callbacks and their authentication is unaffected.
      # Returns true if the transaction existed. The application can call this
      # when it gives up on a provider round trip, for example after the user
      # cancels the flow; a later callback for that key then fails as a
      # missing transaction instead of completing.
      def self.cancel_sign_in(session, key)
        return false unless session.respond_to?(:[]) && key.is_a?(String)

        sign_ins = session['omniauth.sign_ins']
        return false unless sign_ins.is_a?(Hash)

        remembered = sign_ins.keys.detect { |stored| stored.is_a?(String) && Rack::Utils.secure_compare(stored, key) }
        return false unless remembered

        sign_ins = sign_ins.dup
        sign_ins.delete(remembered)
        session['omniauth.sign_ins'] = sign_ins
        true
      end

    protected

      # True when the strategy was configured to carry auth intents.
      def auth_intent_enabled?
        !options[:auth_intent].nil? && !options[:auth_intent].equal?(false)
      end

      # The normalized intent for the current request phase. A nil context is
      # an ordinary login, so every opted-in transaction carries a type.
      def capture_auth_intent
        normalize_auth_intent(configured_auth_intent_context || {'type' => LOGIN_INTENT})
      end

      # The context the application's :auth_intent option returns for this
      # phase, or nil. An option that isn't callable is used as the context.
      def configured_auth_intent_context
        configured = options[:auth_intent]
        configured.respond_to?(:call) ? configured.call(env) : configured
      end

      # The reason a callback must not be trusted, or nil when it still
      # belongs to the transaction that was started. The external auth hash is
      # never part of the decision, so a matching email cannot stand in for an
      # identity the application has not confirmed.
      def auth_intent_failure(sign_in)
        return :auth_intent_missing unless sign_in['auth_intent'].is_a?(Hash)

        intent = sign_in['auth_intent']
        return :auth_intent_mismatch unless auth_intent_binding_matches?(intent, current_auth_intent_context)

        nil
      rescue AuthIntentError
        :auth_intent_mismatch
      end

      # The normalized context the application reports for the session
      # handling the callback. A nil context is again an ordinary login.
      def current_auth_intent_context
        normalize_auth_intent(configured_auth_intent_context || {'type' => LOGIN_INTENT})
      end

      # The context handed to the application as env['omniauth.auth_intent']:
      # the accepted intent exactly as it was recorded, including additional
      # context keys, copied so changes the application makes cannot alter the
      # transaction decision.
      def verified_auth_intent(intent)
        intent.dup
      end

      # A link callback is only trustworthy while both the local user and the
      # auth-session generation are the ones the intent was started with. An
      # ordinary login compares only the fields it recorded, so a login
      # started while signed out is not completed after someone signed in.
      def auth_intent_binding_matches?(intent, current)
        return false unless intent['type'].eql?(current['type'])

        return false unless binding_type_valid?(intent)

        BINDING_FIELDS.all? { |field| !intent.key?(field) || intent[field].eql?(current[field]) }
      end

      # A link must bind both fields; a login may bind either, or neither.
      # Any other type is not an intent this library can verify.
      def binding_type_valid?(intent)
        if intent['type'].eql?(LINK_INTENT)
          bound_identity?(intent['user_id']) && bound_identity?(intent['session_generation'])
        else
          intent['type'].eql?(LOGIN_INTENT)
        end
      end

      # A Hash with string keys and scalar values, with the type and, for a
      # link, both binding fields checked. Raising AuthIntentError reports an
      # invalid context as a failed authentication, not an app error.
      def normalize_auth_intent(context)
        raise AuthIntentError, 'Authentication intent context must be a Hash' unless context.is_a?(Hash)

        normalized = {}
        context.each_pair do |key, value|
          raise AuthIntentError, 'Authentication intent context keys must be Strings or Symbols' unless key.is_a?(String) || key.is_a?(Symbol)

          normalized[key.to_s] = normalize_auth_intent_value(value)
        end

        validate_auth_intent_type!(normalized)
        normalized
      end

      def validate_auth_intent_type!(intent)
        type = intent['type']
        raise AuthIntentError, 'Authentication intent context must include a non-empty type' unless type.is_a?(String) && !type.empty?
        return unless type.eql?(LINK_INTENT)

        require_bound_identity!(intent, 'user_id')
        require_bound_identity!(intent, 'session_generation')
      end

      def normalize_auth_intent_value(value)
        case value
        when String
          raise AuthIntentError, "Authentication intent context values cannot be longer than #{MAX_AUTH_INTENT_VALUE_LENGTH} characters" if value.length > MAX_AUTH_INTENT_VALUE_LENGTH

          value
        when Symbol then value.to_s
        when Integer, TrueClass, FalseClass, NilClass then value
        when Float
          raise AuthIntentError, 'Authentication intent context values cannot be non-finite numbers' unless value.finite?

          value
        else
          raise AuthIntentError, "Authentication intent context values cannot be #{value.class}"
        end
      end

      def require_bound_identity!(context, field)
        return if bound_identity?(context[field])

        raise AuthIntentError, "A link authentication intent requires a non-empty #{field}"
      end

      def bound_identity?(value)
        value.is_a?(Integer) || (value.is_a?(String) && !value.empty?)
      end
    end
  end
end
