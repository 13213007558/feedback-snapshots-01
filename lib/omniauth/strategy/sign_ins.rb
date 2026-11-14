module OmniAuth
  module Strategy
    # Keeps the origin and params of several sign-ins in progress at once,
    # for example in several tabs, so each callback gets its own. Without
    # this, the session holds a single omniauth.origin and omniauth.params,
    # and starting a sign-in replaces the last one's.
    #
    # A strategy opts in when its provider sends a value from the request
    # phase back to the callback, such as OAuth 2.0's state. Its request
    # phase calls remember_sign_in with that value, and it overrides
    # callback_sign_in_key to return the value from the callback.
    #
    # When an auth intent is configured (see AuthIntents), the record also
    # carries it, bound to this strategy's name, so neither can be paired
    # with another transaction's key or another strategy's callback.
    module SignIns
      # How many sign-ins are remembered. Remembering another forgets the
      # oldest.
      MAX_REMEMBERED_SIGN_INS = 5

      # Remembers the origin and params stored for the current request phase
      # under key, which the provider sends back to the callback. With an
      # auth intent configured, the record also carries this phase's intent.
      def remember_sign_in(key)
        return if key.empty?

        sign_in = {'origin' => session['omniauth.origin'], 'params' => session['omniauth.params']}
        if auth_intent_enabled?
          sign_in['strategy'] = name
          sign_in['auth_intent'] = capture_auth_intent
        end

        sign_ins = remembered_sign_ins
        sign_ins.delete(key)
        sign_ins[key] = sign_in
        session['omniauth.sign_ins'] = sign_ins.to_a.last(MAX_REMEMBERED_SIGN_INS).to_h
      end

      # The key the callback sends back, which a strategy that calls
      # remember_sign_in returns. Nil for a strategy that doesn't.
      def callback_sign_in_key; end

    protected

      # The origin and params for this callback, removed from the session:
      # the ones remembered under its key, or else omniauth.origin and
      # omniauth.params, which hold the latest sign-in's. An intent-enabled
      # callback only takes a record this strategy remembered, so its intent
      # and data cannot come from another transaction.
      def recall_sign_in
        key = callback_sign_in_key
        return recall_bound_sign_in(key) if auth_intent_enabled?

        recall_legacy_sign_in(key)
      end

      def recall_legacy_sign_in(key)
        fallback = {'origin' => session.delete('omniauth.origin'), 'params' => session.delete('omniauth.params')}
        sign_ins = remembered_sign_ins
        remembered = find_sign_in_key(sign_ins, key)
        sign_in = sign_ins.delete(remembered)
        return fallback unless sign_in

        session['omniauth.sign_ins'] = sign_ins
        sign_in
      end

      # A record is accepted only when this strategy created it, so another
      # strategy's record (or one left over from before intents were enabled)
      # cannot be consumed as this transaction. An unknown or already
      # consumed key yields an empty record, which the callback reports as a
      # missing intent. The fallback to omniauth.origin and omniauth.params
      # is deliberately not used: those hold the latest sign-in's data, which
      # may belong to another transaction.
      def recall_bound_sign_in(key)
        sign_ins = remembered_sign_ins
        remembered = find_bound_sign_in_key(sign_ins, key)
        sign_in = sign_ins.delete(remembered)
        return {'origin' => nil, 'params' => nil} unless sign_in

        session['omniauth.sign_ins'] = sign_ins
        sign_in
      end

      def find_sign_in_key(sign_ins, key)
        return unless key.instance_of?(String)

        sign_ins.keys.detect { |stored| stored.is_a?(String) && Rack::Utils.secure_compare(stored, key) }
      end

      def find_bound_sign_in_key(sign_ins, key)
        return unless key.instance_of?(String)

        sign_ins.keys.detect do |stored|
          record = sign_ins[stored]
          stored.is_a?(String) && Rack::Utils.secure_compare(stored, key) &&
            record.is_a?(Hash) && record['strategy'].eql?(name)
        end
      end

      # A copy of the remembered sign-ins, which are changed by assigning the
      # session key, not in place.
      def remembered_sign_ins
        sign_ins = session['omniauth.sign_ins']
        sign_ins.is_a?(Hash) ? sign_ins.dup : {}
      end
    end
  end
end
