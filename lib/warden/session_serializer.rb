# encoding: utf-8
# frozen_string_literal: true
module Warden
  # Raised by a +serialize_from_session+ hook when the user could not be
  # reconstituted because of a temporary problem (for example a directory
  # service that is briefly unreachable). The stored identity is kept so the
  # next request can try again.
  class RetryableDeserializationError < StandardError; end

  # Raised by a +serialize_from_session+ hook when the stored identity is no
  # longer valid (for example the account has been deactivated). The stored
  # identity is deleted, signing the scope out.
  class InvalidIdentityError < StandardError; end

  class SessionSerializer
    attr_reader :env

    def initialize(env)
      @env = env
      @retryable_fetch_errors = {}
    end

    def key_for(scope)
      "warden.user.#{scope}.key"
    end

    def serialize(user)
      user
    end

    def deserialize(key)
      key
    end

    def store(user, scope)
      return unless user
      method_name = "#{scope}_serialize"
      specialized = respond_to?(method_name)
      session[key_for(scope)] = specialized ? send(method_name, user) : serialize(user)
    end

    def fetch(scope)
      key = session[key_for(scope)]
      return nil unless key

      @retryable_fetch_errors.delete(scope)
      method_name = "#{scope}_deserialize"
      begin
        user = respond_to?(method_name) ? send(method_name, key) : deserialize(key)
      rescue RetryableDeserializationError => error
        # A temporary failure: keep the stored identity and report the
        # retryable state so the request is treated as unauthenticated without
        # destroying the session. The next request will try again.
        remember_retryable_fetch_error(scope, error)
        return nil
      rescue InvalidIdentityError
        # The identity is permanently invalid, drop the stored record.
        delete(scope)
        return nil
      end

      delete(scope) unless user
      user
    end

    # Whether the last +fetch+ for +scope+ failed because the hook raised a
    # Warden::RetryableDeserializationError rather than because there was no
    # stored identity.
    def retryable_fetch_error?(scope)
      @retryable_fetch_errors.key?(scope)
    end

    # The Warden::RetryableDeserializationError raised by the hook for +scope+
    # on the last +fetch+, or +nil+ when there was no such failure.
    def retryable_fetch_error(scope)
      @retryable_fetch_errors[scope]
    end

    def stored?(scope)
      !!session[key_for(scope)]
    end

    def delete(scope, user=nil)
      session.delete(key_for(scope))
    end

    # We can't cache this result because the session can be lazy loaded
    def session
      env["rack.session"] || {}
    end

    private

    def remember_retryable_fetch_error(scope, error)
      @retryable_fetch_errors[scope] = error
    end
  end # SessionSerializer
end # Warden
