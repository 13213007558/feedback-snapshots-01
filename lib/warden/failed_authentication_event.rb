# encoding: utf-8
# frozen_string_literal: true
module Warden
  # A sanitized record of a failed authentication attempt.
  #
  # This is the only object handed to +on_failed_authentication+ hooks.
  # It deliberately exposes just the failure +category+ and the +scope+
  # that was being authenticated, so it is safe to forward to audit or
  # scheduling systems. It never carries credentials, strategy failure
  # messages, or the raw Rack env.
  #
  # :api: public
  class FailedAuthenticationEvent
    # The category of the failure, taken from the winning strategy result
    # (for example :failure, :redirect or :custom).
    # :api: public
    attr_reader :category

    # The scope that failed to authenticate.
    # :api: public
    attr_reader :scope

    def initialize(category, scope) #:nodoc:
      @category, @scope = category, scope
    end

    # The event as a plain Hash, containing only :category and :scope.
    # :api: public
    def to_h
      { :category => category, :scope => scope }
    end

    def ==(other) #:nodoc:
      other.is_a?(FailedAuthenticationEvent) &&
        other.category == category && other.scope == scope
    end
    alias eql? ==

    def inspect #:nodoc:
      "#<Warden::FailedAuthenticationEvent category=#{category.inspect} scope=#{scope.inspect}>"
    end
  end
end
