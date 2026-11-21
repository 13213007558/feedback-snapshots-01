# frozen_string_literal: true

require "json"
require "securerandom"

module Pundit
  # A serialization-safe, public representation of a denied authorization.
  #
  # Unlike {Pundit::NotAuthorizedError}, an event never holds the restricted
  # record or the policy instance. It only carries data that is safe to emit to
  # a public log or an external error tracker: the policy class name, the query
  # that was denied, and a correlation id that ties the public event back to
  # the locally captured exception.
  #
  # Building an event never calls +#inspect+ (or any other method) on the
  # record, so models with a custom +#inspect+ are never invoked.
  #
  # @example Logging a denial from a Rails controller
  #   rescue_from Pundit::NotAuthorizedError, with: :user_not_authorized
  #
  #   def user_not_authorized(exception)
  #     PUBLIC_LOGGER.info(exception.denied_event.to_json)
  #     head :forbidden
  #   end
  #
  # @since v2.6.0
  class AuthorizationDeniedEvent
    # @return [String] fixed event type, useful for routing log entries
    attr_reader :event
    # @return [String, nil] name of the policy class that denied the query
    attr_reader :policy_class
    # @return [String, nil] the predicate method that was checked, e.g. +"update?"+
    attr_reader :query
    # @return [String] random id shared with the originating exception
    attr_reader :correlation_id

    # Builds an event from a {Pundit::NotAuthorizedError}.
    #
    # @param error [Pundit::NotAuthorizedError] the captured authorization error
    # @return [Pundit::AuthorizationDeniedEvent]
    def self.from_error(error)
      new(
        policy_class: error.policy_class_name,
        query: error.query,
        correlation_id: error.correlation_id
      )
    end

    # @param policy_class [String, Module, nil] the policy class or its name
    # @param query [Symbol, String, nil] the predicate method that was checked
    # @param correlation_id [String] id shared with the originating exception
    def initialize(policy_class:, query:, correlation_id: SecureRandom.uuid)
      @event = "pundit.authorization_denied"
      @policy_class =
        if policy_class.nil? || policy_class.is_a?(String)
          policy_class
        else
          policy_class.name
        end
      @query = query&.to_s
      @correlation_id = correlation_id
    end

    # @return [Hash{String => Object}] a hash containing only public-safe values
    def to_h
      {
        "event" => event,
        "policy_class" => policy_class,
        "query" => query,
        "correlation_id" => correlation_id
      }
    end

    # @return [String] JSON representation containing only public-safe values
    def to_json(*args)
      as_json.to_json(*args)
    end

    # @param options [Hash] standard +ActiveSupport#as_json+ options
    # @return [Hash{String => Object}]
    def as_json(options = nil)
      hash = to_h
      return hash unless hash.respond_to?(:as_json)

      hash.as_json(options)
    end

    # @return [String]
    def inspect
      "#<#{self.class.name} #{to_h.inspect[1...-1]}>"
    end

    # @param other [Object]
    # @return [Boolean]
    def ==(other)
      other.is_a?(self.class) && other.to_h == to_h
    end
    alias_method :eql?, :==

    # @return [Integer]
    def hash
      to_h.hash
    end
  end
end
