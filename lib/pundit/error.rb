# frozen_string_literal: true

require "pundit/authorization_denied_event"

module Pundit
  # @api private
  # @since v1.0.0
  # To avoid name clashes with common Error naming when mixing in Pundit,
  # keep it here with compact class style definition.
  class Error < StandardError; end

  # Error that will be raised when authorization has failed
  # @since v0.1.0
  class NotAuthorizedError < Error
    # @see #initialize
    # @since v0.2.3
    attr_reader :query
    # @see #initialize
    # @since v0.2.3
    attr_reader :record
    # @see #initialize
    # @since v0.2.3
    attr_reader :policy
    # @see #denied_event
    # @since v2.6.0
    attr_reader :correlation_id

    # @since v1.0.0
    #
    # @overload initialize(message)
    #   Create an error with a simple error message.
    #   @param [String] message A simple error message string.
    #
    # @overload initialize(options)
    #   Create an error with the specified attributes.
    #   @param [Hash] options The error options.
    #   @option options [String] :message Optional custom error message. Will default to a generalized message.
    #   @option options [Symbol] :query The name of the policy method that was checked.
    #   @option options [Object] :record The object that was being checked with the policy.
    #   @option options [Class] :policy The class of policy that was used for the check.
    #   @option options [String] :correlation_id Optional id shared with the {#denied_event}.
    #     A UUID is generated when omitted.
    def initialize(options = {})
      if options.is_a? String
        @correlation_id = SecureRandom.uuid
        super(options)
      else
        @query = options[:query]
        @record = options[:record]
        @policy = options[:policy]
        @correlation_id = options[:correlation_id] || SecureRandom.uuid

        message = options.fetch(:message) do
          record_name = record.is_a?(Class) ? record.to_s : "this #{record.class}"
          "not allowed to #{policy.class}##{query} #{record_name}"
        end

        super(message)
      end
    end

    # The name of the policy class that denied the query.
    #
    # Only the class name is exposed: neither the policy instance nor the
    # restricted record are touched, and +#inspect+ is never called on them.
    #
    # @return [String, nil]
    # @since v2.6.0
    def policy_class_name
      return if policy.nil?

      policy.class.name
    end

    # A public-safe representation of the denial, suitable for public logs or
    # external error trackers.
    #
    # The event retains the {#policy_class_name}, the {#query} and the
    # {#correlation_id}, but never the restricted {#record} or the {#policy}
    # instance. Serializing the exception itself (e.g. via +to_json+ or
    # +Marshal+) also goes through this representation.
    #
    # @return [Pundit::AuthorizationDeniedEvent]
    # @since v2.6.0
    def denied_event
      @denied_event ||= AuthorizationDeniedEvent.from_error(self)
    end

    # @return [Hash{String => Object}] only public-safe event data
    # @since v2.6.0
    def as_json(options = nil)
      denied_event.as_json(options)
    end

    # @return [String] JSON containing only public-safe event data
    # @since v2.6.0
    def to_json(*args)
      denied_event.to_json(*args)
    end

    # Keeps the restricted record and policy instance out of marshalled payloads
    # (e.g. when the exception is passed through a background job). Exceptions
    # use Ruby's +_dump+ / +_load+ marshaling protocol rather than
    # +marshal_dump+ / +marshal_load+.
    #
    # @param _level [Integer] marshaling depth (unused)
    # @return [String]
    # @since v2.6.0
    def _dump(_level)
      Marshal.dump(
        message: message,
        query: query,
        policy_class_name: policy_class_name,
        correlation_id: correlation_id
      )
    end

    # Reconstructs the exception from the data produced by {#_dump}.
    #
    # @param string [String]
    # @return [Pundit::NotAuthorizedError]
    # @since v2.6.0
    def self._load(string)
      data = Marshal.load(string) # rubocop:disable Security/MarshalLoad
      new(
        message: data[:message],
        query: data[:query],
        policy: policy_placeholder(data[:policy_class_name]),
        correlation_id: data[:correlation_id]
      )
    end

    # @param name [String, nil] name of the original policy class
    # @return [nil, Pundit::NotAuthorizedError::PolicyClassPlaceholder] a
    #   stand-in whose {#policy_class_name} is still available, without
    #   restoring the original policy instance or the restricted record
    # @api private
    # @since v2.6.0
    def self.policy_placeholder(name)
      return if name.nil?

      PolicyClassPlaceholder.new(name)
    end

    # Stand-in used when reconstructing an exception from a marshalled event.
    # It only carries the policy class name, so the restricted record and the
    # original policy instance are never part of the serialized payload.
    #
    # @api private
    # @since v2.6.0
    class PolicyClassPlaceholder
      # @param name [String] name of the original policy class
      def initialize(name)
        @name = name
      end

      # @return [Class] an anonymous class whose {Class#name} returns the
      #   original policy class name, so {NotAuthorizedError#policy_class_name}
      #   keeps working after a marshaling round trip
      def klass
        @klass ||= begin
          name = @name
          Class.new do
            define_singleton_method(:name) { name }
          end
        end
      end

      # @return [Class]
      alias_method :class, :klass
    end
  end

  # Error that will be raised if a policy or policy scope constructor is not called correctly.
  # @since v2.0.0
  class InvalidConstructorError < Error; end

  # Error that will be raised if a controller action has not called the
  # `authorize` or `skip_authorization` methods.
  # @since v0.2.3
  class AuthorizationNotPerformedError < Error; end

  # Error that will be raised if a controller action has not called the
  # `policy_scope` or `skip_policy_scope` methods.
  # @since v0.3.0
  class PolicyScopingNotPerformedError < AuthorizationNotPerformedError; end

  # Error that will be raised if a policy or policy scope is not defined.
  # @since v0.1.0
  class NotDefinedError < Error; end
end
