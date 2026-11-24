# frozen_string_literal: true

module Grape
  module HelperCallPermission
    Definition = Data.define(:name, :owner, :source_location) do
      def self.from_method(method)
        new(name: method.name, owner: method.owner, source_location: method.source_location)
      end

      def self.unresolved(name)
        new(name: name.to_sym, owner: nil, source_location: nil)
      end

      def implementation_id
        "#{owner_label}##{name}"
      end

      def owner_label
        return owner.name if owner.is_a?(Module) && owner.name
        return owner.inspect if owner.is_a?(Module)

        '(unresolved)'
      end
    end

    Decision = Data.define(:allowed, :scope, :definition, :reason) do
      def allowed?
        allowed
      end
    end

    class Policy
      Rule = Data.define(:method_name, :scope, :owner, :implementation_id, :source_location) do
        def match?(definition, requested_scope)
          method_name == definition.name &&
            scope == requested_scope&.to_sym &&
            owner_match?(definition) &&
            implementation_id_match?(definition) &&
            source_location_match?(definition)
        end

        def description
          return implementation_id if implementation_id
          return "#{owner}##{method_name}" if owner

          "source #{source_location}"
        end

        private

        def owner_match?(definition)
          owner.nil? || owner == definition.owner
        end

        def implementation_id_match?(definition)
          return true if implementation_id.nil?
          return implementation_id === definition.implementation_id if implementation_id.is_a?(Regexp)

          implementation_id.to_s == definition.implementation_id
        end

        def source_location_match?(definition)
          return true if source_location.nil?
          return false if definition.source_location.nil?
          return source_location.match?(definition.source_location.join(':')) if source_location.is_a?(Regexp)

          source_location == definition.source_location
        end
      end

      private_constant :Rule

      def initialize(rules = [])
        @rules = rules
      end

      def allow(method_name, scope:, owner: nil, implementation_id: nil, source_location: nil)
        if owner.nil? && implementation_id.nil? && source_location.nil?
          raise ArgumentError, 'an exact owner, implementation_id, or source_location is required'
        end

        @rules << Rule.new(method_name.to_sym, scope.to_sym, owner, implementation_id, source_location)
        self
      end

      def authorize(definition, scope:)
        scope = scope&.to_sym
        rule = @rules.find { |candidate| candidate.match?(definition, scope) }
        return Decision.new(true, scope, definition, nil) if rule

        Decision.new(false, scope, definition, denial_reason(definition, scope))
      end

      private

      def denial_reason(definition, scope)
        approved = approved_descriptions(definition.name, scope)
        location = definition.source_location&.join(':') || 'unknown location'
        base = "Helper `#{definition.name}` in scope `#{scope}` resolved to unapproved implementation " \
               "`#{definition.implementation_id}` (#{location}); business call blocked."
        return "#{base} No implementation is approved for this scope." if approved.empty?

        "#{base} Approved implementations: #{approved.join(', ')}."
      end

      def approved_descriptions(name, scope)
        @rules.select { |rule| rule.method_name == name && rule.scope == scope }
              .map(&:description)
      end
    end

    class Denied < Grape::Exceptions::Base
      attr_reader :decision

      def initialize(decision)
        @decision = decision
        super(status: 403, message: decision.reason)
      end
    end

    class Enforcement
      attr_reader :policy, :scope, :method_names, :recorder

      def initialize(policy:, scope:, methods:, recorder: nil)
        @policy = policy
        @scope = scope.to_sym
        @method_names = Array(methods).map(&:to_sym)
        @recorder = recorder
        @interceptor_module = build_interceptor_module
      end

      def helper_module
        enforcement = self
        Module.new do
          define_singleton_method(:included) do |base|
            base.prepend(enforcement.interceptor_module)
          end
        end
      end

      def interceptor_module
        @interceptor_module
      end

      def invoke(endpoint, method_name, args, kwargs, block)
        implementation = resolved_implementation(endpoint, method_name)
        definition = implementation ? Definition.from_method(implementation) : Definition.unresolved(method_name)
        decision = policy.authorize(definition, scope:)
        record(decision_payload(decision, endpoint))
        raise Denied, decision unless decision.allowed?

        implementation.call(*args, **kwargs, &block)
      end

      private

      def resolved_implementation(endpoint, method_name)
        endpoint.method(method_name).super_method
      rescue NameError
        nil
      end

      def build_interceptor_module
        enforcement = self
        Module.new do
          enforcement.method_names.each do |method_name|
            define_method(method_name) do |*args, **kwargs, &block|
              enforcement.invoke(self, method_name, args, kwargs, block)
            end
          end
        end
      end

      def decision_payload(decision, endpoint)
        definition = decision.definition
        {
          event: :helper_call_permission,
          phase: decision.allowed? ? :allowed : :denied,
          allowed: decision.allowed?,
          scope: decision.scope,
          endpoint_namespace: endpoint_namespace(endpoint),
          request_path: request_path(endpoint),
          method_name: definition.name,
          definition: definition.implementation_id,
          owner: definition.owner,
          source_location: definition.source_location,
          reason: decision.reason
        }
      end

      def endpoint_namespace(endpoint)
        return unless endpoint.respond_to?(:namespace)

        endpoint.namespace
      end

      def request_path(endpoint)
        return unless endpoint.respond_to?(:env) && endpoint.env

        endpoint.env[Rack::PATH_INFO]
      end

      def record(payload)
        return unless recorder

        if recorder.respond_to?(:call)
          recorder.call(payload)
        else
          recorder << payload
        end
      end
    end

    module DSL
      private

      def enforce_helper_call_permissions(policy:, scope:, methods:, recorder: nil)
        enforcement = Enforcement.new(policy:, scope:, methods:, recorder:)
        helpers(enforcement.helper_module)
      end
    end
  end
end
