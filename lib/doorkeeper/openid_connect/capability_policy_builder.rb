# frozen_string_literal: true

module Doorkeeper
  module OpenidConnect
    # Builds the per-space capability policies declared through the
    # `client_capabilities` configuration option:
    #
    #   client_capabilities do
    #     space :admins do
    #       scopes :openid, :profile
    #       grant_types :authorization_code, :client_credentials
    #       response_types :code
    #       token_endpoint_auth_methods :client_secret_basic
    #     end
    #   end
    #
    # The block-less form declares the default space instead:
    #
    #   client_capabilities scopes: [:openid], grant_types: [:authorization_code]
    #
    # Within a `space`, a capability left undeclared inherits the server's
    # global setting. `space` may be called for a namespace that has no mount;
    # its policy is still kept, so configuration can be inspected — and a typo
    # caught — before the route exists.
    class CapabilityPolicyBuilder
      def initialize(&block)
        @policies = []
        instance_eval(&block) if block
      end

      def build
        @policies
      end

      # Declares one registration space. The name is the mount namespace
      # (`:admins` for `use_doorkeeper_openid_connect as: :admins`).
      def space(name, &block)
        policy = SpaceBuilder.new(name).build(block)
        @policies << policy
        policy
      end

      # Declares the default (un-namespaced) space.
      def default_space(&block)
        space(:"", &block)
      end

      # A shorthand for the default space when no block DSL is needed.
      def declare(name = "", **capabilities)
        @policies << SpaceBuilder.new(name).build(nil, capabilities)
        @policies.last
      end

      class SpaceBuilder
        def initialize(name)
          @name = name
          @capabilities = {}
        end

        def build(block = nil, explicit = {})
          @capabilities.merge!(explicit)

          if block
            # The block is evaluated against a fresh DSL evaluator, keeping the
            # capability setters from being shadowed by Object methods.
            evaluator = Evaluator.new(@capabilities)
            evaluator.instance_eval(&block)
          end

          CapabilityPolicy.new(
            name: @name,
            scopes: @capabilities[:scopes],
            grant_types: @capabilities[:grant_types],
            response_types: @capabilities[:response_types],
            token_endpoint_auth_methods: @capabilities[:token_endpoint_auth_methods],
          )
        end
      end

      # The DSL a `space` block runs against. It only exposes the capability
      # setters, so a host application cannot accidentally redefine `scopes`
      # or `grant_types` on the policy object itself.
      class Evaluator
        def initialize(capabilities)
          @capabilities = capabilities
        end

        def scopes(*values)
          @capabilities[:scopes] = flatten(values)
        end

        def grant_types(*values)
          @capabilities[:grant_types] = flatten(values)
        end

        def response_types(*values)
          @capabilities[:response_types] = flatten(values)
        end

        def token_endpoint_auth_methods(*values)
          @capabilities[:token_endpoint_auth_methods] = flatten(values)
        end

        # Explicitly inherit every capability the server supports in this
        # space. Useful for the default space when a narrower namespace
        # exists, so the default space keeps its historical unrestricted
        # behaviour by intent rather than by accident.
        def inherit!
          @capabilities.clear
        end

        private

        def flatten(values)
          values.flatten.map(&:to_s).reject(&:empty?)
        end
      end
    end
  end
end
