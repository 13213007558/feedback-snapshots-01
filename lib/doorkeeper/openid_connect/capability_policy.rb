# frozen_string_literal: true

module Doorkeeper
  module OpenidConnect
    # Per-namespace client capability policy.
    #
    # A Doorkeeper OIDC installation can be mounted more than once (see
    # `use_doorkeeper_openid_connect as: :admins`). Each mount is a registration
    # *space* with its own client capabilities: scopes, grant types, response
    # types and token endpoint authentication methods. A dynamically registered
    # client may ask for anything, but only what its space explicitly approves
    # may be persisted, advertised in that space's discovery document, or
    # exercised by the client afterwards.
    #
    # This object is the single source of truth for such a policy. It is read by
    # the registration endpoint, the discovery documents and the OAuth request
    # strategies, so those three can never disagree about a space.
    #
    # Every capability may be left undeclared, in which case the space inherits
    # the server's global setting; a declared capability is intersected with it,
    # so a space can narrow what Doorkeeper offers, never widen it.
    class CapabilityPolicy
      PUBLIC_CLIENT_AUTH_METHOD = CapabilitySet::PUBLIC_CLIENT_AUTH_METHOD

      attr_reader :name, :scopes, :grant_types, :response_types,
                  :token_endpoint_auth_methods

      def initialize(name:, scopes: nil, grant_types: nil, response_types: nil,
                     token_endpoint_auth_methods: nil)
        @name = CapabilityPolicy.prefix_for(name)
        @scopes = normalize_scopes(scopes)
        @grant_types = normalize_list(grant_types)
        @response_types = normalize_list(response_types)
        @token_endpoint_auth_methods = normalize_list(token_endpoint_auth_methods)
      end

      # The route helper prefix of the mount this policy belongs to
      # (`admins_`), or "" for the default mount.
      def prefix
        name
      end

      def default?
        prefix.empty?
      end

      # A human-readable space name: "default", "admins", ...
      def space_name
        default? ? "default" : prefix.chomp("_")
      end

      # Whether the policy explicitly declares a capability. An undeclared
      # capability inherits the server's global setting (and therefore cannot
      # cause a previously allowed registration to be revoked).
      def declares_scopes?
        !scopes.nil?
      end

      def declares_grant_types?
        !grant_types.nil?
      end

      def declares_response_types?
        !response_types.nil?
      end

      def declares_token_endpoint_auth_methods?
        !token_endpoint_auth_methods.nil?
      end

      # The space's effective capability set, intersected with what Doorkeeper
      # itself offers. See CapabilitySet.
      def capability_set(server = ::Doorkeeper.configuration)
        CapabilitySet.new(
          server,
          scopes: scopes,
          grant_types: grant_types,
          response_types: response_types,
          token_endpoint_auth_methods: token_endpoint_auth_methods,
        )
      end

      def effective_scopes(server = ::Doorkeeper.configuration)
        capability_set(server).scopes
      end

      def effective_grant_types(server = ::Doorkeeper.configuration)
        capability_set(server).grant_types
      end

      def effective_response_types(server = ::Doorkeeper.configuration)
        capability_set(server).response_types
      end

      def effective_token_endpoint_auth_methods(server = ::Doorkeeper.configuration)
        capability_set(server).token_endpoint_auth_methods
      end

      def permitted_registration_auth_methods(server = ::Doorkeeper.configuration)
        capability_set(server).registration_auth_methods
      end

      def permits_scopes?(requested, server = ::Doorkeeper.configuration)
        capability_set(server).permits_scopes?(requested)
      end

      def permitted_scopes(requested, server = ::Doorkeeper.configuration)
        capability_set(server).permitted_scopes(requested)
      end

      def permits_grant_type?(grant_type, server = ::Doorkeeper.configuration)
        capability_set(server).permits_grant_type?(grant_type)
      end

      def permits_response_type?(response_type, server = ::Doorkeeper.configuration)
        capability_set(server).permits_response_type?(response_type)
      end

      def permits_token_endpoint_auth_method?(method, server = ::Doorkeeper.configuration)
        capability_set(server).permits_token_endpoint_auth_method?(method)
      end

      # Which capabilities of an already-registered client need re-approval
      # under this policy. See CapabilityReview.
      def capability_review(registration, server = ::Doorkeeper.configuration)
        CapabilityReview.new(self, server: server).revoked(registration)
      end

      # Turns a mount name into its route helper prefix: nil/"" -> "",
      # :admins/"admins" -> "admins_".
      def self.prefix_for(name)
        value = name.to_s
        return "" if value.empty?
        return value if value.end_with?("_")

        "#{value}_"
      end

      private

      def normalize_scopes(scopes)
        normalized = normalize_list(scopes)
        return nil if normalized.nil?

        ::Doorkeeper::OAuth::Scopes.from_array(normalized)
      end

      def normalize_list(values)
        return nil if values.nil?

        Array(values).flat_map { |value| value.is_a?(Array) ? value : [value] }
                     .map(&:to_s)
                     .reject(&:empty?)
                     .uniq
      end
    end
  end
end
