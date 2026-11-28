# frozen_string_literal: true

module Doorkeeper
  module OpenidConnect
    # Answers which capabilities of an already-registered client need
    # re-approval under a space's current policy.
    #
    # A configuration change never rewrites a stored client by itself: the
    # scopes, grant types, response types and authentication method captured at
    # registration stay as they were. What changes is whether the *current*
    # policy would still admit them. This object reports exactly that, and only
    # for the capabilities the policy actually declares — an undeclared
    # capability inherits the server's global setting and therefore cannot
    # withdraw an earlier approval.
    class CapabilityReview
      attr_reader :policy, :server

      def initialize(policy, server: ::Doorkeeper.configuration)
        @policy = policy
        @server = server
      end

      # @param registration [Hash] `scopes`, `grant_types`, `response_types`,
      #   `token_endpoint_auth_method` captured at registration time
      # @return [Array<Symbol>] capability categories needing re-approval
      def revoked(registration)
        revoked = []
        revoked << :scopes if scopes_revoked?(registration)
        revoked << :grant_types if grant_types_revoked?(registration)
        revoked << :response_types if response_types_revoked?(registration)
        revoked << :token_endpoint_auth_method if auth_method_revoked?(registration)
        revoked
      end

      private

      def scopes_revoked?(registration)
        policy.declares_scopes? &&
          !policy.permits_scopes?(Array(registration[:scopes]).join(" "), server)
      end

      def grant_types_revoked?(registration)
        return false unless policy.declares_grant_types?

        Array(registration[:grant_types]).any? do |grant_type|
          !policy.permits_grant_type?(grant_type, server)
        end
      end

      def response_types_revoked?(registration)
        return false unless policy.declares_response_types?

        Array(registration[:response_types]).any? do |response_type|
          !policy.permits_response_type?(response_type, server)
        end
      end

      def auth_method_revoked?(registration)
        return false unless policy.declares_token_endpoint_auth_methods?

        method = registration[:token_endpoint_auth_method]
        method && !policy.permits_token_endpoint_auth_method?(method, server)
      end
    end
  end
end
