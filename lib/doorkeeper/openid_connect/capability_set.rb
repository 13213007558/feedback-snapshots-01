# frozen_string_literal: true

module Doorkeeper
  module OpenidConnect
    # Resolves a policy declaration against the server's global capabilities.
    #
    # The effective set of a space is the global set intersected with what the
    # space declared, except for capabilities it left undeclared, which it
    # inherits wholesale. Keeping that resolution in one object lets the policy,
    # discovery and request enforcement share the exact same arithmetic.
    class CapabilitySet
      INTERNAL_GRANT_TYPE_MAPPING = {
        "implicit_oidc" => "implicit",
      }.freeze

      PUBLIC_CLIENT_AUTH_METHOD = "none"

      CLIENT_CREDENTIALS_METHOD_MAPPING = {
        from_basic: "client_secret_basic",
        from_params: "client_secret_post",
      }.freeze

      def initialize(server, scopes: nil, grant_types: nil, response_types: nil,
                     token_endpoint_auth_methods: nil)
        @server = server
        @scopes = scopes
        @grant_types = grant_types
        @response_types = response_types
        @token_endpoint_auth_methods = token_endpoint_auth_methods
      end

      def scopes
        return server_scopes if @scopes.nil?

        allowed_subset(server_scopes, @scopes)
      end

      def grant_types
        declared = @grant_types&.map { |type| INTERNAL_GRANT_TYPE_MAPPING.fetch(type, type) }
        return global_grant_types if declared.nil?

        global_grant_types & declared
      end

      def response_types
        return @server.authorization_response_types if @response_types.nil?

        @server.authorization_response_types & @response_types
      end

      def token_endpoint_auth_methods
        return global_auth_methods if @token_endpoint_auth_methods.nil?

        global_auth_methods & @token_endpoint_auth_methods
      end

      # Registration methods include the RFC 8414 "none" pseudo-method when
      # the space approves public clients. It is never part of an advertised
      # discovery document, which lists token endpoint authentication methods
      # only.
      def registration_auth_methods
        return token_endpoint_auth_methods | [PUBLIC_CLIENT_AUTH_METHOD] if
          @token_endpoint_auth_methods.nil?

        token_endpoint_auth_methods |
          (@token_endpoint_auth_methods & [PUBLIC_CLIENT_AUTH_METHOD])
      end

      def permits_scopes?(requested)
        return true if @scopes.nil?

        requested_scopes = ::Doorkeeper::OAuth::Scopes.from_string(requested.to_s)
        return true if requested_scopes.empty?

        permitted_scopes(requested).to_s == requested_scopes.to_s
      end

      def permitted_scopes(requested)
        allowed_subset(scopes, ::Doorkeeper::OAuth::Scopes.from_string(requested.to_s))
      end

      def permits_grant_type?(grant_type)
        return true if @grant_types.nil?

        grant_types.include?(INTERNAL_GRANT_TYPE_MAPPING.fetch(grant_type.to_s, grant_type.to_s))
      end

      def permits_response_type?(response_type)
        return true if @response_types.nil?

        response_types.include?(response_type.to_s)
      end

      def permits_token_endpoint_auth_method?(method)
        return registration_auth_methods.include?(method.to_s) if
          method.to_s == PUBLIC_CLIENT_AUTH_METHOD

        token_endpoint_auth_methods.include?(method.to_s)
      end

      private

      attr_reader :server

      # `Scopes#allowed` only exists on Doorkeeper 5.8.1+; older versions have
      # no dynamic scopes, so a plain intersection is equivalent there.
      def allowed_subset(base, requested)
        if base.respond_to?(:allowed)
          base.allowed(requested)
        else
          base & requested
        end
      end

      def server_scopes
        scopes = @server.scopes
        return scopes if scopes.is_a?(::Doorkeeper::OAuth::Scopes)

        ::Doorkeeper::OAuth::Scopes.from_array(scopes.all)
      end

      def global_grant_types
        supported = @server.grant_flows.map do |flow|
          INTERNAL_GRANT_TYPE_MAPPING.fetch(flow, flow)
        end.uniq

        if @server.refresh_token_enabled? && !supported.include?("refresh_token")
          supported << "refresh_token"
        end

        supported
      end

      def global_auth_methods
        names =
          if @server.respond_to?(:client_authentication_methods)
            @server.client_authentication_methods.map { |method| method.name.to_s }
          else
            @server.client_credentials_methods.filter_map do |method|
              CLIENT_CREDENTIALS_METHOD_MAPPING[method]
            end
          end

        names.reject { |name| name == PUBLIC_CLIENT_AUTH_METHOD }
      end
    end
  end
end
