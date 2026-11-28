# frozen_string_literal: true

module Doorkeeper
  module OpenidConnect
    module OAuth
      class DynamicRegistrationRequest
        include Doorkeeper::Validations
        include Doorkeeper::OpenidConnect::TokenEndpointAuthMethodsSupportedMixin
        include Doorkeeper::OpenidConnect::GrantTypesSupportedMixin

        DEFAULT_TOKEN_ENDPOINT_AUTH_METHOD = "client_secret_basic"
        PUBLIC_CLIENT_AUTH_METHOD = "none"
        DEFAULT_APPLICATION_TYPE = "web"
        SUPPORTED_APPLICATION_TYPES = %w[web native].freeze
        # RFC 7591 §2: when omitted, a client registers for the
        # `authorization_code` grant type and the `code` response type — not
        # for everything the server happens to support.
        DEFAULT_RESPONSE_TYPES = %w[code].freeze
        DEFAULT_GRANT_TYPES = %w[authorization_code].freeze

        validate :token_endpoint_auth_method, error: :invalid_client_metadata
        validate :application_type,           error: :invalid_client_metadata
        validate :response_types,             error: :invalid_client_metadata
        validate :grant_types,                error: :invalid_client_metadata
        validate :scope,                      error: :invalid_client_metadata

        def initialize(server, params, policy: nil)
          @server = server
          @params = params
          @policy = policy
        end

        def token_endpoint_auth_method
          @params[:token_endpoint_auth_method].presence || DEFAULT_TOKEN_ENDPOINT_AUTH_METHOD
        end

        def requested_application_type
          @params[:application_type].presence || DEFAULT_APPLICATION_TYPE
        end

        def requested_response_types
          types = Array(@params[:response_types]).compact_blank
          types.presence || DEFAULT_RESPONSE_TYPES
        end

        def requested_grant_types
          types = Array(@params[:grant_types]).compact_blank
          types.presence || DEFAULT_GRANT_TYPES
        end

        def confidential_client?
          token_endpoint_auth_method != PUBLIC_CLIENT_AUTH_METHOD
        end

        # RFC 7591 §2 lets the authorization server replace or omit requested
        # scopes. The requested scope is intersected against the server's
        # configured scopes (default + optional): partially unrecognized
        # scopes are silently dropped, while a request whose scopes are all
        # unsupported is rejected via #validate_scope, since persisting an
        # empty scope set would make Doorkeeper's ScopeChecker fall back to
        # the full server scope set. `Scopes#allowed` honors dynamic scopes
        # and preserves the requested order, but only exists on Doorkeeper
        # 5.8.1+; older versions fall back to plain intersection (dynamic
        # scopes do not exist there, so nothing is lost).
        def permitted_scopes
          if policy && requested_scopes.present?
            return policy.permitted_scopes(requested_scopes, server).to_s
          end

          permitted_server_scopes.to_s
        end

        # Capability metadata the receiving space must approve. When the
        # registration is evaluated without a policy (a direct call from a
        # legacy integration) the server's global capabilities apply unchanged.
        def policy
          @policy
        end

        def error_response
          { error: error.to_s, error_description: @error_description }
        end

        # The advertised set echoed by the registration response. It must match
        # the receiving space's discovery document, not the global registry.
        def advertised_auth_methods
          return policy.effective_token_endpoint_auth_methods(server) if policy

          token_endpoint_auth_methods_supported
        end

        private

        attr_reader :server

        def validate_token_endpoint_auth_method
          return true if supported_auth_methods.include?(token_endpoint_auth_method)

          @error_description =
            "token_endpoint_auth_method '#{token_endpoint_auth_method}' is not supported. " \
            "Supported methods: #{supported_auth_methods.join(", ")}"
          false
        end

        def validate_application_type
          return true if SUPPORTED_APPLICATION_TYPES.include?(requested_application_type)

          @error_description =
            "application_type '#{requested_application_type}' is not supported. " \
            "Supported types: #{SUPPORTED_APPLICATION_TYPES.join(", ")}"
          false
        end

        def validate_response_types
          unsupported = requested_response_types - supported_response_types
          return true if unsupported.empty?

          @error_description =
            "response_types #{unsupported.join(", ")} are not supported. " \
            "Supported types: #{supported_response_types.join(", ")}"
          false
        end

        def validate_grant_types
          unsupported = requested_grant_types - supported_grant_types
          return true if unsupported.empty?

          @error_description =
            "grant_types #{unsupported.join(", ")} are not supported. " \
            "Supported types: #{supported_grant_types.join(", ")}"
          false
        end

        def requested_scopes
          ::Doorkeeper::OAuth::Scopes.from_string(@params[:scope].to_s)
        end

        # RFC 7591 §2: when the request omits `scope`, the authorization
        # server registers the client with its own default set. Doorkeeper
        # has one — `default_scopes` — and registering with no scopes at all
        # is emphatically not it: an application whose `scopes` column is
        # blank is treated as unrestricted by Doorkeeper's ScopeChecker
        # (`app_scopes.presence || server_scopes`), so an omitted `scope`
        # would register a client entitled to every scope the server defines,
        # while a client that honestly declared a narrow scope stays confined
        # to it.
        def effective_requested_scopes
          requested_scopes.presence || default_registration_scopes
        end

        # When `scope` is omitted, RFC 7591 §2 registers the client for the
        # server's default scopes. A space only approves a subset of them, so
        # its policy narrows that default too; otherwise an omitted scope would
        # register for scopes the space never approved.
        def default_registration_scopes
          return server.default_scopes if policy.nil? || policy.scopes.nil?

          server.default_scopes.allowed(policy.scopes)
        end

        def permitted_server_scopes
          server_scopes = server.scopes

          if server_scopes.respond_to?(:allowed)
            server_scopes.allowed(effective_requested_scopes)
          else
            server_scopes & effective_requested_scopes
          end
        end

        # A registration must never persist an empty scope set, whichever way
        # it got there: neither an explicit `scope` made up entirely of
        # unsupported values, nor an omitted `scope` on a server that
        # configures no default scopes.
        def validate_scope
          return true if permitted_scopes.present?

          supported = policy ? policy.effective_scopes(server).to_s : server.scopes
          @error_description =
            if requested_scopes.present?
              "scope '#{requested_scopes}' contains no scopes supported by this server. " \
              "Supported scopes: #{supported}"
            else
              "scope is required: this server registers no default scopes, so a client " \
              "must request at least one of its supported scopes: #{supported}"
            end
          false
        end

        def supported_response_types
          return policy.effective_response_types(server) if policy

          server.authorization_response_types
        end

        def supported_grant_types
          return policy.effective_grant_types(server) if policy

          grant_types_supported(server)
        end

        def supported_auth_methods
          return policy.permitted_registration_auth_methods(server) if policy

          token_endpoint_auth_methods_supported + [PUBLIC_CLIENT_AUTH_METHOD]
        end

      end
    end
  end
end
