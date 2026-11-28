# frozen_string_literal: true

module Doorkeeper
  module OpenidConnect
    module OAuth
      # Applies a space's capability policy to the token endpoint requests that
      # mint an access token. Doorkeeper's strategies validate differently
      # (authorization-code and refresh run a validation chain, while
      # `ClientCredentialsRequest#valid?` delegates to an issuer that validates
      # and creates its token in one step), so the space is checked in
      # `authorize` before any strategy-specific work. A refusal therefore
      # produces the standard OAuth error response (`unauthorized_client` /
      # `invalid_scope`) before a token is created or a grant is consumed.
      #
      # The receiving space is resolved from the request the strategy serves
      # through `CapabilityPolicyContext` (see the engine's controller hooks).
      module TokenRequestPolicy
        include CapabilityPolicyRequest

        def authorize
          refusal = capability_policy_refusal
          return refusal if refusal

          super
        end

        private

        def capability_policy_refusal
          if !policy_permits_grant_type?
            capability_policy_error(Doorkeeper::Errors::UnauthorizedClient)
          elsif policy_rejects_scopes?(requested_policy_scopes)
            capability_policy_error(Doorkeeper::Errors::InvalidScope)
          end
        end

        def capability_policy_error(error_class)
          Doorkeeper::OAuth::ErrorResponse.new(name: error_class.name_for_response)
        end

        # What the request will actually issue. Strategies that carry a grant
        # or refresh token ask for their scopes; the others fall back to the
        # scopes Doorkeeper resolved for the request.
        def requested_policy_scopes
          if respond_to?(:grant) && grant.respond_to?(:scopes)
            grant.scopes.to_s
          elsif respond_to?(:refresh_token) && refresh_token.respond_to?(:scopes)
            refresh_token.scopes.to_s
          elsif respond_to?(:scopes)
            scopes.to_s
          elsif respond_to?(:parameters) && parameters.respond_to?(:[])
            parameters[:scope].to_s
          else
            ""
          end
        end
      end
    end
  end
end
