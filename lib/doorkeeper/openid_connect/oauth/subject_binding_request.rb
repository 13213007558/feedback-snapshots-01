# frozen_string_literal: true

module Doorkeeper
  module OpenidConnect
    module OAuth
      # Enforces the pinned subject policy on the token endpoint and propagates
      # it onto the access token an exchange creates.
      #
      # Both the authorization-code exchange and the refresh grant build a new
      # access token from a previously persisted record (the grant, or the
      # refreshed token). Before minting anything, that record's pinned policy
      # is checked against the client that authenticated the request; a mismatch
      # raises ReauthorizationRequired so the response is an OAuth `invalid_grant`
      # rather than a token carrying the wrong `sub`. When the check passes, the
      # stored binding is copied onto the new token so its ID Token and UserInfo
      # derive the same identifier across the whole life of the authorization.
      module SubjectBindingRequest
        private

        # `client` is the strategy's authenticated client. Doorkeeper strategies
        # hold either the application itself or a wrapper that exposes it via
        # `#application`, so normalize before handing it to the policy check.
        def authenticated_application
          value = respond_to?(:client) ? client : nil
          value.respond_to?(:application) ? value.application : value
        end

        def resource_owner_for_subject(record)
          Doorkeeper::OpenidConnect.configuration
            .resource_owner_from_access_token
            .call(record)
        rescue StandardError
          record.respond_to?(:resource_owner_id) ? record.resource_owner_id : nil
        end
      end

      # Nested names are kept distinct from Doorkeeper's own strategy classes
      # (`Doorkeeper::OAuth::AuthorizationCodeRequest`, …): a constant that
      # shares a name with one of them is resolved relative to the existing
      # `…::OAuth::Authorization` namespace and would not find the nested
      # module. The unique names make the fully-qualified references unambiguous.
      module SubjectBindingAuthorizationCodeRequest
        include SubjectBindingRequest

        private

        def before_successful_response
          owner = resource_owner_for_subject(grant)
          SubjectIdentifier.enforce!(grant, authenticated_application, owner)
          super
        end

        def after_successful_response
          SubjectIdentifier.inherit(access_token, grant)
          super
        end
      end

      module SubjectBindingRefreshTokenRequest
        include SubjectBindingRequest

        private

        def before_successful_response
          owner = resource_owner_for_subject(refresh_token)
          SubjectIdentifier.enforce!(refresh_token, authenticated_application, owner)
          super
        end

        def after_successful_response
          SubjectIdentifier.inherit(access_token, refresh_token)
          super
        end
      end
    end
  end
end

Doorkeeper::OAuth::AuthorizationCodeRequest.prepend(
  Doorkeeper::OpenidConnect::OAuth::SubjectBindingAuthorizationCodeRequest,
)
Doorkeeper::OAuth::RefreshTokenRequest.prepend(
  Doorkeeper::OpenidConnect::OAuth::SubjectBindingRefreshTokenRequest,
)
