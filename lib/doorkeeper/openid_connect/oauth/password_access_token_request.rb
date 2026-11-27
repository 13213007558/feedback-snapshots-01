# frozen_string_literal: true

module Doorkeeper
  module OpenidConnect
    module OAuth
      module PasswordAccessTokenRequest
        attr_reader :nonce

        # Forward every argument: the superclass signature has changed across
        # Doorkeeper versions and keeps changing (e.g. doorkeeper#1794).
        def initialize(...)
          super
          @nonce = parameters[:nonce]
        end

        private

        def after_successful_response
          if access_token.includes_scope?("openid")
            # The password grant has no authorization grant to inherit a policy
            # from, so pin the client's current subject policy directly onto the
            # access token. A no-op on installations without the binding columns.
            SubjectIdentifier.stamp(
              access_token,
              SubjectIdentifier.binding_for(access_token.application, resource_owner),
            )

            id_token = Doorkeeper::OpenidConnect.configuration.id_token_model
                                                .new(access_token, nonce)
            @response.id_token = id_token
          end
          super
        end
      end
    end
  end

  OAuth::PasswordAccessTokenRequest.prepend OpenidConnect::OAuth::PasswordAccessTokenRequest
end
