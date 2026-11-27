# frozen_string_literal: true

module Doorkeeper
  module OpenidConnect
    module OAuth
      # Pins the subject policy onto the records created at issuance time.
      #
      # The authorization-code flow persists an `AccessGrant` first; stamping
      # the grant is what fixes the policy for the whole lifetime of the
      # authorization, because the token exchange and every later refresh read
      # it back from there. The implicit flows never create a grant, so the
      # access token itself is stamped instead.
      module SubjectBinding
        module AuthorizationCode
          def issue_token!
            super.tap do |access_grant|
              SubjectIdentifier.stamp(
                access_grant,
                SubjectIdentifier.binding_for(
                  access_grant.application,
                  resource_owner_for_subject(access_grant),
                ),
              )
            end
          end

          private

          # The grant stores `resource_owner_id`; resolve the owner the same way
          # the rest of the gem does so the `subject` block receives the actual
          # user record rather than its id.
          def resource_owner_for_subject(access_grant)
            Doorkeeper::OpenidConnect.configuration
              .resource_owner_from_access_token
              .call(access_grant)
          rescue StandardError
            access_grant.resource_owner_id
          end
        end

        module AuthorizationToken
          def issue_token!
            super.tap do |access_token|
              next if access_token.nil?

              resource_owner = resolve_resource_owner(access_token)

              SubjectIdentifier.stamp(
                access_token,
                SubjectIdentifier.binding_for(access_token.application, resource_owner),
              )
            end
          end

          private

          def resolve_resource_owner(access_token)
            Doorkeeper::OpenidConnect.configuration
              .resource_owner_from_access_token
              .call(access_token)
          rescue StandardError
            access_token.resource_owner_id
          end
        end
      end
    end
  end
end

Doorkeeper::OAuth::Authorization::Code.prepend(
  Doorkeeper::OpenidConnect::OAuth::SubjectBinding::AuthorizationCode,
)
Doorkeeper::OAuth::Authorization::Token.prepend(
  Doorkeeper::OpenidConnect::OAuth::SubjectBinding::AuthorizationToken,
)
