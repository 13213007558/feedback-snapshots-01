# frozen_string_literal: true

module Doorkeeper
  module OpenidConnect
    module OAuth
      # Enforces a registration space's capability policy on the requests that
      # actually enable a client, not just on the documents that describe it.
      #
      # Registration and discovery are only declarations: a client can be
      # registered with a narrow set and still ask for more at `/oauth/authorize`
      # or `/oauth/token`. The policy is therefore applied at three points:
      #
      # * the authorization request (`PreAuthorization`): the requested
      #   response type and scopes must belong to the receiving space;
      # * the token request (`AuthorizationCodeRequest`,
      #   `PasswordAccessTokenRequest`, `ClientCredentialsRequest` and
      #   `RefreshTokenRequest`): the grant type, the client's approved scopes
      #   and the client's approved grant type must belong to the space;
      # * the dynamic registration endpoint, discovery documents and userinfo
      #   (see their controllers).
      #
      # Doorkeeper resolves the space from the request path (the mount
      # namespace), so a request sent to `/admins/oauth/token` is checked
      # against the admins space even though both mounts share one database and
      # one configuration object.
      module CapabilityPolicyRequest
        # A Doorkeeper error the strategy raises. `unauthorized_client` is the
        # RFC 6749 §5.2 code for a client not permitted to use this grant type;
        # `invalid_scope` is the code for scopes outside the approved set.
        def capability_policy
          @capability_policy ||= Doorkeeper::OpenidConnect.current_capability_policy
        end

        def policy_permits_grant_type?(grant_type = self.grant_type)
          capability_policy.permits_grant_type?(grant_type, server)
        end

        def policy_permits_response_type?(response_type)
          capability_policy.permits_response_type?(response_type, server)
        end

        # The scopes this space (and therefore this request) may issue. This
        # intersects the policy with the client's already-approved scopes, so a
        # request cannot use the space's wider set to escape the narrower set
        # its client was registered with.
        def policy_permitted_scopes(requested)
          policy_scopes = capability_policy.effective_scopes(server)
          client_scopes = client_scopes_for_policy
          allowed = if client_scopes.blank?
                      policy_scopes
                    else
                      intersect_policy_scopes(policy_scopes, client_scopes)
                    end
          intersect_policy_scopes(allowed, ::Doorkeeper::OAuth::Scopes.from_string(requested.to_s))
        end

        # Whether the request asks for any scope its space does not approve.
        # Partial approvals are not enough at enforcement time: a registration
        # may silently drop an unsupported scope, but an authorization or token
        # request must be refused so the client is never left believing it
        # received a capability it did not.
        def policy_rejects_scopes?(requested)
          return false unless capability_policy.declares_scopes?

          requested_scopes = ::Doorkeeper::OAuth::Scopes.from_string(requested.to_s)
          return false if requested_scopes.empty?

          policy_permitted_scopes(requested.to_s).all.sort != requested_scopes.all.sort
        end

        private

        def intersect_policy_scopes(base, requested)
          if base.respond_to?(:allowed)
            base.allowed(requested)
          else
            base & requested
          end
        end

        def client_scopes_for_policy
          client_application = respond_to?(:client) ? self.client : nil
          application = if client_application.respond_to?(:application)
                          client_application.application
                        else
                          client_application
                        end
          application.respond_to?(:scopes) ? application.scopes : nil
        end
      end
    end
  end
end
