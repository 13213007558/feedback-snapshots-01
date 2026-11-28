# frozen_string_literal: true

module Doorkeeper
  module OpenidConnect
    module OAuth
      module PreAuthorization
        include CapabilityPolicyRequest

        attr_reader :nonce

        def initialize(server, attrs = {}, resource_owner = nil)
          super
          @nonce = attrs[:nonce]
        end

        # The authorization endpoint is where a client acts on the capabilities
        # it asked for at registration. Doorkeeper's own validations only know
        # the server's global configuration; these two checks add the receiving
        # space's policy, so a client registered in a narrow space cannot
        # broaden its access by sending a wider request to a shared authorize
        # endpoint.
        # Doorkeeper's `authorizable?` is `valid?`; keeping the policy check
        # here means every controller path (consent, prompt=none, direct
        # authorization) sees the same verdict.
        def valid?
          return false unless super

          unless policy_permits_response_type?(response_type)
            @error = Doorkeeper::Errors::UnsupportedResponseType
            return false
          end

          if policy_rejects_scopes?(scope)
            @error = Doorkeeper::Errors::InvalidScope
            return false
          end

          true
        end

        # NOTE: Auto get default response_mode of specified response_type if response_mode is not
        #   yet present. We can delete this method after Doorkeeper's minimize version support it.
        def response_on_fragment?
          return response_mode == "fragment" if response_mode.present?

          grant_flow = server.authorization_response_flows.detect do |flow|
            flow.matches_response_type?(response_type)
          end

          grant_flow&.default_response_mode == "fragment"
        end
      end
    end
  end

  OAuth::PreAuthorization.prepend OpenidConnect::OAuth::PreAuthorization
end
