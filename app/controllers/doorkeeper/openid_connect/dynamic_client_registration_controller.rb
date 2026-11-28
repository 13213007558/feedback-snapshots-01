# frozen_string_literal: true

module Doorkeeper
  module OpenidConnect
    class DynamicClientRegistrationController < ::Doorkeeper::ApplicationMetalController
      before_action :authorize_dynamic_client_registration!

      def register
        registration = OAuth::DynamicRegistrationRequest.new(
          ::Doorkeeper.configuration,
          params,
          policy: capability_policy,
        )

        unless registration.valid?
          render json: registration.error_response, status: :bad_request
          return
        end

        client = Doorkeeper.configuration.application_model.create!(
          application_params(registration).merge(approval_attributes(registration)),
        )
        render json: registration_response(client, registration), status: :created
      rescue ActiveRecord::RecordInvalid => e
        render json: record_invalid_response(e.record), status: :bad_request
      end

      private

      # The registration space that received this request. The registration
      # route carries the mount's `route_helper_prefix` as a route default, so
      # `/admins/oauth/registration` is evaluated against `admins` and not the
      # default space. A single-mount installation resolves to the default
      # policy, which inherits every global capability.
      def capability_policy
        ::Doorkeeper::OpenidConnect.capability_policy_for(
          request,
          prefix: request.path_parameters[:route_helper_prefix],
        )
      end

      # The capability set the space actually approved, never the raw request
      # declaration, written in the same INSERT as the client so a client is
      # never observable without the approval it was admitted under. The
      # columns are optional (see the application mixin): an installation that
      # has not run the upgrade migration registers clients exactly as before.
      def approval_attributes(registration)
        model = Doorkeeper.configuration.application_model
        return {} unless model.respond_to?(:column_available_for_capability_approval?)
        return {} unless model.column_available_for_capability_approval?

        {
          registered_space: capability_policy.default? ? nil : capability_policy.space_name,
          registered_grant_types: registration.requested_grant_types.join(" "),
          registered_response_types: registration.requested_response_types.join(" "),
          registered_token_endpoint_auth_method: registration.token_endpoint_auth_method,
        }
      end

      def authorize_dynamic_client_registration!
        authorizer = ::Doorkeeper::OpenidConnect.configuration.authorize_dynamic_client_registration
        return if authorizer.nil?

        return if authorized?(authorizer)

        response.headers["WWW-Authenticate"] = "Bearer error=\"invalid_token\""
        render json: {
          error: "invalid_token",
          error_description: I18n.t(
            "doorkeeper.openid_connect.errors.messages.dynamic_client_registration_unauthorized",
          ),
        }, status: :unauthorized
      end

      def authorized?(authorizer)
        if authorizer.respond_to?(:to_proc)
          instance_exec(&authorizer.to_proc)
        elsif authorizer.respond_to?(:call)
          authorizer.call(self)
        else
          authorizer
        end
      end

      def record_invalid_response(record)
        {
          error: registration_error_code(record),
          error_description: record.errors.full_messages.join(", "),
        }
      end

      # RFC 7591 §3.2.2 registration error codes: `invalid_redirect_uri` for
      # redirect URI problems, `invalid_client_metadata` for everything else.
      def registration_error_code(record)
        record.errors.include?(:redirect_uri) ? "invalid_redirect_uri" : "invalid_client_metadata"
      end

      def application_params(registration)
        application_params = {
          name: params[:client_name],
          redirect_uri: params[:redirect_uris] || [],
          scopes: registration.permitted_scopes,
          confidential: registration.confidential_client?,
        }

        # Existing installations may not have run the migration that adds the
        # `post_logout_redirect_uris` column yet. RFC 7591 §2 allows the server
        # to ignore client metadata it does not understand, so the parameter is
        # simply dropped in that case instead of failing the registration.
        if post_logout_redirect_uris_supported?
          application_params[:post_logout_redirect_uris] = params[:post_logout_redirect_uris] || []
        end

        application_params
      end

      def post_logout_redirect_uris_supported?
        Doorkeeper.config.application_model.column_names.include?("post_logout_redirect_uris")
      end

      # One method per metadata document: the registration response echoes
      # the client metadata as RFC 7591 §3.2.1 lists it, and splitting it
      # would hide the shape of the published document.
      # rubocop:disable Metrics/AbcSize
      def registration_response(doorkeeper_application, registration)
        response = {
          client_id: doorkeeper_application.uid,
          client_id_issued_at: doorkeeper_application.created_at.to_i,
          # RFC 7591 §3.2.1: the response must include all registered client
          # metadata. The name is always present on a successfully created
          # application (the model validates its presence).
          client_name: doorkeeper_application.name,
          redirect_uris: doorkeeper_application.redirect_uri.split,
          token_endpoint_auth_method: registration.token_endpoint_auth_method,
          token_endpoint_auth_methods_supported: registration.advertised_auth_methods,
          response_types: registration.requested_response_types,
          grant_types: registration.requested_grant_types,
          scope: doorkeeper_application.scopes.to_s,
          application_type: registration.requested_application_type,
        }

        # Registration is optional (RP-Initiated Logout §2), so the metadata
        # field is only echoed when post-logout redirect URIs were registered.
        post_logout_uris = doorkeeper_application.post_logout_redirect_uris
        response[:post_logout_redirect_uris] = post_logout_uris if post_logout_uris.present?

        if registration.confidential_client?
          response[:client_secret] =
            doorkeeper_application.plaintext_secret || doorkeeper_application.secret
          # RFC 7591 §3.2.1 / OIDC Dynamic Client Registration 1.0 §3.2:
          # client_secret_expires_at is REQUIRED when a client_secret is issued.
          # Doorkeeper secrets never expire, so the value is 0 (no expiration).
          response[:client_secret_expires_at] = 0
        end

        response
      end
      # rubocop:enable Metrics/AbcSize
    end
  end
end
