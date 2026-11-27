# frozen_string_literal: true

require "doorkeeper/openid_connect/helpers/controller/authorization_binding"
require "doorkeeper/openid_connect/helpers/controller/error_response"
require "doorkeeper/openid_connect/helpers/controller/max_age"
require "doorkeeper/openid_connect/helpers/controller/prompt"
require "doorkeeper/openid_connect/helpers/controller/token_matching"

module Doorkeeper
  module OpenidConnect
    module Helpers
      module Controller
        # Emit `auth_time_from_resource_owner` deprecation at most once per process
        # to avoid spamming logs on every authorize request with `max_age`.
        @auth_time_from_resource_owner_deprecation_warned = false

        def self.warn_auth_time_from_resource_owner_deprecation
          return if @auth_time_from_resource_owner_deprecation_warned

          @auth_time_from_resource_owner_deprecation_warned = true
          warn "DEPRECATION WARNING: `auth_time_from_resource_owner` is deprecated for " \
               "`max_age` enforcement because it cannot distinguish between concurrent " \
               "sessions of the same user, which is a security issue (see " \
               "https://github.com/doorkeeper-gem/doorkeeper-openid_connect/issues/150). " \
               "Please configure `auth_time_from_session` to derive auth_time from the " \
               "current session instead. The `auth_time_from_resource_owner` callback " \
               "continues to be used as a fallback and for the `auth_time` claim on the " \
               "ID Token."
        end

        # Reset the deprecation flag (test helper).
        def self.reset_auth_time_deprecation_warning!
          @auth_time_from_resource_owner_deprecation_warned = false
        end

        # Because this module is prepended onto Doorkeeper's
        # Helpers::Controller, the included modules end up between it and
        # Doorkeeper's implementation in the ancestor chain — their `super`
        # calls (e.g. in `skip_authorization?`) still reach Doorkeeper.
        include AuthorizationBinding
        include ErrorResponse
        include MaxAge
        include Prompt
        include TokenMatching

        private

        def authenticate_resource_owner!
          super.tap do |owner|
            next unless oidc_authorization_request? ||
                        non_oidc_request_with_prompt_handling_enabled?

            # When the configured resource_owner_authenticator redirects an
            # unauthenticated user, +super+ returns whatever +redirect_to+
            # returned (a truthy Integer/String), not a resource owner. Treat
            # that as "no owner" so the OIDC param handling below still runs
            # (e.g. prompt=none must yield login_required per OIDC Core
            # §3.1.2.1) without calling model methods on a non-model value.
            owner = nil if performed?

            # A resumed authorization must act as the account the end user
            # selected for THIS request. The binding is keyed per request, so a
            # concurrent sibling authorization (including a prompt=none one)
            # cannot read or overwrite the selected account.
            bound_owner_id = oidc_bound_resource_owner_id
            if bound_owner_id.present?
              bound_owner = resolve_bound_oidc_resource_owner(bound_owner_id)
              if bound_owner && !performed?
                @current_resource_owner = bound_owner
                owner = bound_owner
              else
                # The bound account no longer resolves (or the host rejected
                # it): fail closed rather than silently falling back to another
                # session's account.
                raise Errors::LoginRequired
              end
            end

            # `max_age` stays OIDC-only (OIDC Core §3.1.2.1); `prompt` is
            # also honored on non-OIDC requests when the option is enabled.
            handle_oidc_max_age_param!(owner) if oidc_authorization_request?
            handle_oidc_prompt_param!(owner)
          end
        rescue Errors::AuthorizationError => e
          # Only OAuth/OIDC protocol errors are reported to the client. Internal
          # errors (e.g. Errors::InvalidConfiguration from an unconfigured
          # callback) must propagate as a 500 rather than being leaked to the
          # client as a spurious authorization error.
          handle_oidc_error!(e)
        end

        def oidc_authorization_request?
          authorization_request_on_authorize_endpoint? &&
            pre_auth.scopes.include?("openid")
        end

        def non_oidc_request_with_prompt_handling_enabled?
          Doorkeeper::OpenidConnect.configuration.apply_prompt_to_non_oidc_requests &&
            authorization_request_on_authorize_endpoint?
        end

        # Resolves the resource owner stored in an authorization binding by
        # re-running the host's configured authenticator with the bound id
        # exposed as `params[:current_user]`. The authenticator owns the
        # resource owner model and its lookup, so the gem never has to name it.
        # Returns nil (or leaves a response performed) when the host cannot
        # authenticate the bound account.
        def resolve_bound_oidc_resource_owner(bound_owner_id)
          original_current_user = params[:current_user]
          params[:current_user] = bound_owner_id
          instance_exec(&Doorkeeper.config.authenticate_resource_owner)
        ensure
          params[:current_user] = original_current_user
        end

        def authorization_request_on_authorize_endpoint?
          controller_path == Doorkeeper::Rails::Routes.mapping[:authorizations][:controllers] &&
            action_name == "new" &&
            pre_auth.valid?
        end

        # Once an authorization response is issued the per-request binding has
        # served its purpose. Drop it so the selected account cannot be replayed
        # by a later request that happens to carry the same correlation key.
        # The binding is kept while an interactive consent screen is still
        # pending: the `new` action that is about to render the form still needs
        # it when the form posts back to `create`.
        def authorize_response
          response = super
          oidc_clear_authorization_binding! unless oidc_consent_screen_pending?
          response
        end

        def oidc_consent_screen_pending?
          action_name == "new" &&
            !skip_authorization? &&
            !(respond_to?(:can_authorize_response?, true) && can_authorize_response?)
        end

        # Clear the previous response body to avoid a DoubleRenderError when
        # rendering or redirecting again after the authenticator already
        # produced a response.
        def clear_oidc_response
          self.response_body = nil

          # Setting `response_body` to nil only resets the response object's
          # body and leaves `@_response_body` assigned, so `performed?` would
          # still return true (rails/rails#25106, still present in Rails 8).
          @_response_body = nil
        end
      end
    end
  end

  Helpers::Controller.prepend OpenidConnect::Helpers::Controller
end
