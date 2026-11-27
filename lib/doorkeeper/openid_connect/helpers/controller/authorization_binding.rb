# frozen_string_literal: true

require "digest"

module Doorkeeper
  module OpenidConnect
    module Helpers
      module Controller
        # Binds the interactive part of an authorization request — the account
        # chosen through `prompt=select_account` and the interaction envelope
        # (the original `prompt` values) — to that *single* authorization
        # request rather than to the browser session as a whole.
        #
        # One browser can hold several concurrent authorizations for the same
        # client (e.g. an interactive request in one tab and a
        # `prompt=none` request in another). Storing the selected account in a
        # plain session key would let the second request resume the first one's
        # selection and let a silent request surface an interactive page, so
        # every binding is namespaced under a correlation key:
        #
        #   1. the OIDC `state` parameter when present (the primary key — it is
        #      preserved unchanged across the account-selection redirect);
        #   2. otherwise a stable fingerprint of the request's identifying
        #      parameters, deliberately excluding `prompt` (which the resume
        #      URL strips once handled);
        #   3. as a last resort, the exact `return_to` URL the chooser stored on
        #      the binding when the interactive step began.
        #
        # A `prompt=none` request never opens a binding, so none of these
        # lookups can ever return an interactive selection to it.
        module AuthorizationBinding
          # Session key under which all per-request bindings live. Each entry
          # is itself a Hash keyed by the request correlation key. A String key
          # is used deliberately: the cookie session serializer round-trips
          # symbol keys as strings, so a symbol key would not resolve after the
          # session is reloaded.
          OIDC_AUTHORIZATION_BINDINGS_SESSION_KEY = "oidc_authorization_bindings"

          # Correlation key for the current authorization request.
          def oidc_authorization_binding_key
            state = params[:state].to_s
            return state if state.present?

            self.class.oidc_request_fingerprint(request.query_parameters)
          end

          # Persists the resource owner chosen for this authorization request.
          # Typically called by the host's `select_account_for_resource_owner`
          # flow once the end user picks an account.
          def oidc_bind_selected_resource_owner!(resource_owner_id, return_to: nil)
            binding = oidc_authorization_binding
            binding[:resource_owner_id] = resource_owner_id.to_s
            binding[:return_to] = return_to if return_to
            oidc_store_authorization_binding!(binding)
            binding
          end

          # The resource owner id bound to this request by an earlier
          # interactive step, or nil when the request has no binding (e.g. a
          # fresh `prompt=none` request).
          def oidc_bound_resource_owner_id
            oidc_authorization_binding[:resource_owner_id]
          end

          # Removes every binding that could resolve the current request, so a
          # completed authorization cannot be replayed by a later request.
          def oidc_clear_authorization_binding!
            bindings = session[OIDC_AUTHORIZATION_BINDINGS_SESSION_KEY]
            return unless bindings.is_a?(Hash)

            bindings.delete(oidc_authorization_binding_key)
            bindings.delete(oidc_return_to_binding_key)
            session.delete(OIDC_AUTHORIZATION_BINDINGS_SESSION_KEY) if bindings.empty?
          end

          def self.included(base)
            base.extend(ClassMethods)
          end

          # Stable fingerprint of an authorization request's identifying
          # parameters. `prompt` is intentionally excluded: it is consumed by
          # the interactive step and removed from the resume URL, so including
          # it would make the resumed request hash to a different key.
          module ClassMethods
            def oidc_request_fingerprint(query_parameters)
              relevant = query_parameters.to_unsafe_h.stringify_keys.slice(
                "client_id",
                "redirect_uri",
                "response_type",
                "response_mode",
                "scope",
                "nonce",
                "state",
                "max_age",
                "current_user",
              )
              Digest::SHA256.hexdigest(relevant.sort.to_json)
            end
          end

          private

          # Records the interaction envelope for an incoming authorization
          # request. Called from the prompt handling before any interactive
          # redirect, so the resumed request can prove the `prompt` values it
          # carries match the ones the request started with.
          def oidc_open_authorization_binding!(prompt_values)
            binding = oidc_authorization_binding
            binding[:prompts] = prompt_values.dup
            oidc_store_authorization_binding!(binding)
            binding
          end

          # The binding stored for the current request, or an empty Hash.
          # Returned as a HashWithIndifferentAccess so symbol access keeps
          # working after the cookie session serializes symbol keys into
          # strings. In memory the correlation key and the return-to alias
          # point at the same object, so writes through either stay in sync;
          # the copy here only normalizes access after a serialized reload.
          def oidc_authorization_binding
            bindings = session[OIDC_AUTHORIZATION_BINDINGS_SESSION_KEY]
            return {} unless bindings.is_a?(Hash)

            found = bindings[oidc_authorization_binding_key] ||
                    bindings[oidc_return_to_binding_key]
            return {} unless found.is_a?(Hash)

            found.is_a?(HashWithIndifferentAccess) ? found : found.with_indifferent_access
          end

          def oidc_store_authorization_binding!(binding)
            bindings = session[OIDC_AUTHORIZATION_BINDINGS_SESSION_KEY]
            bindings = {} unless bindings.is_a?(Hash)
            unless binding.is_a?(HashWithIndifferentAccess)
              binding = binding.with_indifferent_access
            end
            bindings[oidc_authorization_binding_key] = binding
            # Also index by the chooser's return URL so the resumed request can
            # find the binding when it carries no `state` (the resume URL drops
            # the handled `prompt`, which would otherwise change the
            # fingerprint). Only a request following that exact URL matches.
            # The alias references the same in-memory binding object.
            if binding[:return_to].present?
              bindings[return_to_binding_key(binding[:return_to])] = binding
            end
            session[OIDC_AUTHORIZATION_BINDINGS_SESSION_KEY] = bindings
          end

          # Key derived from a chooser return URL, matching what a resumed
          # request's full path looks like. Works for both absolute URLs and
          # the relative return paths the chooser actually receives.
          def return_to_binding_key(return_to)
            uri = URI.parse(return_to)
            [uri.path, uri.query && "?#{uri.query}"].compact.join
          rescue URI::InvalidURIError
            return_to
          end

          # Key derived from the current request's full path, matching the
          # `return_to` recorded when the interactive redirect started. Only a
          # request that actually follows the chooser's return URL can match
          # this; a silent `prompt=none` request never carries one.
          def oidc_return_to_binding_key
            request.fullpath
          end

          # Enforces that a resumed request keeps within the interaction
          # envelope it started with. The resume URL strips prompts that were
          # already handled (e.g. `select_account`), so the resumed set is
          # allowed to be a subset of the stored set but may never gain a
          # prompt the request did not begin with. A `prompt=none` request
          # never opens a binding, so it is left untouched here and keeps
          # failing closed through the regular prompt handling.
          def oidc_enforce_authorization_binding!(prompt_values)
            binding = oidc_authorization_binding
            return if binding.empty?
            return if prompt_values.include?("none")

            stored_prompts = binding[:prompts]
            return if stored_prompts.blank?
            return if (prompt_values - stored_prompts).empty?

            raise Errors::InvalidRequest
          end
        end
      end
    end
  end
end
