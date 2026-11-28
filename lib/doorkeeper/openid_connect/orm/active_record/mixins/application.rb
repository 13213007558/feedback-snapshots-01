# frozen_string_literal: true

module Doorkeeper
  module OpenidConnect
    module Orm
      module ActiveRecord
        module Mixins
          module Application
            extend ::ActiveSupport::Concern

            MISSING_COLUMN_MESSAGE =
              "can't write post_logout_redirect_uris: the oauth_applications column is missing — " \
              "run `rails generate doorkeeper:openid_connect:add_post_logout_redirect_uris` " \
              "and `rails db:migrate`"

            included do
              # Class-level probe used by the registration controller before it
              # builds the INSERT. Instance-level `client_capability_columns?`
              # cannot be asked of a new record without triggering attribute
              # reads, and a model that has not run the upgrade migration must
              # be detected without exceptions.
              def self.column_available_for_capability_approval?
                %w[
                  registered_space
                  registered_grant_types
                  registered_response_types
                  registered_token_endpoint_auth_method
                ].all? { |column| column_names.include?(column) }
              rescue StandardError
                false
              end

              # Dynamic registrations record which space approved them and the
              # exact capability set that was approved. The columns are
              # optional: an installation that has not run the upgrade
              # migration keeps working, with the registration endpoint
              # enforcing the space of the receiving mount instead.
              # The registration space (route helper prefix without the trailing
              # underscore: "admins") this client was approved in, or nil for a
              # client created before capability policies existed.
              def registered_space
                return nil unless has_attribute?(:registered_space)

                read_attribute(:registered_space).presence
              end

              def registered_grant_types
                split_registered_list(:registered_grant_types)
              end

              def registered_response_types
                split_registered_list(:registered_response_types)
              end

              def registered_token_endpoint_auth_method
                return nil unless has_attribute?(:registered_token_endpoint_auth_method)

                read_attribute(:registered_token_endpoint_auth_method).presence
              end

              # The capability metadata captured at registration, in the shape
              # CapabilityPolicy#revoked_capabilities expects. A pre-policy
              # client only carries the capabilities Doorkeeper persists for it
              # (scopes, and confidentiality as the "none" auth method).
              def approved_client_capabilities
                {
                  scopes: scopes.all,
                  grant_types: registered_grant_types,
                  response_types: registered_response_types,
                  token_endpoint_auth_method: registered_token_endpoint_auth_method ||
                    (confidential? ? nil : CapabilityPolicy::PUBLIC_CLIENT_AUTH_METHOD),
                }
              end

              # Validate registered post-logout redirect URIs with exactly the
              # same rules Doorkeeper applies to `redirect_uri`, by delegating
              # to its own `Doorkeeper::RedirectUriValidator`. This keeps the
              # two attributes in lockstep (forbidden schemes such as
              # `javascript:`, fragments, relative/opaque URIs, missing host
              # and `force_ssl_in_redirect_uri`) without re-implementing any of
              # that logic here.
              #
              # Per the RP-Initiated Logout spec the registration is optional,
              # so a blank value is allowed (no `post_logout_redirect_uri` may
              # then be used at logout time).
              #
              # Skipped entirely when the column has not been added yet (an
              # existing installation that has not run the upgrade migration),
              # so saving applications keeps working without it.
              validate do
                next unless has_attribute?(:post_logout_redirect_uris)

                raw_value = read_attribute(:post_logout_redirect_uris)
                next if raw_value.blank?

                Doorkeeper::RedirectUriValidator
                  .new(attributes: [:post_logout_redirect_uris])
                  .validate_each(self, :post_logout_redirect_uris, raw_value)
              end

              # Normalizes the value stored in the database. An array is stored
              # as a newline-separated string, mirroring how Doorkeeper handles
              # `redirect_uri` (see Doorkeeper's ApplicationMixin#redirect_uri=).
              #
              # Unlike the read paths (getter, validation, DCR), writing without
              # the column is not silently ignored: dropping a value the caller
              # explicitly assigned would surface much later as a mysteriously
              # rejected logout redirect. Raise a clear error pointing at the
              # missing migration instead of the bare `super: no superclass
              # method` NoMethodError.
              def post_logout_redirect_uris=(uris)
                unless has_attribute?(:post_logout_redirect_uris)
                  raise ActiveModel::MissingAttributeError, MISSING_COLUMN_MESSAGE
                end

                super(uris.is_a?(Array) ? uris.join("\n") : uris)
              end

              # Returns the list of registered post-logout redirect URIs as an
              # array. The stored value is whitespace/newline-separated, matching
              # the way Doorkeeper parses `redirect_uri`.
              #
              # Returns an empty array when the `post_logout_redirect_uris`
              # column has not been added yet (an existing installation that has
              # not run the upgrade migration), so logout-time validation and
              # the DCR response degrade gracefully instead of raising.
              def post_logout_redirect_uris
                return [] unless has_attribute?(:post_logout_redirect_uris)

                super.to_s.split
              end

              # Checks whether the given URI is a valid post-logout redirect URI
              # for this application, i.e. it has been previously registered.
              #
              # @param uri [String] the post-logout redirect URI to validate
              #
              # @return [Boolean] true if the URI is registered, false otherwise
              #
              def valid_post_logout_redirect_uri?(uri)
                return false if uri.blank?

                post_logout_redirect_uris.include?(uri.to_s)
              end

              private

              def split_registered_list(attribute)
                return [] unless has_attribute?(attribute)

                read_attribute(attribute).to_s.split
              end
            end
          end
        end
      end
    end
  end
end
