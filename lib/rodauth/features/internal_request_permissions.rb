# frozen-string-literal: true

module Rodauth
  # The internal_request_permissions feature requires internal_request.
  # When enabled, every internal request must include a :principal option,
  # and the principal must have been registered for the requested operation
  # using internal_request_permission:
  #
  #   plugin :rodauth do
  #     enable :internal_request_permissions, :verify_account
  #
  #     internal_request_permission :account_reader,
  #       :account_exists?, :account_id_for_login
  #     internal_request_permission :account_notifier,
  #       :verify_account
  #   end
  #
  #   App.rodauth.account_exists?(principal: :account_reader, login: 'foo@example.com')
  #
  # A principal is allowed an operation either by registering the operation
  # itself, or by registering the feature that handles it.  Registration
  # happens at configuration time, and the actual operation is authorized
  # before Rodauth loads an account or runs any route hooks for the internal
  # request.
  #
  # Unapproved operations raise Rodauth::InternalRequestNotAuthorized.
  Feature.define(:internal_request_permissions, :InternalRequestPermissions) do
    depends :internal_request
  end
end
