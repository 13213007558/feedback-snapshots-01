# frozen_string_literal: true

module Doorkeeper
  module OpenidConnect
    # The request currently being served by a Doorkeeper controller.
    #
    # Doorkeeper builds its `PreAuthorization` and its request strategies from
    # the configuration object, not from the controller, so those objects have
    # no request of their own. A `CurrentAttributes` slot (reset by Rails'
    # executor after every request) is the narrow bridge that lets them resolve
    # the registration space the request was sent to without threading a new
    # argument through Doorkeeper's constructors.
    #
    # It is only a hint: a request object that can be reached directly (as in
    # the registration and discovery controllers) is always preferred, and a
    # missing hint falls back to the default space.
    class CapabilityPolicyContext < ActiveSupport::CurrentAttributes
      attribute :request
    end
  end
end
