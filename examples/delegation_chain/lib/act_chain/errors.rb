# frozen_string_literal: true

module ActChain
  # Base error for all delegation-chain (RFC 8693 `act`) validation failures.
  class Error < StandardError; end

  # The `act` claim is present but cannot be parsed into a chain.
  class MalformedChain < Error; end

  # The chain contains more delegation hops than the policy allows.
  class DepthExceeded < Error; end

  # The same subject appears more than once, i.e. the chain loops back.
  class DuplicateSubject < Error; end

  # A hop moves between tenants that the policy does not allow to meet.
  class CrossTenantJump < Error; end

  # A consecutive (actor -> next-actor) edge is not in the allow list.
  class EdgeNotAllowed < Error; end

  # A subject on the path is not authorized to call the final audience.
  class AudienceMismatch < Error; end

  # A hop references evidence whose signature cannot be verified. In
  # non-strict mode this is recorded on the result rather than raised.
  class UnverifiedEvidence < Error; end
end
