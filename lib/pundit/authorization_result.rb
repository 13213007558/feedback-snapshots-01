# frozen_string_literal: true

module Pundit
  # Outcome of a combined authorization check performed by
  # {Pundit::Context#authorize_all}.
  #
  # The result is safe to serialize into an HTTP response: it never holds the
  # checked records or policy instances, only identifying metadata about the
  # checks ({#checks}) and, on failure, the {#index} of the first business
  # object that was not authorized.
  #
  # @example
  #   result = pundit.authorize_all([ticket, [:organization, resource]], query: :approve?)
  #
  #   if result.success?
  #     ticket.approve!(resource)
  #   else
  #     head :forbidden
  #   end
  #
  # @see Pundit::Context#authorize_all
  # @see Pundit::Authorization#authorize_all
  # @api public
  # @since v2.6.0
  class AuthorizationResult
    # Metadata describing a single check inside a combined authorization.
    #
    # Instances do not hold the record or its policy, only their class names
    # and the query that was performed, so they can be logged or rendered
    # without exposing record details.
    #
    # @!attribute index
    #   @return [Integer] zero-based position of the check in the input
    # @!attribute query
    #   @return [Symbol] the predicate method that was checked
    # @!attribute record_class
    #   @return [String] class name of the record (or the symbol name for a
    #     headless policy)
    # @!attribute policy_class
    #   @return [String] class name of the policy that performed the check
    # @!attribute allowed
    #   @return [Boolean] whether the check passed
    Check = Data.define(:index, :query, :record_class, :policy_class, :allowed) do
      # @return [Boolean] whether the check passed
      def allowed?
        allowed
      end

      # @return [Boolean] inverse of {#allowed}
      def denied?
        !allowed
      end
    end

    include Enumerable

    # @api private
    # @param checks [Array<Hash>] metadata collected while performing the checks
    def initialize(checks)
      @checks = checks.map { |check| Check.new(**check) }
    end

    # @return [Array<Check>] the metadata of every performed check, in order
    attr_reader :checks

    # Allows iterating over the checks without exposing the wrapped array.
    #
    # @yieldparam check [Check]
    # @return [Enumerator, Array]
    def each(&block)
      checks.each(&block)
    end

    # @return [Boolean] true only when every check passed
    def success?
      checks.all?(&:allowed)
    end

    # @return [Boolean] inverse of {#success?}
    def failure?
      !success?
    end
    alias_method :denied?, :failure?

    # @return [Boolean] whether any of the checks was denied
    def any_denied?
      checks.any?(&:denied?)
    end

    # @return [Check, nil] the first denied check, or nil when everything passed
    def first_denied
      checks.find(&:denied?)
    end

    # Zero-based position of the first business object that failed the check.
    #
    # This is how callers learn which object was rejected without the record
    # itself being attached to the result.
    #
    # @return [Integer, nil] the index of {#first_denied}, or nil on success
    def index
      first_denied&.index
    end

    # @return [Array<Integer>] the indexes of every denied check
    def denied_indexes
      checks.select(&:denied?).map(&:index)
    end
  end
end
