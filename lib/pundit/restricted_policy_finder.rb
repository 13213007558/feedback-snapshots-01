# frozen_string_literal: true

module Pundit
  # A {PolicyFinder} that only resolves policies which have explicitly been
  # approved (allowlisted) for the caller.
  #
  # This is intended for situations where the same models and policies are
  # served through more than one entry point, for example an internal gateway
  # and an external partner API. The partner entry point registers only the
  # policy classes it is allowed to use; every other lookup is refused even
  # though the policy exists in the application.
  #
  # Namespace handling and model level `policy_class` overrides are inherited
  # unchanged from {PolicyFinder}. The restriction is layered on top of the
  # normal lookup, so the recorded namespace is preserved.
  #
  # The two failure modes stay distinguishable:
  #
  # - the policy cannot be located at all => {NotDefinedError}
  # - the policy exists but is not approved => {NotApprovedError}
  #
  # @example Restricting a Pundit context
  #   finder_class = Pundit::RestrictedPolicyFinder.with_allowed(
  #     [Partner::PostPolicy, Partner::InvoicePolicy]
  #   )
  #   context = Pundit::Context.new(user: partner, policy_finder_class: finder_class)
  #
  # @see PolicyFinder
  # @since v2.6.0
  class RestrictedPolicyFinder < PolicyFinder
    # Builds a finder class bound to the given allowlist.
    #
    # The allowlist may contain policy classes (recommended) or their names as
    # strings/symbols. A subclass is returned rather than mutating a shared
    # constant, so each entry point can carry its own allowlist.
    #
    # @param allowed_policies [Array<Class, String, Symbol>] the approved policies
    # @return [Class<RestrictedPolicyFinder>] a configured finder class
    # @since v2.6.0
    def self.with_allowed(allowed_policies)
      allowlist = Array(allowed_policies).map { |policy| policy_name(policy) }.compact.uniq

      Class.new(self) do
        define_singleton_method(:allowed_policy_names) { allowlist }
      end
    end

    # The names of the policies this finder is allowed to resolve.
    #
    # Subclasses (typically built via {.with_allowed}) override this. The base
    # class approves nothing, which is the safe default.
    #
    # @return [Array<String>]
    # @since v2.6.0
    def self.allowed_policy_names
      []
    end

    # @return [Class, nil] the approved policy class, or nil if it cannot be found
    # @raise [NotApprovedError] if the policy exists but is not on the allowlist
    # @since v2.6.0
    def policy
      located = super
      return if located.nil?

      unless approved?(located)
        raise NotApprovedError,
          "policy `#{policy_name}` resolves to `#{located}` which is not approved for `#{object.inspect}`"
      end

      located
    end

    # @return [Class] the approved policy class
    # @raise [NotDefinedError] if the policy cannot be found
    # @raise [NotApprovedError] if the policy exists but is not on the allowlist
    # @since v2.6.0
    def policy!
      policy or raise NotDefinedError, "unable to find policy `#{policy_name}` for `#{object.inspect}`"
    end

    private

    # Whether the given policy class is on the allowlist.
    #
    # @param policy_class [Class]
    # @return [Boolean]
    # @since v2.6.0
    def approved?(policy_class)
      self.class.allowed_policy_names.include?(self.class.policy_name(policy_class))
    end

    # The name the underlying, unrestricted, lookup would resolve to.
    #
    # `find` is private in {PolicyFinder}; expose the recorded name without
    # constantizing it so error messages can describe what was looked up.
    #
    # @return [String]
    # @since v2.6.0
    def policy_name
      self.class.policy_name(find(object))
    end

    # Normalizes a policy reference (class, string or symbol) to its name.
    #
    # Anonymous classes have no name and are never approvable by name.
    #
    # @param policy [Class, String, Symbol, nil]
    # @return [String, nil]
    # @since v2.6.0
    def self.policy_name(policy)
      name = policy.is_a?(Class) ? policy.name : policy&.to_s
      name = name.to_s
      name unless name.empty?
    end
  end
end
