# frozen_string_literal: true

module Liquid
  # @liquid_public_docs
  # @liquid_type object
  # @liquid_name self
  # @liquid_summary
  #   Provides access to variables through the current scope chain.
  # @liquid_description
  #   The `self` object resolves variables through the normal lookup hierarchy
  #   (local > file > global) without exposing filters, interrupts, errors,
  #   or other context internals. It's used when bare bracket notation
  #   (`['variable']`) needs to be replaced with an explicit variable lookup.
  #
  #   If `self` is explicitly assigned as a local variable (e.g. `{% assign self = 'value' %}`),
  #   then the local value takes precedence over the `self` object.
  #
  #   A `SelfDrop` is a live view of the context that created it. When it is
  #   resolved in another context (for example after being passed to
  #   `{% render %}`), the lookup is performed against that context instead, so
  #   it can only resolve values that are visible there (explicit render
  #   arguments and globals), not the caller's private local variables.
  # @liquid_access global
  class SelfDrop < Drop
    def initialize(self_context)
      super()
      @self_context = self_context
    end

    def [](key)
      @self_context.find_variable(key)
    rescue UndefinedVariable
      nil
    end

    def key?(key)
      @self_context.variable_defined?(key)
    end

    # Rebind this drop to +context+ unless it is already scoped there.
    # Used at lookup boundaries so a passed-in `self` does not keep a handle on
    # the caller's scope. Returns +self+ when no rebinding is needed.
    #
    # @api private
    def for_context(context)
      @self_context.equal?(context) ? self : self.class.new(context)
    end

    def to_liquid
      self
    end

    def ==(other)
      other.is_a?(SelfDrop) && other.self_context.equal?(@self_context)
    end

    alias_method :eql?, :==

    def hash
      @self_context.object_id.hash
    end

    protected

    attr_reader :self_context

    undef context=
  end
end
