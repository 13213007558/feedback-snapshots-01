# frozen_string_literal: true
module SecureHeaders
  # Utilities that define the ownership boundaries between three kinds of
  # configuration:
  #
  #   1. Registered configs (the global default and named overrides) - these
  #      are deep-frozen and must never alias mutable objects supplied by a
  #      caller. Mutating the arguments after registration therefore cannot
  #      change a registered policy.
  #   2. Per-request configs - these are deep copies owned by the request.
  #      They stay writable and freezing one never freezes an object the
  #      caller still holds.
  #   3. OPT_OUT - a global singleton. It is never copied and never frozen,
  #      preserving its identity semantics.
  module Ownership
    module_function

    # Deep, non-mutating copy of a configuration value. Hashes and arrays are
    # rebuilt recursively; every other object (strings, booleans, nil and the
    # OPT_OUT singleton) is shared because it is immutable or identity-based.
    def deep_dup(value)
      case value
      when Hash
        value.each_with_object({}) do |(key, nested_value), result|
          result[deep_dup(key)] = deep_dup(nested_value)
        end
      when Array
        value.map { |element| deep_dup(element) }
      else
        value
      end
    end

    # Recursively freeze a configuration tree. OPT_OUT is left untouched so
    # the shared singleton keeps its identity and remains usable across
    # configs. Returns the frozen value.
    def deep_freeze(value)
      return value if value.nil? || value.equal?(OPT_OUT)

      case value
      when Hash
        value.each do |key, nested_value|
          deep_freeze(key)
          deep_freeze(nested_value)
        end
        value.freeze
      when Array
        value.each { |element| deep_freeze(element) }
        value.freeze
      else
        value.freeze
      end
    end

    # True when every nested Hash and Array is frozen. Used to assert that a
    # registered configuration is fully immutable, not merely frozen at its
    # top level. Objects that own an explicit deep_frozen? predicate (e.g. CSP
    # configs wrapping a private directive store) delegate to it. OPT_OUT is
    # considered immutable.
    def deep_frozen?(value)
      return true if value.nil? || value.equal?(OPT_OUT)
      return value.deep_frozen? if value.respond_to?(:deep_frozen?)

      case value
      when Hash
        value.frozen? && value.all? { |key, nested_value| deep_frozen?(key) && deep_frozen?(nested_value) }
      when Array
        value.frozen? && value.all? { |element| deep_frozen?(element) }
      else
        value.frozen?
      end
    end
  end
end
