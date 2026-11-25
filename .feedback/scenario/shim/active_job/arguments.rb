# frozen_string_literal: true

# Local-only stand-in for ActiveJob::Arguments, which is not available in the
# locked .feedback bundle. It implements the serialize/deserialize contract the
# CurrentAttributes middleware relies on for the scalar/hash values in the
# scenario. The production code path still uses the real Active Job gem.
module ActiveJob
  module Arguments
    SYMBOL_KEY = "_aj_symbol_keys"
    SYMBOL_VAL = "_aj_symbol"

    class << self
      def serialize(value)
        case value
        when Hash
          symbol_keys = value.each_key.select { |key| key.is_a?(Symbol) }.map(&:to_s)
          result = value.transform_keys(&:to_s).transform_values { |v| serialize(v) }
          result[SYMBOL_KEY] = symbol_keys unless symbol_keys.empty?
          result
        when Symbol
          {SYMBOL_VAL => value.to_s}
        when Array
          value.map { |item| serialize(item) }
        else
          value
        end
      end

      def deserialize(value)
        case value
        when Hash
          if value.key?(SYMBOL_VAL)
            value[SYMBOL_VAL].to_sym
          else
            symbol_keys = value.fetch(SYMBOL_KEY, [])
            value.except(SYMBOL_KEY).each_with_object({}) do |(key, item), hash|
              hash[symbol_keys.include?(key) ? key.to_sym : key] = deserialize(item)
            end
          end
        when Array
          value.map { |item| deserialize(item) }
        else
          value
        end
      end
    end
  end
end
