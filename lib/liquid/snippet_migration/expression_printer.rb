# frozen_string_literal: true

module Liquid
  module SnippetMigration
    # Turns parsed expressions back into valid Liquid markup for suggested
    # arguments. It is only used for reporting; no source file is edited.
    module ExpressionPrinter
      module_function

      def print(expression)
        case expression
        when Liquid::VariableLookup
          print_lookup(expression)
        when Liquid::RangeLookup
          "(#{print(expression.start_obj)}..#{print(expression.end_obj)})"
        when String
          expression.inspect
        when NilClass
          'nil'
        else
          expression.inspect
        end
      end

      def dynamic?(expression)
        case expression
        when Liquid::VariableLookup
          return true if expression.name.is_a?(Liquid::VariableLookup)

          expression.lookups.any? do |lookup|
            lookup.is_a?(Liquid::VariableLookup)
          end
        when Liquid::RangeLookup
          dynamic?(expression.start_obj) || dynamic?(expression.end_obj)
        else
          false
        end
      end

      def print_lookup(lookup)
        root = if lookup.name.is_a?(Liquid::VariableLookup)
          "[#{print(lookup.name)}]"
        else
          lookup.name.to_s
        end

        lookup.lookups.inject(root) do |markup, key|
          if key.is_a?(Liquid::VariableLookup)
            "#{markup}[#{print(key)}]"
          else
            "#{markup}.#{key}"
          end
        end
      end
    end
  end
end
