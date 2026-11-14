# frozen_string_literal: true

module Liquid
  module SnippetMigration
    # Serializable audit report. "safe" means the call had no construct the
    # analyzer could not resolve; it is not a claim that render is a sandbox.
    class Report
      attr_reader :calls, :manual
      attr_accessor :globals, :private_names

      def initialize
        @calls = []
        @manual = []
        @globals = []
        @private_names = []
      end

      def add_call(call)
        @calls << call
      end

      def add_manual(kind:, template:, line:, detail:, snippet: nil)
        finding = {
          'kind' => kind,
          'template' => template,
          'line' => line,
          'detail' => detail,
          'status' => 'manual_review',
        }
        finding['snippet'] = snippet if snippet
        return if @manual.any? { |existing| existing == finding }

        @manual << finding
      end

      def to_h
        {
          'isolation' => {
            'render_scope' => 'isolated subcontext',
            'parent_local_variables_hidden' => true,
            'global_data_still_visible' => globals.map do |name|
              {
                'name' => name,
                'visible_after_render' => true,
                'detail' => 'Global/static environment data remains visible inside render.',
              }
            end,
            'private_names_withheld_from_render' => private_names,
            'sandbox' => false,
            'note' => 'render isolates the parent variable scope; it is not a complete security sandbox.',
          },
          'calls' => calls,
          'manual_review' => manual,
        }
      end
    end
  end
end
