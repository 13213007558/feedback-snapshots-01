# frozen_string_literal: true

require 'liquid'
require_relative 'snippet_migration/repository'
require_relative 'snippet_migration/report'
require_relative 'snippet_migration/analyzer'

module Liquid
  # Read-only support for auditing {% include %} calls before moving snippets to
  # the isolated {% render %} tag. This module deliberately does not rewrite
  # templates: calls whose dependencies cannot be resolved statically are
  # reported for manual review.
  module SnippetMigration
    def self.analyze(
      templates:,
      snippets:,
      caller_bindings: {},
      globals: [],
      private_names: [],
      environment: Liquid::Environment.default,
      error_mode: :strict2
    )
      Analyzer.new(
        templates: templates,
        snippets: snippets,
        caller_bindings: caller_bindings,
        globals: globals,
        private_names: private_names,
        environment: environment,
        error_mode: error_mode,
      ).analyze
    end
  end
end
