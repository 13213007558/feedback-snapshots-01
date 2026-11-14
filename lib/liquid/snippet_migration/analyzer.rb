# frozen_string_literal: true

require_relative 'expression_printer'

module Liquid
  module SnippetMigration
    # Analyzes statically named {% include %} calls. The analyzer is read-only:
    # it reports what a {% render %} call would need and marks everything it
    # cannot prove as manual review.
    class Analyzer
      SnippetRead = Struct.new(:name, :template, :line, :resolved_locally, keyword_init: true)
      LocalDefinition = Struct.new(:name, :kind, :line, keyword_init: true)

      Scope = Struct.new(:locals, :loop_vars, :parent, keyword_init: true) do
        def defines?(name)
          locals.include?(name) || loop_vars.include?(name) || (parent && parent.defines?(name))
        end

        def child(locals: [], loop_vars: [])
          Scope.new(locals: Array(locals), loop_vars: Array(loop_vars), parent: self)
        end
      end

      SnippetAnalysis = Struct.new(:reads, :definitions, :dynamic_reasons, :nested_include, keyword_init: true) do
        def dynamic?
          dynamic_reasons.any? || nested_include
        end
      end

      def initialize(templates:, snippets:, caller_bindings:, globals:, private_names:, environment:, error_mode:)
        @repository = Repository.new(snippets)
        @caller_bindings = normalize_bindings(caller_bindings)
        @globals = Array(globals).map(&:to_s).uniq
        @private_names = Array(private_names).map(&:to_s).uniq
        @environment = environment
        @error_mode = error_mode
        @standard_tags = Liquid::Tags::STANDARD_TAGS
        @report = Report.new
        @report.globals = @globals
        @report.private_names = @private_names
        @templates = templates
        @analysis = nil
        @template_reads = Hash.new { |h, k| h[k] = [] }
        @index_seq = 0
        @index_seq_by_node = {}
        @visit_seq = 0
        @include_seq = nil
      end

      def analyze
        parsed = {}
        @templates.each do |name, source|
          parsed[name] = parse(name, source)
        rescue Liquid::SyntaxError => e
          @report.add_manual(kind: 'syntax_error', template: name, line: e.line_number, detail: e.message)
        end

        # Reads are indexed first so a caller read after an include can be
        # detected even though include bodies are analyzed separately.
        @indexing = true
        parsed.each do |name, template|
          visit_body(name, template.root.nodelist, Scope.new(locals: [], loop_vars: [], parent: nil))
        end

        @indexing = false
        parsed.each do |name, template|
          visit_body(name, template.root.nodelist, Scope.new(locals: [], loop_vars: [], parent: nil))
        end
        @report
      end

      private

      def normalize_bindings(value)
        case value
        when Hash
          value.each_with_object({}) { |(key, entry), out| out[key.to_s] = entry }
        when Array
          value.each_with_object({}) { |key, out| out[key.to_s] = nil }
        when nil
          {}
        else
          { value.to_s => nil }
        end
      end

      def parse(name, source)
        template = Liquid::Template.parse(
          source,
          line_numbers: true,
          error_mode: @error_mode,
          environment: @environment,
        )
        template.name = name
        template
      end

      def visit_body(template_name, body, scope)
        nodes = body.is_a?(Liquid::BlockBody) ? body.nodelist : Array(body)
        nodes.each { |node| visit_node(template_name, node, scope) }
      end

      def visit_node(template_name, node, scope)
        if @indexing
          @index_seq += 1
          @index_seq_by_node[node.object_id] = @index_seq
        else
          @visit_seq += 1
        end
        case node
        when String
          nil
        when Liquid::Variable
          record_variable(template_name, node, node, scope)
        when Liquid::Assign
          record_variable(template_name, node, node.from, scope)
          define_local(node.to, 'assign', node, scope)
        when Liquid::Capture
          visit_body(template_name, node.nodelist, scope)
          define_local(node.to, 'capture', node, scope)
        when Liquid::Increment, Liquid::Decrement
          define_local(node.variable_name, node.tag_name, node, scope)
        when Liquid::For
          record_lookup(template_name, node, node.collection_name, scope)
          record_lookup(template_name, node, node.limit, scope)
          record_lookup(template_name, node, node.from, scope)
          child = scope.child(loop_vars: [node.variable_name, 'forloop'])
          define_local(node.variable_name, 'for', node, child)
          define_local('forloop', 'for', node, child)
          visit_body(template_name, node.nodelist, child)
        when Liquid::TableRow
          record_lookup(template_name, node, node.collection_name, scope)
          node.attributes.each_value { |expr| record_lookup(template_name, node, expr, scope) }
          child = scope.child(loop_vars: [node.variable_name, 'tablerowloop'])
          define_local(node.variable_name, 'tablerow', node, child)
          define_local('tablerowloop', 'tablerow', node, child)
          visit_body(template_name, node.nodelist, child)
        when Liquid::If, Liquid::Unless, Liquid::Case
          visit_condition_blocks(template_name, node, scope)
        when Liquid::Cycle
          record_lookup(template_name, node, node.instance_variable_get(:@name), scope) if node.named?
          node.variables.each { |expr| record_lookup(template_name, node, expr, scope) }
        when Liquid::Echo
          record_variable(template_name, node, node.variable, scope)
        when Liquid::Include
          visit_include(template_name, node, scope)
        when Liquid::Render
          visit_render(template_name, node, scope)
        when Liquid::Ifchanged
          visit_body(template_name, node.nodelist, scope)
        else
          if custom_tag?(node)
            mark_dynamic(template_name, node, "custom tag #{node.tag_name.inspect} may read unknown data") unless @indexing
          elsif node.respond_to?(:nodelist)
            visit_body(template_name, node.nodelist, scope)
          end
        end
      end

      def visit_condition_blocks(template_name, node, scope)
        owner = node
        if node.is_a?(Liquid::Case)
          record_lookup(template_name, node, node.left, scope)
        end
        node.blocks.each do |condition|
          visit_condition(template_name, condition, scope, owner)
          visit_body(template_name, condition.attachment, scope) if condition.respond_to?(:attachment)
        end
      end

      def visit_condition(template_name, condition, scope, owner)
        return unless condition.respond_to?(:left)

        record_lookup(template_name, owner, condition.left, scope, line_node: condition)
        record_lookup(template_name, owner, condition.right, scope, line_node: condition)
        child = condition.child_condition if condition.respond_to?(:child_condition)
        visit_condition(template_name, child, scope, owner) if child
      end

      def record_variable(template_name, node, variable, scope)
        return unless variable.is_a?(Liquid::Variable)

        record_lookup(template_name, node, variable.name, scope)
        variable.filters.each do |_filter_name, args, kwargs|
          Array(args).each { |arg| record_lookup(template_name, node, arg, scope) }
          (kwargs || {}).each_value { |arg| record_lookup(template_name, node, arg, scope) }
        end
      end

      def record_lookup(template_name, node, expression, scope, line_node: nil)
        case expression
        when Liquid::VariableLookup
          analyze_lookup(template_name, node, expression, scope, line_node: line_node)
        when Liquid::RangeLookup
          record_lookup(template_name, node, expression.start_obj, scope, line_node: line_node)
          record_lookup(template_name, node, expression.end_obj, scope, line_node: line_node)
        end
      end

      def analyze_lookup(template_name, node, lookup, scope, line_node: nil)
        if lookup.name.is_a?(Liquid::VariableLookup)
          mark_dynamic(template_name, node, 'dynamic bracket root cannot be resolved statically')
          return
        end

        name = lookup.name.to_s
        return if name.empty? || literal?(name)

        mark_dynamic(template_name, node, 'self access cannot be resolved statically') if name == 'self'
        lookup.lookups.each do |key|
          next unless key.is_a?(Liquid::VariableLookup)

          mark_dynamic(template_name, node, 'dynamic bracket key cannot be resolved statically')
        end

        line = if line_node && line_node.respond_to?(:line_number)
          line_node.line_number
        elsif node.respond_to?(:line_number)
          node.line_number
        end

        @template_reads[template_name] << [name, @index_seq] if @indexing

        return unless @analysis

        @analysis.reads << SnippetRead.new(
          name: name,
          template: template_name,
          line: line,
          resolved_locally: scope.defines?(name),
        )
      end

      def literal?(name)
        name.match?(/\A-?\d+(?:\.\d+)?\z/) || %w(true false nil null empty blank).include?(name)
      end

      def define_local(name, kind, node, scope)
        return unless name

        scope.locals << name.to_s unless scope.locals.include?(name.to_s)
        return unless @analysis

        @analysis.definitions << LocalDefinition.new(
          name: name.to_s,
          kind: kind,
          line: node.respond_to?(:line_number) ? node.line_number : nil,
        )
      end

      def visit_include(template_name, node, scope)
        if @indexing
          visit_commands(template_name, node, scope)
          return
        end
        if @analysis
          @analysis.nested_include = true
          @analysis.dynamic_reasons << "nested include at line #{node.line_number} cannot stay inside render"
          return
        end

        @include_seq = @index_seq_by_node[node.object_id]
        template = node.template_name_expr
        unless template.is_a?(String)
          add_manual(template_name, node, 'dynamic include template name cannot be migrated statically')
          visit_commands(template_name, node, scope)
          return
        end

        source = @repository.read(template)
        unless source
          add_manual(template_name, node, "snippet #{template.inspect} was not found")
          visit_commands(template_name, node, scope)
          return
        end

        @analysis = SnippetAnalysis.new(
          reads: [],
          definitions: [],
          dynamic_reasons: [],
          nested_include: false,
        )
        begin
          visit_body(template, parse(template, source.body).root.nodelist, snippet_scope)
        rescue Liquid::SyntaxError => e
          @analysis.dynamic_reasons << "snippet has a syntax error: #{e.message}"
        ensure
          analysis = @analysis
          @analysis = nil
        end

        if analysis.dynamic_reasons.any?
          analysis.dynamic_reasons.each do |reason|
            add_manual(template_name, node, reason, snippet: template)
          end
        end
        if analysis.nested_include
          add_manual(
            template_name,
            node,
            'snippet contains include, which render disables; nested call needs manual migration',
            snippet: template,
          )
        end

        explicit, implicit = include_bindings(node)
        call = build_call(template_name, node, template, source, scope, analysis, explicit, implicit)
        @report.add_call(call)
      end

      def visit_render(template_name, node, scope)
        record_lookup(template_name, node, node.variable_name_expr, scope) if node.variable_name_expr
        node.attributes.each_value { |expr| record_lookup(template_name, node, expr, scope) }

        return if @indexing
        return unless @analysis

        @analysis.dynamic_reasons << "nested render at line #{node.line_number} is not analyzed"
      end

      def visit_commands(template_name, node, scope)
        record_lookup(template_name, node, node.variable_name_expr, scope) if node.variable_name_expr
        node.attributes.each_value { |expr| record_lookup(template_name, node, expr, scope) }
      end

      def snippet_scope
        Scope.new(locals: [], loop_vars: [], parent: nil)
      end

      def include_alias(node)
        node.instance_variable_get(:@alias_name)
      end

      def keyword_name(template)
        template.split('/').last
      end

      # include with/for binds the alias (or snippet name) to the evaluated
      # expression. A bare include, including `as name`, resolves that name from
      # the caller scope instead.
      def include_bindings(node)
        explicit = {}
        if node.variable_name_expr
          explicit[include_alias(node) || keyword_name(node.template_name_expr)] = node.variable_name_expr
        end
        node.attributes.each { |name, expr| explicit[name] = expr }

        implicit = {}
        unless node.variable_name_expr
          binding = include_alias(node) || keyword_name(node.template_name_expr)
          source_name = keyword_name(node.template_name_expr)
          implicit[binding] = Liquid::Expression.parse(source_name)
        end
        [explicit, implicit]
      end

      def build_call(template_name, node, template, source, caller_scope, analysis, provided, implicit)
        dependency_names = analysis.reads.reject(&:resolved_locally).map(&:name).uniq
        dependencies = dependency_names.sort.map do |name|
          dependency_entry(name, analysis, provided, implicit, caller_scope, node, template_name)
        end

        include_seq = @include_seq

        local_shadowing = analysis.definitions.map do |definition|
          shadows = shadowed_value(definition.name, provided, caller_scope, node)
          {
            'name' => definition.name,
            'kind' => definition.kind,
            'line' => definition.line,
            'shadows' => shadows,
          }
        end

        gaps = dependencies.select { |dependency| !dependency['render_safe'] }
        gaps.each do |dependency|
          add_manual(template_name, node, dependency['manual_reason'], snippet: template)
        end
        loop_kinds = %w(for tablerow forloop tablerowloop)
        assigned = analysis.definitions.reject { |definition| loop_kinds.include?(definition.kind) }
        side_effects = assigned.map do |definition|
          {
            'name' => definition.name,
            'kind' => definition.kind,
            'line' => definition.line,
            'include_leaks_to_caller' => true,
            'render_isolated' => true,
          }
        end
        side_effects.each do |effect|
          effect['caller_reads_after_include'] = caller_reads_after?(template_name, effect['name'], include_seq)
        end
        leaking_side_effects = side_effects.select { |effect| effect['caller_reads_after_include'] }
        leaking_side_effects.each do |effect|
          add_manual(
            template_name,
            node,
            "snippet assigns #{effect['name'].inspect}, which the caller reads after this include; " \
              'render would isolate that assignment and change output',
            snippet: template,
          )
        end

        suggested = if analysis.dynamic? || gaps.any? || leaking_side_effects.any?
          nil
        else
          suggested_render(node, template, dependencies)
        end

        caller_can_provide = dependencies.select { |dependency| dependency['caller_can_provide'] }.map do |dependency|
          entry = {
            'name' => dependency['name'],
            'expression' => dependency['caller_can_provide'],
            'resolution' => dependency['resolution'],
          }
          entry['note'] = dependency['caller_can_provide_note'] if dependency['caller_can_provide_note']
          entry
        end

        {
          'caller_template' => template_name,
          'line' => node.line_number,
          'snippet' => template,
          'snippet_path' => source.path,
          'status' => (analysis.dynamic? || gaps.any? || leaking_side_effects.any?) ? 'manual_review' : 'static',
          'include_provided' => provided.map do |name, expr|
            { 'name' => name, 'expression' => ExpressionPrinter.print(expr), 'kind' => 'explicit' }
          end,
          'include_implicit_bindings' => implicit.map do |name, expr|
            { 'name' => name, 'source_expression' => ExpressionPrinter.print(expr), 'kind' => 'implicit_caller_scope' }
          end,
          'dependencies' => dependencies,
          'local_shadowing' => local_shadowing,
          'caller_can_provide' => caller_can_provide,
          'include_side_effects' => side_effects,
          'suggested_render' => suggested,
        }
      end

      def caller_reads_after?(template_name, name, include_seq)
        return false unless include_seq

        @template_reads[template_name].any? do |read_name, read_seq|
          read_name == name && read_seq > include_seq
        end
      end

      def suggested_render(node, template, dependencies)
        added = dependencies.each_with_object({}) do |dependency, out|
          next unless dependency['render_argument_needed']
          next unless dependency['caller_can_provide']

          out[dependency['name']] = dependency['caller_can_provide']
        end

        markup = +"{% render #{template.inspect}"
        if node.variable_name_expr
          keyword = node.for_loop? ? 'for' : 'with'
          markup << " #{keyword} #{ExpressionPrinter.print(node.variable_name_expr)}"
          alias_name = include_alias(node)
          markup << " as #{alias_name}" if alias_name
        end

        node.attributes.each do |key, expression|
          markup << ", #{key}: #{ExpressionPrinter.print(expression)}"
        end
        added.each do |key, expression|
          next if node.attributes.key?(key)

          markup << ", #{key}: #{expression}"
        end
        markup << ' %}'
      end

      def dependency_entry(name, analysis, provided, implicit, caller_scope, node, template_name)
        read_sites = analysis.reads.select { |read| read.name == name }.map do |read|
          { 'template' => read.template, 'line' => read.line }
        end.uniq
        include_argument = provided.key?(name)
        implicit_include = implicit.key?(name)
        binding = caller_binding(name)
        caller_defined = !!caller_scope.defines?(name)
        global = @globals.include?(name)
        private = @private_names.include?(name)

        entry = {
          'name' => name,
          'include_argument' => include_argument,
          'implicit_include_binding' => implicit_include,
          'caller_binding' => binding,
          'caller_local_shadow' => caller_defined,
          'global_visible' => global,
          'private_parent_value' => private,
          'read_sites' => read_sites,
        }

        if private
          entry.merge!(
            'render_argument_needed' => false,
            'render_safe' => false,
            'resolution' => 'private_parent_value',
            'manual_reason' => "snippet reads private parent value #{name.inspect}; " \
              'the analyzer will not suggest passing it to render',
          )
        elsif include_argument
          entry.merge!(
            'render_argument_needed' => false,
            'render_safe' => true,
            'resolution' => 'explicit_include_argument',
            'caller_can_provide' => ExpressionPrinter.print(provided[name]),
          )
        elsif binding
          entry.merge!(
            'render_argument_needed' => true,
            'render_safe' => true,
            'resolution' => 'caller_binding',
            'caller_can_provide' => binding,
          )
        elsif implicit_include
          entry.merge!(
            'render_argument_needed' => true,
            'render_safe' => true,
            'resolution' => 'implicit_include_binding',
            'caller_can_provide' => ExpressionPrinter.print(implicit[name]),
          )
        elsif caller_defined
          entry.merge!(
            'render_argument_needed' => true,
            'render_safe' => true,
            'resolution' => 'caller_local_scope',
            'caller_can_provide' => name,
          )
        elsif global
          entry.merge!(
            'render_argument_needed' => false,
            'render_safe' => true,
            'resolution' => 'global_environment_still_visible',
            'caller_can_provide' => name,
            'caller_can_provide_note' => 'optional: render still sees this global without an argument',
          )
        else
          entry.merge!(
            'render_argument_needed' => true,
            'render_safe' => false,
            'resolution' => 'unknown',
            'manual_reason' => "dependency #{name.inspect} is not an include argument, caller binding, " \
              'caller local, declared global, or private value; cannot prove how to provide it',
          )
        end
        entry
      end

      def caller_binding(name)
        return nil unless @caller_bindings.key?(name)

        value = @caller_bindings[name]
        case value
        when Hash
          value['expression'] || value[:expression] || name
        when String
          value
        else
          name
        end
      end

      def shadowed_value(name, provided, caller_scope, node)
        values = []
        values << 'include_argument' if provided.key?(name)
        values << 'caller_binding' if caller_binding(name)
        values << 'caller_local_scope' if caller_scope.defines?(name)
        values << 'global_environment' if @globals.include?(name)
        values << 'private_parent_value' if @private_names.include?(name)
        values
      end

      def mark_dynamic(template_name, node, reason)
        return if @indexing

        if @analysis
          @analysis.dynamic_reasons << reason unless @analysis.dynamic_reasons.include?(reason)
        else
          add_manual(template_name, node, reason)
        end
      end

      def add_manual(template_name, node, detail, snippet: nil)
        @report.add_manual(
          kind: 'dynamic_execution',
          template: template_name,
          line: node.respond_to?(:line_number) ? node.line_number : nil,
          detail: detail,
          snippet: snippet,
        )
      end

      def custom_tag?(node)
        return false unless node.respond_to?(:tag_name)

        @standard_tags[node.tag_name] != node.class
      end
    end
  end
end
