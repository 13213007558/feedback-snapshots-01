# frozen_string_literal: true

module Liquid
  # FilterVerification is the confirmed set of filters a template was
  # verified against. It is a snapshot: filters added at render time do not
  # silently extend it, the template has to be verified again instead.
  class FilterVerification
    attr_reader :filter_names

    def initialize(filter_names)
      @filter_names = filter_names.sort.freeze
    end

    def matches?(other_names)
      @filter_names == other_names.sort
    end
  end

  # FilterVerifier confirms, before any output is produced, that every filter
  # a template relies on is actually invokable. This is an opt-in strict
  # integration for templates that depend on sanitizing filters: a typo'd
  # filter name or a filter plugin that failed to load must not result in the
  # raw value being output as-is.
  #
  # The verifier walks the parsed template and checks filters used in plain
  # variables, capture blocks, conditional branches, and statically known
  # partials. Only public filter methods count, a private method that happens
  # to share a name is not a usable filter.
  #
  # Content that cannot be proven safe from the main template alone is an
  # explicit boundary and raises UnverifiableContent:
  # * partials loaded under a dynamic (non-literal) name
  # * extension tags the verifier cannot audit
  class FilterVerifier
    VERIFIABLE_TAG_CLASSES = Tags::STANDARD_TAGS.values.to_set.freeze

    def self.verify!(template, filters: [])
      new(template, filters).verify!
    end

    def initialize(template, extra_filters)
      @template          = template
      @environment       = template.environment
      @strainer_class    = build_strainer_class(extra_filters)
      @verified_partials = {}
    end

    def verify!
      walk(@template.root, @template.name) if @template.root
      FilterVerification.new(@strainer_class.filter_method_names)
    end

    private

    def build_strainer_class(extra_filters)
      base = @environment.strainer_template
      return base if extra_filters.empty?

      klass = Class.new(base)
      extra_filters.each { |mod| klass.add_filter(mod) }
      klass
    end

    def walk(node, template_name)
      check_node(node, template_name)
      ParseTreeVisitor.for(node).each_child do |child|
        walk(child, template_name)
      end
    end

    def check_node(node, template_name)
      case node
      when Variable
        verify_variable(node, template_name)
      when Render, Include
        verify_partial(node, template_name)
      when Tag
        unless VERIFIABLE_TAG_CLASSES.include?(node.class)
          raise_unverifiable("tag #{node.tag_name.inspect} cannot be audited", template_name, node.line_number)
        end
      end
    end

    def verify_variable(variable, template_name)
      variable.filters.each do |filter|
        filter_name = filter[0]
        next if @strainer_class.invokable?(filter_name)

        raise_undefined_filter(filter_name, template_name, variable.line_number)
      end
    end

    def verify_partial(node, template_name)
      partial_name = node.template_name_expr
      unless partial_name.is_a?(String)
        raise_unverifiable("partial is loaded dynamically and cannot be audited", template_name, node.line_number)
      end
      return if @verified_partials.key?(partial_name)

      @verified_partials[partial_name] = true
      source  = @environment.file_system.read_template_file(partial_name)
      partial = parse_partial(partial_name, source)
      walk(partial.root, partial_name)
    end

    def parse_partial(partial_name, source)
      parse_context = ParseContext.new(environment: @environment)
      parse_context.partial = true
      partial = Template.new(environment: @environment)
      partial.parse(source, parse_context)
      partial.name = partial_name
      partial
    rescue Liquid::Error => e
      e.template_name ||= partial_name
      raise
    end

    # Error messages name the template and the filter, never the markup or
    # the value that was supposed to be sanitized.
    def raise_undefined_filter(filter_name, template_name, line_number)
      message = +"undefined filter #{filter_name}"
      message << " in template #{template_name.inspect}" if template_name && line_number.nil?
      error = UndefinedFilter.new(message)
      error.template_name = template_name
      error.line_number   = line_number
      raise error
    end

    def raise_unverifiable(reason, template_name, line_number)
      error = UnverifiableContent.new("cannot verify template filters: #{reason}")
      error.template_name = template_name
      error.line_number   = line_number
      raise error
    end
  end
end
