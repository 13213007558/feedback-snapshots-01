# frozen_string_literal: true

require 'liquid'

# Grammar-driven differential harness for Liquid's loose parsers vs. :strict2.
#
# The oracle is a pair of side-effect-free extension probes:
#   * a tag that records its name and markup, then renders nothing
#   * filters that record their name and argument shape, then return their input
#
# Every observation is the ordered list of extension callbacks that actually ran.
# Text inside {% raw %} / {% comment %} is never a callback, so literal probe-looking
# text there can never be mistaken for execution capability.
module Strict2Differential
  SEED = 20261114
  MODES = [:lax, :warn, :strict, :strict2].freeze
  PROBE_TAG = 'diff_tag'
  PROBE_FILTERS = %w[diff_f1 diff_f2 diff_f3].freeze
  PARTIALS = {
    'sn' => "{% diff_tag in_partial %}x={{ x | diff_f1 }}q={{ q | diff_f2 }}",
  }.freeze

  class Recorder
    attr_reader :entries

    def initialize
      @entries = []
    end

    def record(entry)
      @entries << entry
      entry
    end

    def snapshot
      @entries.dup.freeze
    end
  end

  class CountingTag < Liquid::Tag
    def render(context)
      context.registers[:diff_recorder].record("tag:#{@tag_name}(#{@markup.strip})")
      +''
    end
  end

  module CountingFilters
    PROBE_FILTERS.each do |filter_name|
      define_method(filter_name) do |input, *args, **kwargs|
        @context.registers[:diff_recorder].record(
          "filter:#{filter_name}(#{argument_shape(args, kwargs)})",
        )
        input
      end
    end

    private

    def argument_shape(args, kwargs)
      parts = args.map { |arg| value_shape(arg) }
      parts << "kw=#{kwargs.keys.map(&:to_s).sort.join('+')}" unless kwargs.empty?
      parts.join(',')
    end

    def value_shape(value)
      case value
      when Hash
        "hash=#{value.sort_by { |key, _| key.to_s }.inspect}"
      when String
        "str=#{value.inspect}"
      when nil
        'nil'
      else
        "#{value.class.name.downcase}=#{value.inspect}"
      end
    end
  end

  class CountingFileSystem
    def initialize(partials, recorder)
      @partials = partials
      @recorder = recorder
    end

    def read_template_file(name)
      @recorder.record("read:#{name}")
      @partials.fetch(name) { raise Liquid::FileSystemError, "No such template '#{name}'" }
    end
  end

  Observation = Struct.new(
    :mode, :status, :output, :callbacks, :warnings, :errors, :message,
    keyword_init: true,
  ) do
    def parse_accepted?
      status != :rejected
    end

    def accepted?
      status == :accepted
    end

    def rejected?
      status == :rejected
    end
  end

  Case = Struct.new(:id, :axis, :template, :partials, :notes, keyword_init: true)

  Result = Struct.new(:case, :observations, :category, keyword_init: true) do
    def [](mode)
      observations.fetch(mode)
    end

    def lax
      self[:lax]
    end

    def warn
      self[:warn]
    end

    def strict
      self[:strict]
    end

    def strict2
      self[:strict2]
    end
  end

  class << self
    def build_environment(recorder, partials)
      file_system = CountingFileSystem.new(partials, recorder)
      Liquid::Environment.build(file_system: file_system) do |environment|
        environment.register_tag(PROBE_TAG, CountingTag)
        environment.register_filter(CountingFilters)
      end
    end

    def assigns
      { 'p' => 'PV', 'q' => 'QV', 'arr' => [1, 2], 'h' => { 'x' => 'XV' } }
    end

    def observe(template, mode, partials: PARTIALS)
      recorder = Recorder.new
      environment = build_environment(recorder, partials)

      begin
        parsed = Liquid::Template.parse(
          template,
          error_mode: mode,
          environment: environment,
          line_numbers: true,
        )
      rescue Liquid::SyntaxError => error
        return Observation.new(
          mode: mode, status: :rejected, output: nil, callbacks: recorder.snapshot,
          warnings: [], errors: [], message: error.message,
        )
      end

      parse_warnings = parsed.warnings.map { |warning| "#{warning.class.name}: #{warning.message}" }
      begin
        output = parsed.render(assigns, registers: { diff_recorder: recorder })
        Observation.new(
          mode: mode, status: :accepted, output: output, callbacks: recorder.snapshot,
          warnings: parse_warnings,
          errors: parsed.errors.map { |error| "#{error.class.name}: #{error.message}" },
          message: nil,
        )
      rescue StandardError => error
        Observation.new(
          mode: mode, status: :render_error, output: nil, callbacks: recorder.snapshot,
          warnings: parse_warnings, errors: [], message: "#{error.class.name}: #{error.message}",
        )
      end
    end

    def analyze(case_or_options)
      case_object = case_or_options.is_a?(Case) ? case_or_options : Case.new(**case_or_options)
      observations = MODES.to_h do |mode|
        [mode, observe(case_object.template, mode, partials: case_object.partials || PARTIALS)]
      end
      Result.new(case: case_object, observations: observations, category: classify(observations))
    end

    def analyze_all(cases)
      cases.map { |case_object| analyze(case_object) }
    end

    # Categories describe the relationship between the loose parser (lax, the
    # behaviour existing templates rely on) and the strict2 target.
    #
    #   :equivalent     strict2 accepts and executes exactly what lax executes
    #   :output_change  same callbacks, but a different rendered value
    #   :execution_change both accept, but different tags/filters actually run
    #   :loose_only     strict2 rejects, lax still renders
    #   :strict2_only   strict2 accepts, lax rejects (new syntax)
    #   :rejected_both  neither parser accepts
    def classify(observations)
      lax = observations.fetch(:lax)
      strict2 = observations.fetch(:strict2)

      if strict2.parse_accepted?
        return :strict2_only unless lax.parse_accepted?
        return :execution_change if lax.callbacks != strict2.callbacks
        return :output_change if lax.status != strict2.status || lax.output != strict2.output

        :equivalent
      else
        return :rejected_both unless lax.parse_accepted?

        :loose_only
      end
    end

    # Warn is a fallback, not a gate: when strict2 rejects, warn records a
    # warning and then parses with lax. This reports whether that fallback
    # executes the same callbacks as lax.
    def warn_relation(result)
      lax = result.lax
      warn = result.warn
      return :not_applicable unless lax.parse_accepted?
      return :warn_rejected if warn.rejected?
      return :fallback_differs if warn.status != lax.status
      return :fallback_differs if warn.output != lax.output
      return :fallback_differs if warn.callbacks != lax.callbacks

      :fallback_matches_lax
    end

    def execution_fingerprint(observation)
      return 'rejected' if observation.rejected?

      observation.callbacks.join(' > ')
    end

    def render_fingerprint(observation)
      return 'rejected' if observation.rejected?

      "#{observation.status}|#{observation.output.inspect}"
    end

    def full_fingerprint(observation)
      "#{render_fingerprint(observation)}|#{execution_fingerprint(observation)}"
    end

    def describe(result)
      subject = "#{result.case.id} [#{result.category}] #{result.case.template.inspect}"
      lines = [subject]
      MODES.each do |mode|
        observation = result[mode]
        line = if observation.rejected?
          "  #{mode}: rejected: #{observation.message.to_s.split('(line').first.strip}"
        else
          "  #{mode}: #{observation.status} out=#{observation.output.inspect} " \
            "calls=#{observation.callbacks.inspect} warn=#{observation.warnings.length}"
        end
        lines << line
      end
      lines.join("\n")
    end
  end
end
