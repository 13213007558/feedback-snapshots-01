# frozen_string_literal: true

require_relative 'strict2_differential_corpus'

# Renders a migration-facing report from the differential corpus.
#
# The report answers one question for a template owner: when I switch to
# strict2, does this construct keep working, refuse to parse, or keep parsing
# while changing what actually executes? It never relaxes strict2 to make a
# template pass; every row is an action for the template.
module Strict2DifferentialReport
  CATEGORY_LABELS = {
    equivalent: 'KEEP AS IS',
    output_change: 'REVIEW OUTPUT',
    execution_change: 'RENAME / RESTRUCTURE',
    loose_only: 'REWRITE BEFORE MIGRATING',
    strict2_only: 'NEW SYNTAX',
    rejected_both: 'INVALID IN EVERY MODE',
  }.freeze

  CATEGORY_ORDER = [:execution_change, :output_change, :loose_only, :strict2_only, :equivalent, :rejected_both].freeze

  AXIS_LABELS = {
    variable: 'Variable filter chains',
    render: 'render parameters',
    liquid: 'liquid multi-statement tags',
    separator: 'Delimiters, quotes, trailing tokens',
    block_end: 'Block end markers',
    protected_region: 'raw / comment protected regions',
    control: 'Control-flow tags',
  }.freeze

  module_function

  def results
    @results ||= Strict2DifferentialCorpus.all.map do |entry|
      result = Strict2Differential.analyze(entry[:case])
      {
        entry: entry,
        result: result,
        category: result.category,
        expected_category: entry[:category],
        warn_relation: Strict2Differential.warn_relation(result),
        expected_warn_relation: entry[:warn_relation],
      }
    end
  end

  def summary
    counts = Hash.new(0)
    results.each { |row| counts[row[:category]] += 1 }
    counts
  end

  def axes
    results.group_by { |row| row[:entry][:case].axis }
  end

  def markdown
    lines = []
    lines << "# strict2 migration differential report"
    lines << ''
    lines << "Seed: `#{Strict2Differential::SEED}`  "
    lines << "Probe tag: `#{Strict2Differential::PROBE_TAG}`  "
    lines << "Probe filters: #{Strict2Differential::PROBE_FILTERS.map { |f| "`#{f}`" }.join(', ')}"
    lines << ''
    lines << 'Oracle: ordered list of probe callbacks that actually ran, plus rendered output.'
    lines << 'A callback list proves execution; literal `{% ... %}` text inside `raw`/`comment`'
    lines << 'does not, so those regions are counted as inert by construction.'
    lines << ''
    lines << '## Counts'
    lines << ''
    lines << '| Category | Meaning | Count |'
    lines << '| --- | --- | ---: |'
    CATEGORY_ORDER.each do |category|
      lines << "| `#{category}` | #{CATEGORY_LABELS.fetch(category)} | #{summary.fetch(category, 0)} |"
    end
    lines << ''
    lines << '## Rows'
    lines << ''
    CATEGORY_ORDER.each do |category|
      rows = results.select { |row| row[:category] == category }
      next if rows.empty?

      lines << "### #{CATEGORY_LABELS.fetch(category)} (`#{category}`)"
      lines << ''
      rows.each do |row|
        case_object = row[:entry][:case]
        lines << "- `#{case_object.id}` (#{AXIS_LABELS.fetch(case_object.axis)}): `#{case_object.template}`"
        lines << "  - #{case_object.notes}"
        if category != :equivalent
          lines << "  - lax: #{describe_execution(row[:result].lax)}"
          lines << "  - strict2: #{describe_execution(row[:result].strict2)}"
        end
        lines << "  - warn: #{row[:warn_relation].to_s.tr('_', ' ')}"
      end
      lines << ''
    end
    lines.join("\n")
  end

  def checklist_markdown
    lines = []
    lines << '# strict2 migration checklist'
    lines << ''
    lines << 'Generated from the grammar-driven differential corpus. Work top to bottom;'
    lines << 'each item names the template shape, why it stops being safe, and the rewrite.'
    lines << ''
    actionable = results.reject { |row| row[:category] == :equivalent || row[:category] == :rejected_both }
    grouped = actionable.group_by { |row| row[:entry][:case].axis }
    grouped.each do |axis, rows|
      lines << "## #{AXIS_LABELS.fetch(axis)}"
      lines << ''
      rows.each do |row|
        case_object = row[:entry][:case]
        lines << "- [ ] `#{case_object.id}` — #{case_object.notes}"
        lines << "  - Template: `#{case_object.template}`"
        lines << "  - #{CATEGORY_LABELS.fetch(row[:category])}: strict2 #{strict2_verdict(row[:result])}"
        lines << "  - Action: #{action_for(row)}"
      end
      lines << ''
    end
    lines << '## Warn-mode caveat'
    lines << ''
    lines << '`:warn` is a hybrid, not a gate: tags fall back from strict2, variables fall back'
    lines << 'from strict. A warning therefore does not prove the executed callbacks match lax;'
    lines << 'use the callback fingerprints in the report, not the warning count.'
    lines << ''
    lines << 'In particular, these corpus entries are rejected by strict2 yet produce **no**'
    lines << 'warning because warn falls back to strict for variables or to lax `when` parsing:'
    lines << ''
    warn_silent_strict2_rejections.each { |id| lines << "- `#{id}`" }
    lines << ''
    lines << 'Run `Template.parse(source, error_mode: :strict2)` in CI to catch these; a clean'
    lines << 'warn log will not.'
    lines.join("\n")
  end

  # strict2 rejects these, but warn does not emit a warning because warn uses
  # strict for variables and the lax `when` parser for case clauses. A clean
  # warning log therefore does NOT prove a template is strict2-ready.
  def warn_silent_strict2_rejections
    results.select do |row|
      row[:result].strict2.rejected? &&
        row[:result].warn.accepted? &&
        row[:result].warn.warnings.empty?
    end.map { |row| row[:entry][:case].id }
  end

  def describe_execution(observation)
    return "rejected (#{observation.message.to_s.split('(line').first.strip})" if observation.rejected?

    "out=#{observation.output.inspect} callbacks=#{observation.callbacks.inspect}"
  end

  def strict2_verdict(result)
    case result.category
    when :loose_only then 'rejects the template'
    when :strict2_only then 'accepts syntax lax rejects'
    when :execution_change then 'executes a different callback set'
    when :output_change then 'renders a different value'
    when :equivalent then 'behaves identically'
    else 'rejects the template too'
    end
  end

  CONTROL_ACTIONS = {
    'ctrl-if-filter' => 'Compute the value in an `assign` first, then test the variable.',
    'ctrl-if-two-filters' => 'Compute the filtered value in an `assign` first.',
    'ctrl-unless-filter' => 'Compute the value in an `assign` first, then test it with `unless`.',
    'ctrl-if-parens' => 'Remove the redundant parentheses around the comparison.',
    'ctrl-if-double-amp' => 'Replace `&&`/`||` with the keyword operators `and`/`or`.',
    'ctrl-if-extra-token' => 'Remove the trailing token; each comparison takes exactly two operands.',
    'ctrl-case-filter' => 'Compute the filtered value before the `case` and compare the variable.',
    'ctrl-case-extra' => 'Remove the trailing token after the `when` value.',
    'ctrl-for-unknown-attr' => 'Use only `limit` and `offset` attributes on `for`.',
    'ctrl-for-extra-dots' => 'Use the two-dot range `(a..b)`.',
    'ctrl-tablerow-unknown-attr' => 'Use only `cols`, `limit`, and `offset` attributes on `tablerow`.',
    'ctrl-cycle-extra' => 'Remove trailing tokens; separate cycle values with commas.',
    'ctrl-increment-extra' => 'Give `increment` a single bare identifier.',
    'ctrl-decrement-extra' => 'Give `decrement` a single bare identifier.',
    'ctrl-assign-dotted' => 'Assign to a single bare identifier, not a dotted or bracketed path.',
    'ctrl-assign-numeric' => 'Use an identifier that starts with a letter or underscore.',
    'ctrl-capture-quoted' => 'Name the capture with a bare identifier, not a quoted string.',
    'ctrl-echo-extra' => 'Remove the trailing token; `echo` takes one expression.',
    'ctrl-include-filter-arg' => 'Move the filter into an `assign` before `include`, or into the snippet.',
    'ctrl-include-double-comma' => 'Remove the empty argument slot.',
  }.freeze

  def control_action(id)
    CONTROL_ACTIONS.fetch(id, 'Rewrite using the strict2 grammar shown by the parse error.')
  end

  def action_for(row)
    case row[:category]
    when :loose_only
      case row[:entry][:case].axis
      when :liquid then 'Split statements onto separate lines; remove inline # comments and semicolons.'
      when :render then 'Use `, key: value` arguments only; move conditionals into the snippet.'
      when :variable then 'Use `| filter: arg1, arg2` with a name, commas, and no parenthesised arguments.'
      when :control then control_action(row[:entry][:case].id)
      when :protected_region then 'Keep probe-looking text but do not rely on nested terminators.'
      else 'Rewrite the construct using the strict2 grammar shown by the strict parser error.'
      end
    when :execution_change then 'Rename or restructure so both parsers call the same extensions.'
    when :output_change then 'Compare rendered output and update expected values.'
    when :strict2_only then 'Optional modernization; strict2-only syntax is safe to adopt last.'
    else 'Fix the template; it is invalid in every mode.'
    end
  end
end
