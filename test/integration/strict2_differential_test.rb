# frozen_string_literal: true

require 'test_helper'
require_relative '../support/strict2_differential_report'

# Locks the grammar-driven differential corpus.
#
# These assertions are about the migration contract, not about individual
# implementation details: every corpus row has a declared relationship to
# :strict2, and switching the default error mode must not silently rewrite a
# template into a different set of executed tags/filters.
class Strict2DifferentialTest < Minitest::Test
  include Liquid

  SEED = Strict2Differential::SEED

  def fingerprint_rows
    Strict2DifferentialReport.results.map do |row|
      [row[:entry][:case].id, row[:category], row[:warn_relation]]
    end
  end

  def test_corpus_is_reproducible
    assert_equal(SEED, Strict2Differential::SEED)
    assert_operator(Strict2DifferentialReport.results.length, :>=, 100)
    assert_equal(fingerprint_rows, fingerprint_rows)

    # Re-observe a few entries from the corpus directly; independent runs must
    # produce identical execution fingerprints.
    sample = Strict2DifferentialCorpus.all.first(10)
    first = sample.map { |entry| Strict2Differential.full_fingerprint(Strict2Differential.analyze(entry[:case]).lax) }
    second = sample.map { |entry| Strict2Differential.full_fingerprint(Strict2Differential.analyze(entry[:case]).lax) }
    assert_equal(first, second)
  end

  def test_every_corpus_entry_matches_its_declared_category
    failures = Strict2DifferentialReport.results.reject do |row|
      row[:category] == row[:expected_category]
    end

    assert_empty(
      failures.map { |row| "#{row[:entry][:case].id}: expected #{row[:expected_category]}, got #{row[:category]}" },
    )
  end

  def test_every_corpus_entry_matches_its_declared_warn_relation
    failures = Strict2DifferentialReport.results.reject do |row|
      row[:warn_relation] == row[:expected_warn_relation]
    end

    assert_empty(
      failures.map do |row|
        "#{row[:entry][:case].id}: expected #{row[:expected_warn_relation]}, got #{row[:warn_relation]}"
      end,
    )
  end

  # `[p]` is the clearest case of "rejected by strict2 but still executed by lax":
  # the value is nil, but the filter callback still runs. A migration audit that
  # only compares rendered output would miss that the filter executed at all.
  def test_bare_bracket_is_rejected_by_strict2_but_still_runs_the_filter_in_lax
    result = Strict2Differential.analyze(
      id: 'bare-bracket',
      axis: :variable,
      template: '{{ [p] | diff_f1 }}',
    )

    assert(result.strict2.rejected?)
    assert(result.lax.accepted?)
    assert_equal(["filter:diff_f1()"], result.lax.callbacks)
    assert_equal('', result.lax.output)
  end

  # The security-relevant invariant: a template that strict2 accepts must not
  # execute a different set of extensions than lax accepted. If this fires,
  # widening strict2 acceptance silently changed execution semantics.
  def test_no_template_that_strict2_accepts_changes_executed_callbacks
    offenders = Strict2DifferentialReport.results.select do |row|
      row[:category] == :execution_change
    end

    assert_empty(
      offenders.map do |row|
        "#{row[:entry][:case].id}: #{row[:result].lax.callbacks.inspect} " \
          "vs #{row[:result].strict2.callbacks.inspect}"
      end,
      'strict2 acceptance must not change which extensions execute',
    )
  end

  def test_warn_always_executes_the_lax_callback_set
    loose_only = Strict2DifferentialReport.results.select { |row| row[:category] == :loose_only }
    refute_empty(loose_only)

    loose_only.each do |row|
      assert_equal(:fallback_matches_lax, row[:warn_relation], row[:entry][:case].id)
      assert_equal(row[:result].lax.callbacks, row[:result].warn.callbacks,
        "#{row[:entry][:case].id}: warn must execute the lax callback set")
      assert_equal(row[:result].lax.output, row[:result].warn.output,
        "#{row[:entry][:case].id}: warn must render the lax output")
    end
  end

  # Warn is a hybrid parser: tags fall back from strict2, but variables fall
  # back from strict and `when` clauses use the lax parser. These constructs are
  # rejected by strict2 yet produce a clean warning log, so "no warnings" is not
  # evidence that a template will survive the switch.
  def test_warn_can_silently_accept_what_strict2_rejects
    expected_silent = %w[
      var-bare-bracket
      liquid-case-when-junk
      ctrl-case-filter
      ctrl-case-extra
    ]

    assert_equal(expected_silent.sort, Strict2DifferentialReport.warn_silent_strict2_rejections.sort)

    Strict2DifferentialReport.results.select { |row| expected_silent.include?(row[:entry][:case].id) }.each do |row|
      assert(row[:result].strict2.rejected?, "#{row[:entry][:case].id}: strict2 should reject")
      assert(row[:result].warn.accepted?, "#{row[:entry][:case].id}: warn should still accept")
      assert_empty(row[:result].warn.warnings, "#{row[:entry][:case].id}: warn silently accepts")
    end
  end

  # raw/comment bodies are text, not execution. A probe-looking token inside them
  # must never appear in the callback log in any mode, and raw must still emit
  # the literal text.
  def test_protected_regions_never_report_execution_callbacks
    protected_rows = Strict2DifferentialReport.results.select do |row|
      row[:entry][:case].axis == :protected_region
    end

    refute_empty(protected_rows)
    protected_rows.each do |row|
      case_object = row[:entry][:case]
      next unless case_object.id.include?('probe-text') || case_object.id.include?('hidden')

      Strict2Differential::MODES.each do |mode|
        observation = row[:result][mode]
        refute_includes(
          observation.callbacks, "tag:#{Strict2Differential::PROBE_TAG}(hidden)",
          "#{case_object.id}/#{mode}: protected text must not execute",
        )
      end
    end
  end

  def test_raw_region_emits_literal_text_without_executing_it
    result = Strict2Differential.analyze(
      id: 'raw-literal',
      axis: :protected_region,
      template: "{% raw %}{% diff_tag hidden %}{{ p | diff_f1 }}{% endraw %}",
    )

    Strict2Differential::MODES.each do |mode|
      observation = result[mode]
      assert(observation.parse_accepted?, "#{mode} should parse raw text")
      assert_equal("{% diff_tag hidden %}{{ p | diff_f1 }}", observation.output)
      assert_empty(observation.callbacks, "#{mode} must not execute text inside raw")
    end
  end

  def test_comment_region_emits_nothing_and_executes_nothing
    result = Strict2Differential.analyze(
      id: 'comment-literal',
      axis: :protected_region,
      template: "{% comment %}{% diff_tag hidden %}{{ p | diff_f1 }}{% endcomment %}{% diff_tag after %}",
    )

    Strict2Differential::MODES.each do |mode|
      observation = result[mode]
      assert(observation.parse_accepted?, "#{mode} should parse comment text")
      assert_equal('', observation.output)
      assert_equal(["tag:#{Strict2Differential::PROBE_TAG}(after)"], observation.callbacks,
        "#{mode} must execute only the tag outside the comment")
    end
  end

  # A probe filter can only be counted if it is actually invoked. Quoting the
  # name, quoting the whole expression, or leaving it in a comment must not.
  def test_filter_probe_counts_only_real_invocations
    positive = Strict2Differential.analyze(id: 'invoked', axis: :variable, template: '{{ p | diff_f1 }}')
    assert_equal(["filter:diff_f1()"], positive.lax.callbacks)

    quoted_expression = Strict2Differential.analyze(
      id: 'quoted-expression',
      axis: :variable,
      template: "{{ 'p | diff_f1' }}",
    )
    assert_empty(quoted_expression.lax.callbacks, 'quoted filter text is not an invocation')
    assert_equal('p | diff_f1', quoted_expression.lax.output)

    in_comment = Strict2Differential.analyze(
      id: 'filter-in-comment',
      axis: :protected_region,
      template: '{% comment %}{{ p | diff_f1 }}{% endcomment %}',
    )
    assert_empty(in_comment.lax.callbacks, 'comment body is not an invocation')

    unregistered = Strict2Differential.analyze(id: 'unknown', axis: :variable, template: '{{ p | not_a_filter }}')
    assert_empty(unregistered.lax.callbacks, 'unknown filters are not counted as probe callbacks')
  end

  def test_render_partial_execution_is_visible_in_callback_log
    result = Strict2Differential.analyze(
      id: 'render-partial',
      axis: :render,
      template: "{% render 'sn', x: p %}",
    )

    assert_equal(
      ["read:sn", 'tag:diff_tag(in_partial)', 'filter:diff_f1()', 'filter:diff_f2()'],
      result.strict2.callbacks,
    )
    assert_equal(result.lax.callbacks, result.strict2.callbacks)
  end

  def test_markdown_report_lists_every_actionable_row
    markdown = Strict2DifferentialReport.markdown
    checklist = Strict2DifferentialReport.checklist_markdown

    actionable = Strict2DifferentialReport.results.reject do |row|
      [:equivalent, :rejected_both].include?(row[:category])
    end

    actionable.each do |row|
      id = row[:entry][:case].id
      assert_includes(markdown, id)
      assert_includes(checklist, id)
    end
  end

  def test_equivalently_executed_rows_are_actually_equivalent
    equivalent = Strict2DifferentialReport.results.select do |row|
      row[:category] == :equivalent
    end

    refute_empty(equivalent)
    equivalent.each do |row|
      result = row[:result]
      assert_equal(result.lax.output, result.strict2.output, "#{row[:entry][:case].id}: output differs")
      assert_equal(result.lax.callbacks, result.strict2.callbacks, "#{row[:entry][:case].id}: callbacks differ")
    end
  end
end
