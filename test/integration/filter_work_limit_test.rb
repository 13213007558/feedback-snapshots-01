# frozen_string_literal: true

require 'test_helper'

# Exercises the optional filter_work_score_limit, which bounds the intermediate
# work of the standard Liquid filters before large objects are allocated.
class FilterWorkLimitTest < Minitest::Test
  include Liquid

  def render_with_limit(source, assigns, limit)
    template = Template.parse(source)
    template.resource_limits.filter_work_score_limit = limit
    [template.render!(assigns), template.resource_limits]
  end

  def render_score(source, assigns = {})
    template = Template.parse(source)
    template.render!(assigns)
    template.resource_limits.filter_work_score
  end

  def assert_rejected(source, assigns, limit)
    template = Template.parse(source)
    template.resource_limits.filter_work_score_limit = limit
    error = assert_raises(Liquid::MemoryError) { template.render!(assigns) }
    [error, template.resource_limits]
  end

  # --- metering without a limit configured: results are unchanged -------------

  def test_unlimited_filters_keep_existing_results
    assigns = {
      'csv' => 'a,b,c,d,e',
      'nums' => [3, 1, 2, 1],
      'pairs' => [{ 'x' => 1 }, { 'x' => 2 }],
    }

    assert_equal('a|b|c|d|e', Template.parse("{{ csv | split: ',' | join: '|' }}").render!(assigns))
    assert_equal('1,2,3', Template.parse('{{ nums | uniq | sort | join: "," }}').render!(assigns))
    assert_equal('1-2-3-4', Template.parse('{{ a | concat: b | map: "x" | join: "-" }}').render!(
      'a' => [{ 'x' => 1 }, { 'x' => 2 }], 'b' => [{ 'x' => 3 }, { 'x' => 4 }],
    ))
  end

  def test_nested_arrays_are_still_flattened
    assert_equal('1,2,3,4', Template.parse('{{ a | join: "," }}').render!('a' => [1, [2, [3, 4]]]))
    assert_equal(10, Template.parse('{{ a | sum }}').render!('a' => [1, [2, [3, 4]]]).to_i)
  end

  def test_repeated_subarrays_are_flattened_each_time
    nested = [1, [2]]
    assert_equal('1,2,1,2', Template.parse('{{ a | join: "," }}').render!('a' => [nested, nested]))
  end

  def test_recursive_arrays_raise_like_native_flatten
    recursive = [1, 2]
    recursive << recursive

    # Filters that traverse the input flatten it lazily and reject recursion,
    # matching the ArgumentError that Array#flatten raises.
    assert_raises(Liquid::ArgumentError) do
      Template.parse('{{ a | join }}').render!('a' => recursive)
    end
    assert_raises(Liquid::ArgumentError) do
      Template.parse('{{ a | uniq | size }}').render!('a' => recursive)
    end
  end

  # --- existing arrays: one unit per flattened, visited element ---------------

  def test_existing_array_is_charged_per_visited_element
    pairs = [{ 'x' => 1 }, { 'x' => 2 }, { 'x' => 3 }, { 'x' => 4 }]
    assert_equal(5, render_score('{{ a | join: "-" }}', 'a' => [1, 2, 3, 4, 5]))
    # map bills its input, then join bills the mapped output: 4 + 4.
    assert_equal(8, render_score('{{ a | map: "x" | join }}', 'a' => pairs))
  end

  def test_nested_array_charges_flattened_leaves_only
    assert_equal(4, render_score('{{ a | join }}', 'a' => [1, [2, [3, 4]]]))
  end

  def test_existing_array_rejection_consumes_at_most_limit_plus_one
    _error, limits = assert_rejected('{{ a | join: "-" }}', { 'a' => (1..100).to_a }, 5)
    assert_operator(limits.filter_work_score, :<=, 6)
  end

  # --- lazy inputs: billed lazily, never materialized up front ---------------

  def test_lazy_range_is_traversed_without_materialization
    range = (1..1_000_000_000).dup
    range.define_singleton_method(:to_a) { raise 'range was materialized' }

    _error, limits = assert_rejected('{{ r | join: "-" }}', { 'r' => range }, 5)
    assert_equal(6, limits.filter_work_score)
  end

  def test_reverse_of_lazy_range_is_bounded_and_never_materialized
    range = (1..1_000_000_000).dup
    range.define_singleton_method(:to_a) { raise 'range was materialized' }

    _error, limits = assert_rejected('{{ r | reverse | first }}', { 'r' => range }, 3)
    assert_operator(limits.filter_work_score, :<=, 4)
  end

  def test_custom_enumerable_is_charged_per_yielded_element
    # A lazy Enumerator exposes each but has no bounded length; the iterator must
    # bill each yielded value rather than trusting an upfront size.
    lazy_source = Object.new
    def lazy_source.to_liquid
      1.step
    end

    _error, limits = assert_rejected('{{ e | join }}', { 'e' => lazy_source }, 4)
    assert_equal(5, limits.filter_work_score)
  end

  # --- exact integer ranges: arithmetic length, billed per visited item -------

  def test_integer_range_filter_input_is_billed_per_visited_item
    assert_equal(10, render_score('{{ r | join }}', 'r' => 1..10))
    _error, limits = assert_rejected('{{ r | join }}', { 'r' => 1..(1 << 40) }, 7)
    assert_equal(8, limits.filter_work_score)
  end

  # --- split: pre-allocation, per segment, with exact semantics ---------------

  def test_split_is_charged_per_emitted_segment
    # split bills 5 segments, then join bills the 5 mapped values.
    assert_equal(10, render_score("{{ s | split: ',' | join }}", 's' => 'a,b,c,d,e'))
    assert_equal(6, render_score("{{ s | split: '' | join }}", 's' => 'abc'))
    assert_equal(0, render_score("{{ s | split: ',' | size }}", 's' => ''))
  end

  def test_split_preserves_trailing_empty_suppression
    assert_equal(2, render_score("{{ s | split: ',' | size }}", 's' => 'a,b,'))
    # Three delimiters are still charged even though the retained result is empty,
    # so a delimiter-heavy input cannot evade the budget.
    assert_equal(3, render_score("{{ s | split: 'a' | size }}", 's' => 'aaa'))
  end

  def test_split_rejects_before_buffering_more_than_the_budget
    big_csv = Array.new(10_000, 'x').join(',')
    _error, limits = assert_rejected("{{ s | split: ',' | size }}", { 's' => big_csv }, 7)
    assert_operator(limits.filter_work_score, :<=, 8)
  end

  # --- concat: the second array is billed before the allocation ---------------

  def test_concat_charges_both_collections_before_buffering
    # size reads the buffered length without another traversal, so the score
    # reflects only concat: 2 input elements plus 3 pre-charged appended leaves.
    assert_equal(5, render_score('{{ a | concat: b | size }}', 'a' => [1, 2], 'b' => [3, 4, 5]))
  end

  def test_concat_does_not_flatten_its_argument_when_metering
    # [[2, 3]] has length 1 and is appended as a single element, so concat costs
    # one unit for the input plus one for the argument.
    assert_equal(2, render_score('{{ a | concat: b | size }}', 'a' => [1], 'b' => [[2, 3]]))
  end

  def test_concat_rejects_a_large_argument_before_allocation
    big = Array.new(10_000, 1)
    _error, limits = assert_rejected('{{ a | concat: b | size }}', { 'a' => [1], 'b' => big }, 5)
    assert_equal(10_000, limits.filter_work_score)
  end

  # --- shared budget across a chain: no per-filter refresh --------------------

  def test_chained_filters_share_one_budget
    # reverse (4) + uniq (4) = 8 units against a single limit of 5; the second
    # stage must not start with a fresh allowance.
    _error, limits = assert_rejected('{{ a | reverse | uniq | join }}', { 'a' => [1, 2, 3, 4] }, 5)
    assert_operator(limits.filter_work_score, :<=, 6)
  end

  def test_legal_chain_under_budget_produces_unchanged_output
    output, limits = render_with_limit('{{ a | concat: b | sort | join: "-" }}',
      { 'a' => [3, 1], 'b' => [4, 2] }, 50)
    assert_equal('1-2-3-4', output)
    assert_operator(limits.filter_work_score, :<=, 50)
  end

  def test_budget_resets_on_a_fresh_render
    template = Template.parse('{{ a | join }}')
    template.resource_limits.filter_work_score_limit = 3
    assert_raises(Liquid::MemoryError) { template.render!('a' => [1, 2, 3, 4, 5]) }

    # A smaller input renders fine on the retry because the score resets.
    assert_equal('1 2 3', template.render!('a' => [1, 2, 3]))
  end
end
