# frozen_string_literal: true

require 'test_helper'

class ResourceLimitsUnitTest < Minitest::Test
  def test_cumulative_scores_initialize_to_zero
    limits = Liquid::ResourceLimits.new({})
    assert_equal(0, limits.cumulative_render_score)
    assert_equal(0, limits.cumulative_assign_score)
  end

  def test_cumulative_limits_default_to_nil
    limits = Liquid::ResourceLimits.new({})
    assert_nil(limits.cumulative_render_score_limit)
    assert_nil(limits.cumulative_assign_score_limit)
  end

  def test_cumulative_limits_configurable_via_hash
    limits = Liquid::ResourceLimits.new(
      cumulative_render_score_limit: 500,
      cumulative_assign_score_limit: 300,
    )
    assert_equal(500, limits.cumulative_render_score_limit)
    assert_equal(300, limits.cumulative_assign_score_limit)
  end

  def test_cumulative_limits_configurable_via_accessor
    limits = Liquid::ResourceLimits.new({})
    limits.cumulative_render_score_limit = 500
    assert_equal(500, limits.cumulative_render_score_limit)
  end

  def test_cumulative_scores_survive_reset
    limits = Liquid::ResourceLimits.new({})
    limits.increment_render_score(10)
    limits.increment_assign_score(5)

    limits.reset

    assert_equal(0, limits.render_score)
    assert_equal(0, limits.assign_score)
    assert_equal(10, limits.cumulative_render_score)
    assert_equal(5, limits.cumulative_assign_score)
  end

  def test_cumulative_scores_accumulate_across_resets
    limits = Liquid::ResourceLimits.new({})
    limits.increment_render_score(10)
    limits.reset
    limits.increment_render_score(20)
    limits.reset
    limits.increment_render_score(30)

    assert_equal(30, limits.render_score)
    assert_equal(60, limits.cumulative_render_score)
  end

  def test_cumulative_render_score_limit_raises
    limits = Liquid::ResourceLimits.new(cumulative_render_score_limit: 25)
    limits.increment_render_score(10)
    limits.reset
    limits.increment_render_score(10)
    limits.reset

    assert_raises(Liquid::MemoryError) do
      limits.increment_render_score(10)
    end
    assert(limits.reached?)
  end

  def test_cumulative_assign_score_limit_raises
    limits = Liquid::ResourceLimits.new(cumulative_assign_score_limit: 15)
    limits.increment_assign_score(8)
    limits.reset

    assert_raises(Liquid::MemoryError) do
      limits.increment_assign_score(8)
    end
    assert(limits.reached?)
  end

  def test_per_template_limits_still_work_with_cumulative
    limits = Liquid::ResourceLimits.new(
      render_score_limit: 50,
      cumulative_render_score_limit: 1000,
    )
    assert_raises(Liquid::MemoryError) do
      limits.increment_render_score(51)
    end
  end

  def test_filter_work_score_defaults_to_zero_and_is_not_limited
    limits = Liquid::ResourceLimits.new({})
    assert_nil(limits.filter_work_score_limit)
    assert_equal(0, limits.filter_work_score)

    limits.increment_filter_work_score(1_000_000)
    assert_equal(1_000_000, limits.filter_work_score)
    refute(limits.reached?)
  end

  def test_filter_work_score_limit_is_configurable
    limits = Liquid::ResourceLimits.new(filter_work_score_limit: 10)
    assert_equal(10, limits.filter_work_score_limit)

    limits.filter_work_score_limit = 3
    limits.increment_filter_work_score(3)
    assert_equal(3, limits.filter_work_score)

    assert_raises(Liquid::MemoryError) do
      limits.increment_filter_work_score(1)
    end
    assert(limits.reached?)
  end

  def test_filter_work_score_resets_between_renders_but_cumulative_scores_do_not
    limits = Liquid::ResourceLimits.new(filter_work_score_limit: 5)
    limits.increment_filter_work_score(5)
    limits.increment_render_score(7)

    limits.reset

    assert_equal(0, limits.filter_work_score)
    assert_equal(7, limits.cumulative_render_score)

    limits.increment_filter_work_score(5)
    assert_equal(5, limits.filter_work_score)
  end
end
