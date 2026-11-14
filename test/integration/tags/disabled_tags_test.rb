# frozen_string_literal: true

require 'test_helper'

# Capability regression for the disabled-tags mechanism (`render` forbids
# `include`). Two independent disable layers (nested `{% render %}`) are
# unwound one layer at a time no matter how the inner region exits: normal
# return, break/continue, syntax error, or runtime error. The partial cache
# and Context reuse after an exception must never grant or revoke permission
# on their own.
class DisabledTagsTest < Minitest::Test
  include Liquid

  DISABLED_MESSAGE = 'include usage is not allowed in this context'

  class CountingFileSystem
    attr_reader :reads

    def initialize(values)
      @values = values
      @reads  = Hash.new(0)
    end

    def read_template_file(template_path)
      @reads[template_path] += 1
      @values.fetch(template_path)
    end
  end

  module BoomFilter
    def boom(_input)
      raise 'kaboom'
    end
  end

  def test_inner_layer_normal_exit_leaves_outer_layer_active
    file_system = CountingFileSystem.new(
      'deep' => '{% include "foo" %}',
      'mid'  => '{% render "deep" %}{% include "foo" %}',
      'foo'  => 'FOO',
    )
    environment, context = build_context(file_system)

    output = parse('{% render "mid" %}{% include "foo" %}', environment).render(context)

    assert_equal(
      "Liquid error (deep line 1): #{DISABLED_MESSAGE}" \
      "Liquid error (mid line 1): #{DISABLED_MESSAGE}FOO",
      output,
    )
    assert_equal({ 'mid' => 1, 'deep' => 1, 'foo' => 1 }, file_system.reads)
    refute(context.tag_disabled?('include'))
  end

  def test_break_exit_unwinds_only_inner_layer
    file_system = CountingFileSystem.new(
      'deep' => '{% break %}{% include "foo" %}',
      'mid'  => '{% for i in (1..2) %}{% render "deep" %}{% endfor %}{% include "foo" %}',
      'foo'  => 'FOO',
    )
    environment, context = build_context(file_system)

    output = parse('{% render "mid" %}{% include "foo" %}', environment).render(context)

    assert_equal("Liquid error (mid line 1): #{DISABLED_MESSAGE}FOO", output)
    assert_equal({ 'mid' => 1, 'deep' => 1, 'foo' => 1 }, file_system.reads)
    refute(context.tag_disabled?('include'))
  end

  def test_continue_exit_unwinds_only_inner_layer
    file_system = CountingFileSystem.new(
      'deep' => '{% continue %}{% include "foo" %}',
      'mid'  => '{% for i in (1..2) %}{% render "deep" %}{% endfor %}{% include "foo" %}',
      'foo'  => 'FOO',
    )
    environment, context = build_context(file_system)

    output = parse('{% render "mid" %}{% include "foo" %}', environment).render(context)

    assert_equal("Liquid error (mid line 1): #{DISABLED_MESSAGE}FOO", output)
    assert_equal({ 'mid' => 1, 'deep' => 1, 'foo' => 1 }, file_system.reads)
    refute(context.tag_disabled?('include'))
  end

  def test_syntax_error_exit_unwinds_all_layers_and_context_stays_usable
    file_system = CountingFileSystem.new(
      'bad' => '{% if %}{% endif %}',
      'mid' => '{% render "bad" %}{% include "foo" %}',
      'foo' => 'FOO',
    )
    environment, context = build_context(file_system)

    assert_raises(Liquid::SyntaxError) do
      parse('{% render "mid" %}', environment).render!(context)
    end

    refute(context.tag_disabled?('include'))
    assert_equal({ 'mid' => 1, 'bad' => 1 }, file_system.reads)

    output = parse('{% include "foo" %}', environment).render(context)
    assert_equal('FOO', output)
    assert_equal({ 'mid' => 1, 'bad' => 1, 'foo' => 1 }, file_system.reads)
  end

  def test_runtime_error_exit_unwinds_all_layers_and_context_stays_usable
    file_system = CountingFileSystem.new(
      'explode' => "{{ 'x' | boom }}",
      'mid'     => '{% render "explode" %}{% include "foo" %}',
      'foo'     => 'FOO',
    )
    environment, context = build_context(file_system)

    assert_raises(RuntimeError) do
      parse('{% render "mid" %}', environment).render!(context, filters: [BoomFilter])
    end

    refute(context.tag_disabled?('include'))
    assert_equal({ 'mid' => 1, 'explode' => 1 }, file_system.reads)

    output = parse('{% include "foo" %}', environment).render(context)
    assert_equal('FOO', output)
    assert_equal({ 'mid' => 1, 'explode' => 1, 'foo' => 1 }, file_system.reads)
  end

  def test_cached_partial_does_not_grant_include_permission
    file_system = CountingFileSystem.new(
      'shared' => 'SHARED',
      'wrap'   => '{% include "shared" %}',
    )
    environment, context = build_context(file_system)

    assert_equal('SHARED', parse('{% include "shared" %}', environment).render(context))
    assert_equal(1, file_system.reads['shared'])

    output = parse('{% render "wrap" %}', environment).render(context)
    assert_equal("Liquid error (wrap line 1): #{DISABLED_MESSAGE}", output)
    assert_equal(1, file_system.reads['shared'], 'cached partial must not bypass the disabled check')

    assert_equal('SHARED', parse('{% include "shared" %}', environment).render(context))
    assert_equal(1, file_system.reads['shared'], 'legal include must reuse the cache')
  end

  def test_partial_cached_by_render_does_not_block_legal_include
    file_system = CountingFileSystem.new(
      'shared' => 'SHARED',
      'wrap'   => '{% include "shared" %}',
    )
    environment, context = build_context(file_system)

    assert_equal('SHARED', parse('{% render "shared" %}', environment).render(context))
    assert_equal(1, file_system.reads['shared'])

    output = parse('{% render "wrap" %}', environment).render(context)
    assert_equal("Liquid error (wrap line 1): #{DISABLED_MESSAGE}", output)

    assert_equal('SHARED', parse('{% include "shared" %}', environment).render(context))
    assert_equal(1, file_system.reads['shared'], 'legal include must reuse the render-cached partial')
  end

  def test_disabled_include_never_loads_and_recovers_after_all_layers_exit
    file_system = CountingFileSystem.new(
      'wrap' => '{% include "foo" %}',
      'foo'  => 'FOO',
    )
    environment, context = build_context(file_system)

    output = parse('{% render "wrap" %}', environment).render(context)
    assert_equal("Liquid error (wrap line 1): #{DISABLED_MESSAGE}", output)
    assert_equal({ 'wrap' => 1 }, file_system.reads, 'disabled include must not touch the file system')

    output = parse('{% include "foo" %}', environment).render(context)
    assert_equal('FOO', output)
    assert_equal({ 'wrap' => 1, 'foo' => 1 }, file_system.reads)
  end

  def test_with_disabled_tags_exception_exit_unwinds_only_own_layer
    context = Liquid::Context.build
    context.with_disabled_tags(['include']) do
      assert_raises(RuntimeError) do
        context.with_disabled_tags(['include']) do
          raise 'boom'
        end
      end
      assert(context.tag_disabled?('include'), 'inner raise must not unwind the outer layer')
    end
    refute(context.tag_disabled?('include'))
  end

  def test_with_disabled_tags_nested_normal_exit
    context = Liquid::Context.build
    context.with_disabled_tags(['include']) do
      context.with_disabled_tags(['include']) do
        assert(context.tag_disabled?('include'))
      end
      assert(context.tag_disabled?('include'), 'inner exit must only unwind its own layer')
    end
    refute(context.tag_disabled?('include'))
  end

  def test_with_disabled_tags_outer_exception_restores_full_access
    context = Liquid::Context.build
    assert_raises(RuntimeError) do
      context.with_disabled_tags(['include']) do
        context.with_disabled_tags(['include']) do
          raise 'boom'
        end
      end
    end
    refute(context.tag_disabled?('include'))
  end

  def test_isolated_subcontext_inherits_disabled_state
    context = Liquid::Context.build
    context.with_disabled_tags(['include']) do
      subcontext = context.new_isolated_subcontext
      assert(subcontext.tag_disabled?('include'))
    end
  end

  private

  def build_context(file_system)
    environment = Liquid::Environment.build(file_system: file_system)
    context = Liquid::Context.build(
      static_environments: {},
      registers: Liquid::Registers.new(file_system: file_system),
      environment: environment,
    )
    [environment, context]
  end

  def parse(template_source, environment)
    Liquid::Template.parse(template_source, environment: environment, line_numbers: true)
  end
end
