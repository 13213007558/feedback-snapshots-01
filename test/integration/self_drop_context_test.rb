# frozen_string_literal: true

require 'test_helper'

class SelfDropContextTest < Minitest::Test
  include Liquid

  def test_self_drop_passed_as_render_param_is_rebound_to_inner_scope
    source = <<~LIQUID
      {%- assign var = 42 -%}
      {%- assign s = self -%}
      {%- render "snippet1", other_self: s -%}
    LIQUID

    partials = {
      'snippet1' => <<~LIQUID,
        {%- assign var = 43 -%}
        {{- other_self.var }}|{{ self.var -}}
      LIQUID
    }

    assert_template_result('43|43', source, partials: partials)
  end

  def test_self_drop_passed_as_render_param_does_not_expose_parent_locals
    source = <<~LIQUID
      {%- assign secret = 'PARENT_PRIVATE' -%}
      {%- assign s = self -%}
      {%- render "snippet1", other_self: s -%}
    LIQUID

    partials = {
      'snippet1' => "{{ other_self['secret'] }}|{{ self['secret'] }}|{% if other_self['secret'] %}defined{% else %}missing{% endif %}",
    }

    assert_template_result('||missing', source, partials: partials)
  end

  def test_self_drop_passed_in_an_array_does_not_expose_parent_locals
    source = <<~LIQUID
      {%- assign secret = 'PARENT_PRIVATE' -%}
      {%- assign s = self -%}
      {%- assign list = s | compact -%}
      {%- render "snippet1", list: list -%}
    LIQUID

    partials = {
      'snippet1' => "{{ list[0]['secret'] }}|{% if list[0]['secret'] %}defined{% else %}missing{% endif %}",
    }

    assert_template_result('|missing', source, partials: partials)
  end

  def test_self_drop_passed_with_as_does_not_expose_parent_locals
    source = <<~LIQUID
      {%- assign secret = 'PARENT_PRIVATE' -%}
      {%- render "snippet1" with self as other_self -%}
    LIQUID

    partials = {
      'snippet1' => "{{ other_self['secret'] }}|{% if other_self['secret'] %}defined{% else %}missing{% endif %}",
    }

    assert_template_result('|missing', source, partials: partials)
  end

  def test_self_drop_can_still_read_globals_when_passed_to_render
    source = <<~LIQUID
      {%- assign s = self -%}
      {%- render "snippet1", other_self: s -%}
    LIQUID

    partials = {
      'snippet1' => "{{ other_self['global_value'] }}|{{ other_self.global_value }}",
    }

    assert_template_result(
      'GLOBAL|GLOBAL',
      source,
      { 'global_value' => 'GLOBAL' },
      partials: partials,
    )
  end

  def test_explicit_render_arguments_remain_available
    source = <<~LIQUID
      {%- assign var = 42 -%}
      {%- render "snippet1", var: var, other: 'other' -%}
    LIQUID

    partials = {
      'snippet1' => "{{ var }}|{{ other }}|{{ self.var }}|{{ self.other }}",
    }

    assert_template_result('42|other|42|other', source, partials: partials)
  end

  def test_local_variable_shadows_rebound_self_within_partial
    source = <<~LIQUID
      {%- assign secret = 'PARENT_PRIVATE' -%}
      {%- assign s = self -%}
      {%- render "snippet1", other_self: s -%}
    LIQUID

    partials = {
      'snippet1' => "{%- assign secret = 'CHILD_PRIVATE' -%}{{ other_self['secret'] }}|{{ self['secret'] }}",
    }

    assert_template_result('CHILD_PRIVATE|CHILD_PRIVATE', source, partials: partials)
  end

  def test_self_drop_in_render_without_passing_resolves_inner_scope
    source = <<~LIQUID
      {%- assign var = 42 -%}
      {%- render "snippet1" -%}
    LIQUID

    partials = {
      'snippet1' => <<~LIQUID,
        {%- assign var = 99 -%}
        {{- self.var -}}
      LIQUID
    }

    assert_template_result('99', source, partials: partials)
  end

  def test_self_drop_passed_to_nested_renders_resolves_each_inner_scope
    source = <<~LIQUID
      {%- assign a = 1 -%}
      {%- assign s1 = self -%}
      {%- render "snippet1", outer: s1 -%}
    LIQUID

    partials = {
      'snippet1' => <<~LIQUID,
        {%- assign a = 2 -%}
        {%- assign s2 = self -%}
        {%- render "snippet2", outer: outer, middle: s2 -%}
      LIQUID
      'snippet2' => <<~LIQUID,
        {%- assign a = 3 -%}
        {{- outer.a }}|{{ middle.a }}|{{ self.a -}}
      LIQUID
    }

    assert_template_result('3|3|3', source, partials: partials)
  end

  def test_self_drop_reflects_variables_assigned_after_creation
    source = <<~LIQUID
      {%- assign s = self -%}
      {%- assign x = 42 %}{{ s.x -}}
    LIQUID

    assert_template_result('42', source)
  end

  def test_self_drop_context_setter_is_undefined
    context = Context.new
    drop = SelfDrop.new(context)
    refute(drop.respond_to?(:context=))

    assert_template_result('42', '{{ self.x }}', { 'x' => 42 })
  end

  def test_self_drop_repeated_lookups_compare_equal_for_same_context
    context = Context.new
    drop = context.find_variable("self")
    cached_drop = context.find_variable("self")

    assert_same(drop, cached_drop)
    assert_equal(drop.object_id, cached_drop.object_id)
    assert_equal(drop, cached_drop)
  end

  def test_assigned_self_drop_compares_equal_to_itself
    assert_template_result('T', '{% assign s = self %}{% if s == s %}T{% else %}F{% endif %}')
  end

  def test_distinct_self_assignments_compare_equal_for_same_context
    assert_template_result('T', '{% assign a = self %}{% assign b = self %}{% if a == b %}T{% else %}F{% endif %}')
  end

  def test_bare_self_compares_equal_to_bare_self
    assert_template_result('T', '{% if self == self %}T{% else %}F{% endif %}')
  end

  def test_self_drop_with_strict_variables_does_not_raise_for_defined_var
    t = Template.parse('{{ self.x }}')
    result = t.render({ 'x' => 42 }, strict_variables: true)
    assert_equal('42', result)
  end

  def test_self_drop_with_strict_variables_returns_nil_for_undefined_var
    t = Template.parse('{{ self.x }}')
    result = t.render({}, strict_variables: true)
    assert_equal('', result)
  end

  def test_self_drop_can_be_passed_as_bare_drop_to_render
    t = Template.parse('{{ self.x }}')
    drop = SelfDrop.new(Context.new({ 'x' => 42 }))
    result = t.render(drop)
    assert_equal('42', result)
  end

  def test_self_drop_for_context_returns_self_when_already_scoped_to_context
    context = Context.new
    drop = SelfDrop.new(context)

    assert_same(drop, drop.for_context(context))
  end

  def test_self_drop_for_context_rebinds_to_a_different_context
    outer = Context.new({ 'secret' => 'OUTER' })
    inner = Context.new
    drop = SelfDrop.new(outer)

    rebound = drop.for_context(inner)

    refute_same(drop, rebound)
    assert_nil(rebound['secret'])
    assert_equal('OUTER', drop['secret'])
  end

  def test_explicit_nil_argument_is_distinct_from_an_undefined_key
    source = <<~LIQUID
      {%- assign parent_nil = nil -%}
      {%- assign s = self -%}
      {%- render "snippet1", s: s, explicit_nil: nil -%}
    LIQUID

    partials = {
      'snippet1' => "{{ s['explicit_nil'] }}|{{ s['parent_nil'] }}|{{ s['missing'] }}",
    }

    assert_template_result('||', source, partials: partials)
  end

  def test_self_drop_in_array_is_rebound_when_resolved_by_inner_context
    source = <<~LIQUID
      {%- assign secret = 'PARENT_PRIVATE' -%}
      {%- assign box = self | compact -%}
      {%- render "snippet1", box: box -%}
    LIQUID

    partials = {
      'snippet1' => "{%- assign item = box[0] -%}{{ item['secret'] }}",
    }

    assert_template_result('', source, partials: partials)
  end
end
