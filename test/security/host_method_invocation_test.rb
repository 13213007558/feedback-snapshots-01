# frozen_string_literal: true

require 'test_helper'
require_relative 'host_method_probe'

class HostMethodInvocationTest < Minitest::Test
  include Liquid
  include LiquidSecurityProbe

  def traced_values(value, found = [])
    case value
    when TracedObject, TracedDrop
      found << value
    when Hash
      value.each_value { |item| traced_values(item, found) }
    when Array
      value.each { |item| traced_values(item, found) }
    end
    found
  end

  def render_with(template, assigns, options = {})
    targets = traced_values(assigns)
    targets.each { |object| object.recorder.clear }
    output = Template.parse(template).render!(assigns, options)
    [output, targets.map { |object| object.recorder.calls }.uniq]
  end

  def assert_calls(expected, template, assigns, options = {})
    output, calls = render_with(template, assigns, options)
    assert_equal(expected, calls, "calls for #{template.inspect}")
    output
  end

  def test_to_liquid_is_unconditional_on_every_top_level_lookup
    object = TracedObject.new

    assert_equal('TRACED', assert_calls([[:to_liquid, :==, :to_s]], '{{ o }}', { 'o' => object }))
    assert_equal('acme', assert_calls([[:to_liquid, :==, :key?, :[]]], '{{ o.name }}', { 'o' => object }))
    assert_equal('Y', assert_calls([[:to_liquid, :==, :to_liquid_value]], '{% if o %}Y{% endif %}', { 'o' => object }))
    assert_equal('', assert_calls([[:to_liquid, :==, :to_liquid_value, :==]], '{% if o == "x" %}Y{% endif %}', { 'o' => object }))
  end

  def test_direct_output_uses_to_s
    object = TracedObject.new
    out, calls = render_with('{{ o }}', { 'o' => object })

    assert_equal('TRACED', out)
    assert_includes(calls.first, :to_s)
  end

  def test_nested_containers_invoke_inspect_without_a_whitelist
    object = TracedObject.new

    out, calls = render_with('{{ h }}', { 'h' => { 'o' => object } })
    assert_includes(out, 'TRACED-INSPECT')
    assert_includes(calls.first, :inspect)
  end

  def test_conditions_use_protocol_methods_beyond_drop_whitelist
    object = TracedObject.new

    assert_calls([[:to_liquid, :==, :to_liquid_value, :include?]], '{% if o contains "x" %}Y{% endif %}', { 'o' => object })
    assert_calls([[:to_liquid, :==, :to_liquid_value, :empty?]], '{% if o == empty %}Y{% endif %}', { 'o' => object })
    assert_calls([[:to_liquid, :==, :to_liquid_value, :<]], '{% if o < 1 %}Y{% endif %}', { 'o' => object })
  end

  def test_for_and_table_row_call_each_directly
    object = TracedObject.new

    assert_calls([[:to_liquid, :==, :each]], '{% for x in o %}{{ x }}{% endfor %}', { 'o' => object })
    out, calls = render_with('{% tablerow x in o %}{{ x }}{% endtablerow %}', { 'o' => object })
    assert_includes(calls.first, :each)
    assert_match(/t1/, out)
  end

  def test_array_filters_use_indexing_and_comparison_not_the_drop_whitelist
    object = TracedObject.new
    array = [object]
    pair = [TracedObject.new, TracedObject.new]

    assert_calls([[:to_liquid, :[]]], '{{ a | map: "name" | join: "," }}', { 'a' => array })
    assert_calls([[:to_liquid, :[], :to_liquid, :[]]], '{{ a | where: "name", "acme" | map: "name" }}', { 'a' => array })
    assert_calls([[:to_liquid, :<=>], [:to_liquid]], '{{ a | sort | size }}', { 'a' => pair })
    assert_calls([[:to_liquid, :to_s]], '{{ a | join: "," }}', { 'a' => array })
  end

  def test_render_tag_evaluates_attributes_even_when_unused
    object = TracedObject.new
    file_system = MemoryFileSystem.new('unused' => 'constant', 'used' => '{{ x.name }}')

    out, calls = render_with(
      "{% render 'unused', x: o %}",
      { 'o' => object },
      { registers: { file_system: file_system } },
    )
    assert_equal('constant', out)
    assert_equal([[:to_liquid, :==]], calls)

    out, calls = render_with(
      "{% render 'used', x: o %}",
      { 'o' => object },
      { registers: { file_system: file_system } },
    )
    assert_equal('acme', out)
    assert_equal([[:to_liquid, :==, :to_liquid, :==, :key?, :[]]], calls)
  end

  def test_render_for_calls_count_and_each
    object = TracedObject.new
    file_system = MemoryFileSystem.new('iter' => '{{ x }}')

    out, calls = render_with(
      "{% render 'iter' for o as x %}",
      { 'o' => object },
      { registers: { file_system: file_system } },
    )
    assert_equal('t1t2', out)
    assert_equal([[:to_liquid, :==, :count, :each]], calls)
  end

  def test_drop_name_lookup_is_whitelisted_but_structural_methods_are_not
    drop = TracedDrop.new

    assert_equal('acme', assert_calls([[:==, :name]], '{{ o.name }}', { 'o' => drop }))
    assert_equal('', assert_calls([[:==, :liquid_method_missing]], '{{ o.inspect }}', { 'o' => drop }))
    assert_equal('', assert_calls([[:==, :liquid_method_missing]], '{{ o.each }}', { 'o' => drop }))
    assert_equal('deleted', assert_calls([[:==, :delete_all]], '{{ o.delete_all }}', { 'o' => drop }))
    assert_equal('s3cr3t', assert_calls([[:==, :secret_token]], '{{ o.secret_token }}', { 'o' => drop }))
  end

  def test_drop_output_and_iteration_bypass_name_whitelist
    drop = TracedDrop.new

    assert_equal('DROP-TO-S', assert_calls([[:==, :to_s]], '{{ o }}', { 'o' => drop }))
    assert_equal('DROP-TO-S', assert_calls([[:==, :to_s]], '{{ o.to_liquid }}', { 'o' => drop }))
    assert_equal('t1t2', assert_calls([[:==, :each]], '{% for x in o %}{{ x }}{% endfor %}', { 'o' => drop }))
    tablerow_out, tablerow_calls = render_with('{% tablerow x in o %}{{ x }}{% endtablerow %}', { 'o' => drop })
    assert_match(/t1/, tablerow_out)
    assert_equal([[:==, :each]], tablerow_calls)
    assert_calls([[:==, :include?]], '{% if o contains "x" %}Y{% endif %}', { 'o' => drop })
    assert_calls([[:==, :empty?]], '{% if o == empty %}Y{% endif %}', { 'o' => drop })
  end

  def test_drop_structural_methods_are_callable_by_name_when_whitelisted
    drop = TracedDrop.new

    assert_equal('2', assert_calls([[:==, :size]], '{{ o.size }}', { 'o' => drop }))
    assert_equal('t1', assert_calls([[:==, :first]], '{{ o.first }}', { 'o' => drop }))
    assert_equal('2', assert_calls([[:==, :count]], '{{ o.count }}', { 'o' => drop }))
  end

  def test_root_drop_is_looked_up_as_a_drop_not_a_hash
    drop = TracedDrop.new

    out, calls = render_with('{{ name }}|{{ delete_all }}|{{ secret_token }}', drop)
    assert_equal('acme|deleted|s3cr3t', out)
    assert_equal([[:name, :delete_all, :secret_token]], calls)
  end

  def test_default_drop_liquid_method_missing_raises_under_strict_variables
    drop = MissingRaisingDrop.new
    template = Template.parse('{{ o.nope }}')

    error = assert_raises(Liquid::UndefinedDropMethod) do
      template.render!({ 'o' => drop }, strict_variables: true)
    end
    assert_match(/undefined method nope/, error.message)
  end

  def test_render_for_drop_uses_variable_runner_without_rebinding_lookup
    drop = TracedDrop.new
    file_system = MemoryFileSystem.new('iter' => '{{ x }}')

    out, calls = render_with(
      "{% render 'iter' for drop as x %}",
      { 'drop' => drop },
      { registers: { file_system: file_system } },
    )
    assert_equal('t1t2', out)
    assert_equal([[:==, :count, :each]], calls)
  end

  def test_preview_and_delivery_share_the_same_call_path
    object = TracedObject.new

    preview_out, preview_calls = render_with('{{ o.name }}', { 'o' => object }, { strict_variables: true })
    delivery_out, delivery_calls = render_with('{{ o.name }}', { 'o' => object })

    assert_equal('acme', preview_out)
    assert_equal('acme', delivery_out)
    assert_equal([[:to_liquid, :==, :key?, :key?, :[]]], preview_calls)
    assert_equal([[:to_liquid, :==, :key?, :[]]], delivery_calls)
  end
end
