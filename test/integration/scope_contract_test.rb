# frozen_string_literal: true

require 'test_helper'

# Scope contract for {% assign %} / {% capture %}:
#
# Both tags write to `context.scopes.last`, the OUTERMOST scope of the
# current Context (Context#push unshifts, so scopes[0] is the innermost).
# Which scope object that is depends on the entry point:
#
# - normal blocks (if/for/...): the shared outer scope of the template's
#   context, so the variable survives the block.
# - include: the parent's outer scope (same Context), so writes leak into
#   the including template by design.
# - render: a fresh isolated subcontext, so writes never touch the parent.
#
# In all cases the write lands in the template's own scope hash
# (instance_assigns), never in the host-provided assigns hash
# (environments): a template may SHADOW a host variable name, but it
# cannot REWRITE the host's original value.
class ScopeContractTest < Minitest::Test
  include Liquid

  class HashFileSystem
    def initialize(values)
      @values = values
    end

    def read_template_file(template_path)
      @values.fetch(template_path) do
        raise Liquid::FileSystemError, "No such template '#{template_path}'"
      end
    end
  end

  def render_with_partials(source, assigns, partials: {}, raise_errors: true)
    file_system = HashFileSystem.new(partials)
    environment = Liquid::Environment.build(file_system: file_system)
    template = Liquid::Template.parse(source, environment: environment)
    output = if raise_errors
      template.render!(assigns, registers: { file_system: file_system })
    else
      template.render(assigns, registers: { file_system: file_system })
    end
    [template, output]
  end

  def test_assign_and_capture_in_plain_blocks_write_the_outermost_scope
    template, output = render_with_partials(
      "{% if true %}{% assign x = 'in-if' %}{% endif %}" \
      "{% for i in (1..1) %}{% capture y %}cap-{{ i }}{% endcapture %}{% endfor %}" \
      "[{{ x }}|{{ y }}]",
      {},
    )

    assert_equal('[in-if|cap-1]', output)
    # writes landed in the template's outermost scope (instance_assigns)
    assert_equal({ 'x' => 'in-if', 'y' => 'cap-1' }, template.instance_assigns)
  end

  def test_capture_shadows_host_name_but_never_rewrites_host_value
    host = { 'perm' => 'deny' }
    template, output = render_with_partials(
      "{% capture perm %}allow{% endcapture %}" \
      "{% if perm == 'allow' %}branch:allow{% else %}branch:deny{% endif %}",
      host,
    )

    # inside the template the shadow wins and drives the branch...
    assert_equal('branch:allow', output)
    assert_equal('allow', template.instance_assigns['perm'])
    # ...but the host's original value is untouched
    assert_equal('deny', host['perm'])
  end

  def test_nested_capture_with_same_name_last_write_wins_in_shared_outer_scope
    _template, output = render_with_partials(
      "{% assign v = 'outer' %}" \
      "{% capture v %}inner1{% endcapture %}" \
      "{% if true %}{% capture v %}inner2{% endcapture %}{% endif %}" \
      "{{ v }}",
      {},
    )

    assert_equal('inner2', output)
  end

  def test_include_shares_the_parent_scope_so_writes_leak_by_design
    host = { 'perm' => 'deny' }
    template, output = render_with_partials(
      "{% include 'snip' %}[{{ leaked }}|{{ perm }}]",
      host,
      partials: {
        'snip' => "{% assign leaked = 'from-include' %}{% capture perm %}allow{% endcapture %}",
      },
    )

    assert_equal('[from-include|allow]', output)
    assert_equal('from-include', template.instance_assigns['leaked'])
    assert_equal('allow', template.instance_assigns['perm'])
    # even the leaky include path only shadows; the host hash is not rewritten
    assert_equal('deny', host['perm'])
  end

  def test_render_isolates_the_partial_scope_in_both_directions
    host = { 'perm' => 'deny' }
    template, output = render_with_partials(
      "{% assign outer_var = 'outer' %}{% render 'snip' %}[{{ leaked | default: 'nil' }}|{{ perm }}]",
      host,
      partials: {
        'snip' => "{% assign leaked = 'from-render' %}{% capture perm %}allow{% endcapture %}" \
                  "(outer_var={{ outer_var | default: 'nil' }} perm={{ perm }})",
      },
    )

    # the partial sees neither the parent's assigned variables nor leaks its own
    assert_equal('(outer_var=nil perm=allow)[nil|deny]', output)
    assert_equal({ 'outer_var' => 'outer' }, template.instance_assigns)
    assert_equal('deny', host['perm'])
  end

  def test_render_for_loop_keeps_each_iteration_isolated_from_the_parent
    host = { 'perm' => 'deny' }
    _template, output = render_with_partials(
      "{% render 'item' for (1..2) as i %}[perm={{ perm }}]",
      host,
      partials: { 'item' => "{% capture perm %}allow{% endcapture %}({{ i }}:{{ perm }})" },
    )

    assert_equal('(1:allow)(2:allow)[perm=deny]', output)
    assert_equal('deny', host['perm'])
  end

  def test_include_restores_the_pushed_scope_after_an_error
    template, output = render_with_partials(
      "{% include 'boom', foo: 'attr' %}[foo={{ foo | default: 'gone' }} before_err={{ before_err | default: 'nil' }}]",
      {},
      partials: { 'boom' => "{% assign before_err = 1 %}{% include 'missing' %}" },
      raise_errors: false,
    )

    # the include's stacked scope (holding the `foo` attribute) was popped via
    # Context#stack's ensure, while the pre-error write to the shared outer
    # scope persists per the include sharing rule
    assert_equal("Liquid error: No such template 'missing'[foo=gone before_err=1]", output)
    refute_empty(template.errors)
  end

  def test_render_discards_the_isolated_subcontext_after_an_error
    template, output = render_with_partials(
      "{% render 'boom' %}[{{ leaked | default: 'nil' }}]",
      {},
      partials: { 'boom' => "{% assign leaked = 1 %}{% render 'missing' %}" },
      raise_errors: false,
    )

    assert_equal("Liquid error: No such template 'missing'[nil]", output)
    refute_empty(template.errors)
  end

  def test_context_stack_pops_the_scope_even_when_the_block_raises
    context = Liquid::Context.build

    assert_raises(RuntimeError) do
      context.stack({ 'inner' => 1 }) { raise 'boom' }
    end

    assert_equal(1, context.scopes.size)
    assert_nil(context['inner'])
  end

  def test_include_is_disabled_inside_render_partials
    template, output = render_with_partials(
      "{% render 'outer_snip' %}",
      {},
      partials: { 'outer_snip' => "{% include 'inner_snip' %}", 'inner_snip' => 'x' },
      raise_errors: false,
    )

    assert_equal('Liquid error: include usage is not allowed in this context', output)
    assert_equal([Liquid::DisabledError], template.errors.map(&:class))
  end
end
