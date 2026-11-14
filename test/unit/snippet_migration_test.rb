# frozen_string_literal: true

require 'test_helper'
require 'liquid/snippet_migration'

class SnippetMigrationTest < Minitest::Test
  include Liquid

  def analyze(template, snippets, **options)
    Liquid::SnippetMigration.analyze(
      templates: { 'caller' => template },
      snippets: snippets,
      **options,
    ).to_h
  end

  def with_snippets(files)
    Dir.mktmpdir do |dir|
      files.each do |name, body|
        File.write(File.join(dir, "#{name}.liquid"), body)
      end
      yield dir
    end
  end

  def test_static_include_lists_dependencies_and_caller_values
    with_snippets('card' => '{{ product.title }} {{ badge }}') do |dir|
      report = analyze(
        "{% include 'card' with featured_product as product, badge: badge %}",
        dir,
        caller_bindings: { 'product' => 'featured_product', 'badge' => 'badge' },
        globals: ['shop'],
      )

      assert_equal(1, report['calls'].length)
      call = report['calls'].first
      assert_equal('static', call['status'])
      assert_equal(%w(badge product), call['dependencies'].map { |d| d['name'] })
      assert_equal(
        [
          { 'name' => 'badge', 'expression' => 'badge', 'resolution' => 'explicit_include_argument' },
          { 'name' => 'product', 'expression' => 'featured_product', 'resolution' => 'explicit_include_argument' },
        ],
        call['caller_can_provide'],
      )
      assert_equal(
        '{% render "card" with featured_product as product, badge: badge %}',
        call['suggested_render'],
      )
    end
  end

  def test_caller_binding_fills_implicit_parent_local
    with_snippets('card' => '{{ product.title }}') do |dir|
      report = analyze("{% include 'card' %}", dir, caller_bindings: ['product'])
      call = report['calls'].first

      assert_equal('static', call['status'])
      assert_equal('caller_binding', call['dependencies'].first['resolution'])
      assert_equal(
        [{ 'name' => 'product', 'expression' => 'product', 'resolution' => 'caller_binding' }],
        call['caller_can_provide'],
      )
      assert_equal('{% render "card", product: product %}', call['suggested_render'])
    end
  end

  def test_local_assign_shadowing_is_reported_separately_from_caller_scope
    with_snippets('card' => "{% assign heading = product.title %}{{ heading }}") do |dir|
      report = analyze(
        "{% assign heading = 'Caller' %}{% include 'card', product: product %}",
        dir,
        caller_bindings: ['product'],
      )
      call = report['calls'].first
      shadow = call['local_shadowing'].find { |item| item['name'] == 'heading' }

      assert_equal('assign', shadow['kind'])
      assert_equal(['caller_local_scope'], shadow['shadows'])
      assert_equal(%w(product), call['dependencies'].map { |d| d['name'] })
      refute_includes(call['caller_can_provide'].map { |value| value['name'] }, 'heading')
    end
  end

  def test_loop_item_and_forloop_are_local_to_snippet
    with_snippets('items' => '{% for item in entries %}{{ forloop.index }}:{{ item.title }}{% endfor %}') do |dir|
      report = analyze("{% include 'items' %}", dir, caller_bindings: ['entries'])
      call = report['calls'].first

      assert_equal(%w(entries), call['dependencies'].map { |d| d['name'] })
      assert_equal(%w(item forloop), call['local_shadowing'].map { |s| s['name'] })
      assert_equal(
        [{ 'name' => 'entries', 'expression' => 'entries', 'resolution' => 'caller_binding' }],
        call['caller_can_provide'],
      )
    end
  end

  def test_private_parent_value_is_never_suggested
    with_snippets('secret' => '{{ private_token }}') do |dir|
      report = analyze(
        "{% include 'secret' %}",
        dir,
        caller_bindings: ['private_token'],
        private_names: ['private_token'],
      )
      call = report['calls'].first
      dependency = call['dependencies'].first

      assert_equal('manual_review', call['status'])
      assert(dependency['private_parent_value'])
      refute(dependency['render_safe'])
      refute(dependency['render_argument_needed'])
      assert_nil(call['suggested_render'])
      assert_empty(call['caller_can_provide'])
      assert_equal('private_parent_value', dependency['resolution'])
    end
  end

  def test_filter_arguments_are_dependencies
    with_snippets(
      'card' => '{% assign title = product.title | append: suffix %}{{ other | default: fallback, allow_false: allow }}',
    ) do |dir|
      report = analyze('{% include "card" %}', dir, caller_bindings: %w(product suffix other fallback allow))
      call = report['calls'].first

      assert_equal(%w(allow fallback other product suffix), call['dependencies'].map { |d| d['name'] })
      assert_equal('static', call['status'])
    end
  end

  def test_bare_as_alias_reads_caller_scope_value_not_alias_name
    with_snippets('card' => '{{ card_alias }}') do |dir|
      report = analyze("{% include 'card' as card_alias %}", dir, caller_bindings: ['card'])
      call = report['calls'].first

      assert_equal('static', call['status'])
      assert_equal(
        [{ 'name' => 'card_alias', 'source_expression' => 'card', 'kind' => 'implicit_caller_scope' }],
        call['include_implicit_bindings'],
      )
      assert_equal('{% render "card", card_alias: card %}', call['suggested_render'])
    end
  end

  def test_snippet_syntax_error_requires_manual_review
    with_snippets('bad' => '{% if %}') do |dir|
      report = analyze("{% include 'bad' %}", dir)
      call = report['calls'].first

      assert_equal('manual_review', call['status'])
      assert_nil(call['suggested_render'])
      assert_match(/syntax error/, report['manual_review'].first['detail'])
    end
  end

  def test_dynamic_template_name_requires_manual_review
    report = analyze("{% assign name = 'card' %}{% include name %}", empty_snippets_dir)

    assert_equal(1, report['manual_review'].length)
    assert_match(/dynamic include template name/, report['manual_review'].first['detail'])
    assert_empty(report['calls'])
  end

  def test_dynamic_bracket_key_requires_manual_review_without_guessing
    with_snippets('card' => '{{ product[key] }}') do |dir|
      report = analyze("{% include 'card' %}", dir, caller_bindings: ['product', 'key'])
      call = report['calls'].first

      assert_equal('manual_review', call['status'])
      assert_nil(call['suggested_render'])
      assert_equal(1, report['manual_review'].length)
      assert_match(/dynamic bracket key/, report['manual_review'].first['detail'])
    end
  end

  def test_custom_tag_requires_manual_review
    custom = Class.new(Liquid::Tag) do
      def initialize(tag_name, markup, parse_context)
        super
      end
    end
    environment = Liquid::Environment.build do |env|
      env.register_tag('custom', custom)
    end

    with_snippets('card' => '{% custom product %}') do |dir|
      report = analyze("{% include 'card' %}", dir, environment: environment, caller_bindings: ['product'])
      call = report['calls'].first

      assert_equal('manual_review', call['status'])
      assert_nil(call['suggested_render'])
    end
  end

  def test_nested_include_blocks_automatic_migration
    with_snippets(
      'outer' => "{% include 'inner' %}",
      'inner' => '{{ title }}',
    ) do |dir|
      report = analyze("{% include 'outer' %}", dir, caller_bindings: ['title'])
      call = report['calls'].first

      assert_equal('manual_review', call['status'])
      assert_nil(call['suggested_render'])
      assert_match(/nested include/, report['manual_review'].first['detail'])
    end
  end

  def test_global_data_is_reported_as_still_visible
    report = analyze('', empty_snippets_dir, globals: %w(shop routes))

    assert_equal(%w(shop routes), report['isolation']['global_data_still_visible'].map { |g| g['name'] })
    assert_equal(false, report['isolation']['sandbox'])
    assert_equal(true, report['isolation']['parent_local_variables_hidden'])
  end

  def test_caller_read_after_include_blocks_automatic_migration
    with_snippets('card' => "{% assign leaked = 'x' %}{{ leaked }}") do |dir|
      report = analyze("{% include 'card' %}{{ leaked }}", dir)
      call = report['calls'].first

      assert_equal('manual_review', call['status'])
      assert_nil(call['suggested_render'])
      assert_equal(true, call['include_side_effects'].first['caller_reads_after_include'])
      assert_match(/caller reads after this include/, report['manual_review'].first['detail'])
    end
  end

  def test_include_side_effects_are_reported_as_isolated_by_render
    with_snippets('card' => "{% assign leaked = 'x' %}{{ leaked }}") do |dir|
      report = analyze("{% include 'card' %}", dir)
      call = report['calls'].first

      assert_equal(
        [
          {
            'name' => 'leaked',
            'kind' => 'assign',
            'line' => 1,
            'include_leaks_to_caller' => true,
            'render_isolated' => true,
            'caller_reads_after_include' => false,
          },
        ],
        call['include_side_effects'],
      )
    end
  end

  private

  def empty_snippets_dir
    @empty_snippets_dir ||= Dir.mktmpdir
  end
end
