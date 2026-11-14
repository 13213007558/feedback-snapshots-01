# frozen_string_literal: true

require 'test_helper'
require 'open3'
require 'json'
require 'liquid/snippet_migration'
require 'rbconfig'

class SnippetMigrationExampleTest < Minitest::Test
  ROOT = File.expand_path('../..', __dir__)

  def test_example_proves_output_parity_and_private_isolation
    stdout, stderr, status = Open3.capture3(
      RbConfig.ruby,
      File.join(ROOT, 'example', 'snippet_migration', 'run.rb'),
    )

    assert_equal('', stderr)
    assert(status.success?)

    result = JSON.parse(stdout)
    assert_equal(true, result['legitimate_outputs_identical'])
    assert_equal(1, result['private_value_reads']['legacy_include'])
    assert_equal(0, result['private_value_reads']['migrated_render'])
    assert_equal('Arbor Draft', result['side_effect_control']['legacy_include_trailing_heading'])
    assert_equal('Catalog', result['side_effect_control']['migrated_render_trailing_heading'])
  end

  def test_suggested_render_runs_with_caller_supplied_values
    Dir.mktmpdir do |dir|
      File.write(File.join(dir, 'card.liquid'), '{{ product.title }} {{ badge }} {{ shop.name }}')
      report = Liquid::SnippetMigration.analyze(
        templates: { 'caller' => "{% include 'card' with featured as product, badge: badge %}" },
        snippets: dir,
        caller_bindings: ['featured', 'badge'],
        globals: ['shop'],
      )
      suggested = report.calls.first['suggested_render']
      file_system = Object.new
      file_system.define_singleton_method(:read_template_file) do |name|
        File.read(File.join(dir, "#{name}.liquid"))
      end

      context = Liquid::Context.build(
        static_environments: { 'shop' => { 'name' => 'Store' } },
        registers: { file_system: file_system },
      )
      context['featured'] = { 'title' => 'Draft' }
      context['badge'] = 'New'
      output = Liquid::Template.parse(suggested).render!(context)

      assert_equal('Draft New Store', output)
    end
  end
end
