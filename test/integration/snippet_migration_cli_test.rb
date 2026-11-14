# frozen_string_literal: true

require 'test_helper'
require 'open3'
require 'json'
require 'rbconfig'

class SnippetMigrationCliTest < Minitest::Test
  ROOT = File.expand_path('../..', __dir__)

  def test_cli_reports_static_and_manual_calls
    stdout, stderr, status = Open3.capture3(
      RbConfig.ruby,
      File.join(ROOT, 'bin', 'liquid-snippet-migration'),
      '--template', File.join(ROOT, 'example', 'snippet_migration', 'templates', 'caller.liquid'),
      '--snippets', File.join(ROOT, 'example', 'snippet_migration', 'snippets'),
      '--caller-binding', 'featured_product',
      '--caller-binding', 'badge',
      '--caller-binding', 'entries',
      '--global', 'shop',
      '--global', 'routes',
      '--global', 'all_products',
      '--private', 'private_token',
      '--format', 'json',
    )

    assert_equal('', stderr)
    assert(status.success?)
    report = JSON.parse(stdout)

    assert_equal(false, report['isolation']['sandbox'])
    assert_equal(%w(shop routes all_products), report['isolation']['global_data_still_visible'].map { |g| g['name'] })

    calls = report['calls'].to_h { |call| [call['snippet'], call] }
    assert_equal('static', calls['product_card']['status'])
    assert_equal('static', calls['line_items']['status'])
    assert_equal('manual_review', calls['secret_probe']['status'])
    assert_nil(calls['secret_probe']['suggested_render'])

    product = calls['product_card']['caller_can_provide'].to_h { |value| [value['name'], value] }
    assert_equal('featured_product', product['product']['expression'])
    assert_equal('badge', product['badge']['expression'])

    private_dependency = calls['secret_probe']['dependencies'].first
    assert_equal('private_parent_value', private_dependency['resolution'])
    assert_equal(false, private_dependency['render_argument_needed'])
  end
end
