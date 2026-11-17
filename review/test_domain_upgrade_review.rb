# frozen_string_literal: true

require 'test-unit'
require_relative 'domain_upgrade_review'

# Regression coverage for the dependency-upgrade review harness.
#
# These tests pin the distinctions the review reports:
#   * a private-suffix addition changes parent-domain acceptance;
#   * host-only declarations are unaffected;
#   * an existing record is not re-scoped merely because the displayed
#     domain string is unchanged.
class TestDomainUpgradeReview < Test::Unit::TestCase
  FIXTURES = File.expand_path('fixtures', __dir__)

  def catalog(name)
    DomainUpgradeReview::Catalog.new(File.join(FIXTURES, name))
  end

  def before_catalog
    catalog('psl-baseline.txt')
  end

  def after_catalog
    catalog('psl-upgraded.txt')
  end

  def run_scenario_with(cat, id)
    scenario = DomainUpgradeReview.scenarios.find { |s| s.id == id }
    DomainUpgradeReview.with_catalog(cat) { DomainUpgradeReview.run_scenario(scenario) }
  end

  def test_fixture_diff_is_exactly_the_private_web_app_rule
    before_rules = before_catalog.rules.map(&:rule)
    after_rules = after_catalog.rules.map(&:rule)
    added = after_rules - before_rules
    removed = before_rules - after_rules

    assert_equal ['web.app'], added
    assert_equal [], removed
    rule = after_catalog.rules.find { |r| r.rule == 'web.app' }
    assert_equal :private, rule.section
  end

  def test_web_app_parent_domain_is_rejected_after_the_upgrade
    before = run_scenario_with(before_catalog, 'web-app-parent')
    after = run_scenario_with(after_catalog, 'web-app-parent')

    assert_equal 1, before[:accepted].size
    assert_equal 0, after[:accepted].size
    assert_equal 'sid=parent-web-app', before[:sent]['http://alice.web.app/']
    assert_equal '', after[:sent]['http://alice.web.app/']
    assert_equal 'sid=parent-web-app', before[:sent]['http://web.app/']
    assert_equal '', after[:sent]['http://web.app/']
  end

  def test_host_only_web_app_cookie_is_unchanged
    before = run_scenario_with(before_catalog, 'web-app-host-only')
    after = run_scenario_with(after_catalog, 'web-app-host-only')

    assert_equal before[:sent], after[:sent]
    assert_equal 'sid=host-web-app', after[:sent]['http://web.app/']
    assert_equal '', after[:sent]['http://alice.web.app/']
  end

  def test_multi_level_suffix_parent_boundary_is_unchanged
    before = run_scenario_with(before_catalog, 'co-jp-parent')
    after = run_scenario_with(after_catalog, 'co-jp-parent')

    assert_equal before[:sent], after[:sent]
    # sibling registrable domain under the same co.jp suffix
    assert_equal 'sid=co-jp', after[:sent]['http://other.example.co.jp/']
    # lookalike must never match
    assert_equal '', after[:sent]['http://notexample.co.jp/']
  end

  def test_unchanged_private_suffix_and_exception_rules
    %w[github-io-parent s3-private-parent kawasaki-exception].each do |id|
      before = run_scenario_with(before_catalog, id)
      after = run_scenario_with(after_catalog, id)
      assert_equal before[:sent], after[:sent], id
    end
  end

  def test_legacy_yaml_keeps_flag_but_stops_sending_to_the_suffix_subdomain
    record = DomainUpgradeReview.legacy_records.find { |r| r.format == :yaml }
    before = DomainUpgradeReview.with_catalog(before_catalog) {
      DomainUpgradeReview.run_legacy(record, FIXTURES)
    }
    after = DomainUpgradeReview.with_catalog(after_catalog) {
      DomainUpgradeReview.run_legacy(record, FIXTURES)
    }

    parent_before = before[:stored].find { |c| c['name'] == 'legacy_parent' }
    parent_after = after[:stored].find { |c| c['name'] == 'legacy_parent' }

    assert_equal true, parent_before['for_domain']
    assert_equal true, parent_after['for_domain'],
                 'YAML must not silently rewrite the stored flag'
    assert_equal 'legacy_parent=from-parent-record', before[:sent]['http://alice.web.app/']
    assert_equal '', after[:sent]['http://alice.web.app/']
  end

  def test_legacy_cookiestxt_recomputes_flag_on_load
    record = DomainUpgradeReview.legacy_records.find { |r| r.format == :cookiestxt }
    after = DomainUpgradeReview.with_catalog(after_catalog) {
      DomainUpgradeReview.run_legacy(record, FIXTURES)
    }

    parent = after[:stored].find { |c| c['name'] == 'legacy_parent' }
    assert_equal false, parent['for_domain'],
                 'cookies.txt loader re-runs domain= and downgrades the suffix'
    assert_equal nil, parent['registrable_domain']
  end

  def test_legacy_reaudit_is_separate_from_new_cookie_rejection
    record = DomainUpgradeReview.legacy_records.find { |r| r.format == :yaml }
    reaudit = DomainUpgradeReview.reaudit(
      record, FIXTURES, before_catalog, after_catalog
    )

    assert_equal true, reaudit['display_domain_unchanged']
    assert_equal 'keep_narrowed', reaudit['recommendation']
    assert_include reaudit['sent_before'], 'http://alice.web.app/'
    assert_not_include reaudit['sent_after'], 'http://alice.web.app/'
    # Keeping a narrowed legacy record does not make a fresh
    # Set-Cookie: Domain=web.app acceptable again.
    fresh = run_scenario_with(after_catalog, 'web-app-parent')
    assert_equal 0, fresh[:accepted].size
  end

  def test_declared_suffix_is_not_registrable_under_the_new_catalog
    facts = DomainUpgradeReview.with_catalog(after_catalog) {
      DomainUpgradeReview.facts('web.app')
    }
    assert_nil facts[:registrable_domain]
    assert_equal true, facts[:suffix_or_ip]
  end
end
