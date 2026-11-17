# frozen_string_literal: true

# Runs the fixed before/after domain-authorization matrix.
#
#   ruby review/run_review.rb            # human summary + JSON to review/output
#   ruby review/run_review.rb --json     # JSON to stdout only
#
# No network, no real hosts, no production cookies: every origin/probe URL
# is a synthetic "http://..." literal and all suffix data comes from
# review/fixtures. The only runtime input is the installed http-cookie code
# under review.

require 'json'
require 'fileutils'
require_relative 'domain_upgrade_review'

ROOT = File.expand_path('..', __dir__)
FIXTURES = {
  'before' => File.join(ROOT, 'review/fixtures/psl-baseline.txt'),
  'after'  => File.join(ROOT, 'review/fixtures/psl-upgraded.txt'),
}.freeze

module DomainUpgradeReview
  def self.observe
    catalogs = FIXTURES.to_h { |label, path| [label, Catalog.new(path)] }

    scenario_rows = scenarios.map { |scenario|
      runs = catalogs.to_h { |label, catalog|
        row = with_catalog(catalog) { run_scenario(scenario) }
        [label, {
          'accepted' => row[:accepted].size,
          'acceptable' => row[:accepted].map { |c| c.acceptable? },
          'effective_for_domain' => row[:accepted].map(&:for_domain?),
          'registrable_domain' => row[:accepted].map { |c| c.domain_name&.domain },
          'sent' => row[:sent],
        }]
      }
      {
        'id' => scenario.id,
        'group' => scenario.group,
        'set_cookie' => scenario.set_cookie,
        'origin' => scenario.origin,
        'note' => scenario.note,
        'before' => runs['before'],
        'after' => runs['after'],
        'verdict' => verdict(runs['before'], runs['after']),
      }
    }

    legacy_rows = legacy_records.map { |record|
      fixture_dir = File.join(ROOT, 'review/fixtures')
      runs = catalogs.to_h { |label, catalog|
        row = with_catalog(catalog) { run_legacy(record, fixture_dir) }
        [label, {
          'stored' => row[:stored],
          'sent' => row[:sent],
        }]
      }
      reaudit = reaudit(record, fixture_dir, catalogs['before'], catalogs['after'])
      {
        'id' => record.id,
        'format' => record.format.to_s,
        'note' => record.note,
        'before' => runs['before'],
        'after' => runs['after'],
        'verdict' => verdict(runs['before'], runs['after']),
        'reaudit' => reaudit,
      }
    }

    classification = %w[
      web.app example.co.jp co.jp github.io s3.amazonaws.com
      foo.kawasaki.jp city.kawasaki.jp example.local local
    ].to_h { |host|
      [host, catalogs.to_h { |label, catalog|
        [label, with_catalog(catalog) {
          DomainUpgradeReview.facts(host).merge(
            'deciding_rules' => DomainUpgradeReview.deciding_rules(catalog, host).map { |r| rule_row(r) }
          )
        }]
      }]
    }

    # Attribute the web.app change to an exact rule + section.
    added = catalogs['after'].rules.reject { |rule|
      catalogs['before'].rules.any? { |old| old.rule == rule.rule }
    }
    removed = catalogs['before'].rules.reject { |rule|
      catalogs['after'].rules.any? { |new_rule| new_rule.rule == rule.rule }
    }

    {
      'meta' => {
        'generated_at' => Time.now.utc.iso8601,
        'http_cookie_version' => HTTP::Cookie::VERSION,
        'domain_name_version' => DomainName::VERSION,
        'network_used' => false,
        'cookies_read_from_disk' => false,
        'fixtures' => catalogs.transform_values { |c| {
          'path' => c.path.sub(ROOT + '/', ''),
          'rules' => c.rules.size,
        } },
      },
      'catalog_diff' => {
        'added_after' => added.map { |r| rule_row(r) },
        'removed_after' => removed.map { |r| rule_row(r) },
      },
      'classification' => classification,
      'scenarios' => scenario_rows,
      'legacy' => legacy_rows,
    }
  end

  def self.rule_row(rule)
    { 'rule' => rule.rule, 'value' => rule.value, 'section' => rule.section.to_s,
      'source_line' => rule.line }
  end

  # before/after verdict from observable Cookie-header values.
  def self.verdict(before, after)
    if before.key?('accepted') && after.key?('accepted')
      accepted_before = before['accepted'].positive?
      accepted_after = after['accepted'].positive?
      return 'newly_rejected' if accepted_before && !accepted_after
      return 'newly_accepted' if !accepted_before && accepted_after
    end
    before['sent'] == after['sent'] ? 'unchanged' : 'scope_changed'
  end

  def self.format_table(report)
    lines = []
    lines << '== Catalog diff (fixed fixtures) =='
    (report['catalog_diff']['added_after'] + report['catalog_diff']['removed_after']).each do |row|
      lines << format('  %-20s value=%-2d section=%s (fixture line %d)',
                      row['rule'], row['value'], row['section'], row['source_line'])
    end
    lines << ''
    lines << '== New declarations (Set-Cookie -> Cookie) =='
    report['scenarios'].each do |row|
      lines << format('%s [%s]', row['id'], row['verdict'])
      lines << "  Set-Cookie: #{row['set_cookie']}  (from #{row['origin']})"
      row['before']['sent'].each do |url, value|
        lines << format('  %-6s %-34s Cookie: %s', 'before', url, value.inspect)
      end
      row['after']['sent'].each do |url, value|
        lines << format('  %-6s %-34s Cookie: %s', 'after ', url, value.inspect)
      end
    end
    lines << ''
    lines << '== Legacy records (flags preserved as stored) =='
    report['legacy'].each do |row|
      lines << format('%s (%s) [%s] recommendation=%s display_domain_unchanged=%s',
                      row['id'], row['format'], row['verdict'],
                      row['reaudit']['recommendation'],
                      row['reaudit']['display_domain_unchanged'])
      %w[before after].each do |phase|
        data = row[phase]
        data['stored'].each do |c|
          lines << format('  %-6s stored name=%-14s domain=%-10s for_domain=%-5s registrable=%s',
                          phase, c['name'], c['domain'].inspect, c['for_domain'].inspect,
                          c['registrable_domain'].inspect)
        end
        data['sent'].each do |url, value|
          lines << format('  %-6s %-34s Cookie: %s', phase, url, value.inspect)
        end
      end
    end
    lines.join("\n")
  end
end

report = DomainUpgradeReview.observe

if ARGV.include?('--json')
  puts JSON.pretty_generate(report)
else
  FileUtils.mkdir_p(File.join(ROOT, 'review/output'))
  out = File.join(ROOT, 'review/output/upgrade-matrix.json')
  File.write(out, JSON.pretty_generate(report) + "\n")
  puts DomainUpgradeReview.format_table(report)
  puts
  puts "Wrote #{out.sub(ROOT + '/', '')}"
end
