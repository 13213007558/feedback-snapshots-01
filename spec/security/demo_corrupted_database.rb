#!/usr/bin/env ruby
#
# Standalone demonstration of bundler-audit's defenses against a
# possibly-corrupted advisory database.
#
# Usage:
#
#   ruby spec/security/demo_corrupted_database.rb
#
# Everything happens under a temporary directory. The script uses harmless
# payloads only, performs no network requests, and never constructs arbitrary
# Ruby objects from YAML.
#
# For each scenario it prints:
#
#   * whether the bad advisory was rejected,
#   * whether a trustworthy finding from the same scan was preserved,
#   * whether the scan is marked complete, and
#   * what exit status the CLI would use (0 = clean, 1 = vulnerable,
#     2 = incomplete / cannot certify safety).
#

$LOAD_PATH.unshift(File.expand_path('../../lib',__dir__))

require 'bundler/audit/advisory'
require 'bundler/audit/cli'
require 'bundler/audit/cli/formats'
require 'bundler/audit/cli/formats/text'
require 'bundler/audit/database'
require 'bundler/audit/report'
require 'bundler/audit/scanner'

require 'fileutils'
require 'stringio'
require 'tmpdir'

module Demo
  VALID = {
    'gem' => 'demo',
    'url' => 'https://example.com/',
    'title' => 'Demo advisory',
    'description' => 'A harmless advisory used by the demo.',
    'patched_versions' => ['>= 2.0.0']
  }

  def self.advisory_yaml(overrides={},omit: [],extra: '')
    fields = VALID.merge(overrides).reject { |key,_| omit.include?(key) }.map do |key,value|
      if value.is_a?(Array)
        "#{key}:\n" + value.map { |entry| "  - #{entry.dump}\n" }.join
      else
        "#{key}:\n  #{value.to_s.dump}\n"
      end
    end.join

    "---\n" + fields + extra
  end

  def self.bundle(dir)
    FileUtils.mkdir_p(dir)
    File.write(File.join(dir,'Gemfile.lock'), <<~LOCK)
      GEM
        remote: https://rubygems.org/
        specs:
          demo (1.0.0)
          stable (1.0.0)

      PLATFORMS
        ruby

      DEPENDENCIES
        demo
        stable
    LOCK
    dir
  end

  def self.database(dir,advisories)
    FileUtils.mkdir_p(dir)

    advisories.each do |gem_name,entries|
      gem_dir = File.join(dir,'gems',gem_name)
      FileUtils.mkdir_p(gem_dir)

      entries.each { |file,body| File.write(File.join(gem_dir,file),body) }
    end

    dir
  end

  def self.cli_status(report)
    if report.vulnerable?
      1
    elsif report.incomplete?
      2
    else
      0
    end
  end

  def self.run(name,bundle,db,expect:)
    report = Bundler::Audit::Scanner.new(
      bundle,'Gemfile.lock',Bundler::Audit::Database.new(db)
    ).report

    output = StringIO.new
    dashboard = Bundler::Audit::CLI.new([],{})
    dashboard.extend Bundler::Audit::CLI::Formats::Text
    dashboard.print_report(report,output)
    summary = output.string.lines.map(&:chomp).grep(/vulnerabilit|incomplete/i).first

    actual = {
      findings:    report.results.map(&:to_s),
      complete:    report.complete?,
      vulnerable:  report.vulnerable?,
      exit_status: cli_status(report),
      summary:     summary
    }

    puts "== #{name} =="
    actual.each { |key,value| puts "  #{key.to_s.ljust(12)} #{value.inspect}" }
    puts

    expect.each do |key,value|
      next if actual[key] == value

      abort("FAILED #{name}: expected #{key}=#{value.inspect}, got #{actual[key].inspect}")
    end
  end
end

Dir.mktmpdir('bundler-audit-demo') do |dir|
  bundle = Demo.bundle(File.join(dir,'bundle'))

  # 1. A single bad advisory must not produce a "safe" result.
  db = Demo.database(File.join(dir,'db-taught'),
                     'demo' => {'CVE-2020-0001.yml' => Demo.advisory_yaml({'patched_versions' => ['>= 0']})})
  Demo.run('widened patched range',bundle,db,
           expect: {findings: [],complete: false,vulnerable: false,exit_status: 2,
                    summary: 'Scan incomplete; cannot confirm that no vulnerabilities exist'})

  # 2. A bad advisory must not hide a trustworthy finding in the same scan.
  db = Demo.database(File.join(dir,'db-mixed'),
                     'demo'   => {'CVE-2020-0001.yml' => Demo.advisory_yaml({'patched_versions' => ['>= 0']})},
                     'stable' => {'CVE-2020-0002.yml' => Demo.advisory_yaml({'gem' => 'stable'})})
  Demo.run('bad advisory plus real finding',bundle,db,
           expect: {findings: ['CVE-2020-0002'],complete: false,vulnerable: true,exit_status: 1,
                    summary: 'Vulnerabilities found!'})

  # 3. Duplicate keys must not override the first version range.
  bad = Demo.advisory_yaml({'patched_versions' => ['>= 9.9.9']})
  bad << "patched_versions:\n  - \">= 0\"\n"
  db = Demo.database(File.join(dir,'db-duplicate'),
                     'demo' => {'CVE-2020-0001.yml' => bad})
  Demo.run('duplicate YAML key',bundle,db,
           expect: {findings: [],complete: false,vulnerable: false,exit_status: 2})

  # 4. A typo/abnormal field must not be rendered as "already fixed".
  db = Demo.database(File.join(dir,'db-scalar'),
                     'demo' => {'CVE-2020-0001.yml' => Demo.advisory_yaml(omit: ['patched_versions'],
                                                                          extra: "patched_versions: \">= 0\"\n")})
  Demo.run('scalar patched_versions',bundle,db,
           expect: {findings: [],complete: false,vulnerable: false,exit_status: 2})

  # 5. A path-bearing gem name must not escape the selected database.
  path = File.join(dir,'bundle-traversal')
  FileUtils.mkdir_p(path)
  File.write(File.join(path,'Gemfile.lock'), <<~LOCK)
    GEM
      remote: https://rubygems.org/
      specs:
        ../../outside (1.0.0)

    PLATFORMS
      ruby

    DEPENDENCIES
      ../../outside
  LOCK
  db = Demo.database(File.join(dir,'db-traversal'),
                     'demo' => {'CVE-2020-0001.yml' => Demo.advisory_yaml})
  Demo.run('gem name escapes database',path,db,
           expect: {findings: [],complete: false,vulnerable: false,exit_status: 2})

  # 6. A completely clean database must be the only case that certifies safety.
  db = Demo.database(File.join(dir,'db-clean'),
                     'stable' => {'CVE-2020-0002.yml' => Demo.advisory_yaml({'gem' => 'stable',
                                                                             'patched_versions' => ['>= 1.0.0','< 1.0.0']})})
  Demo.run('clean database',bundle,db,
           expect: {findings: [],complete: true,vulnerable: false,exit_status: 0,
                    summary: 'No vulnerabilities found'})
end

puts "All completeness invariants held."

