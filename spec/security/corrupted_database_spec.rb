#
# Negative samples for a possibly-corrupted advisory database.
#
# These tests treat the advisory database as untrusted input. They build
# throw-away databases and bundles under a temporary directory, load them
# through the real Advisory/Database/Scanner classes, and use harmless
# payloads. No network access is performed and no arbitrary Ruby objects
# are constructed.
#
# The completeness invariant is central: a scan which could not read every
# advisory must never be reported as "no vulnerabilities found".
#

require 'spec_helper'
require 'bundler/audit/advisory'
require 'bundler/audit/database'
require 'bundler/audit/report'
require 'bundler/audit/scanner'
require 'bundler/audit/cli'
require 'bundler/audit/cli/formats'
require 'bundler/audit/cli/formats/text'
require 'bundler/audit/cli/formats/json'
require 'bundler/audit/cli/formats/junit'

require 'fileutils'
require 'json'
require 'stringio'
require 'tmpdir'

module SecurityFixtures
  VALID = {
    'gem' => 'demo',
    'url' => 'https://example.com/',
    'title' => 'Demo advisory',
    'description' => 'A harmless advisory used by the security specs.',
    'patched_versions' => ['>= 2.0.0']
  }

  def self.advisory(overrides={})
    VALID.merge(overrides)
  end

  def self.advisory_text(overrides={},omit: [],header: "---\n")
    fields = advisory(overrides).reject { |key,_value| omit.include?(key) }.map do |key,value|
      case value
      when Array
        "#{key}:\n" + value.map { |entry| "  - #{entry.dump}\n" }.join
      else
        "#{key}:\n  #{value.to_s.dump}\n"
      end
    end.join

    header + fields
  end

  def self.bundle(dir,name='Gemfile.lock')
    FileUtils.mkdir_p(dir)
    File.write(File.join(dir,name), <<~LOCK)
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

      entries.each do |file,body|
        File.write(File.join(gem_dir,file),body)
      end
    end

    dir
  end

  def self.evidence(report)
    report.results.map { |result| result.to_s }
  end
end

describe "corrupted advisory database" do
  around do |example|
    Dir.mktmpdir('bundler-audit-security') do |dir|
      @tmp = dir
      example.run
    end
  end

  def write_advisory(relative,body,gem_name='demo')
    SecurityFixtures.database(File.join(@tmp,'db'),
                              gem_name => {relative => body})
    File.join(@tmp,'db','gems',gem_name,relative)
  end

  def parse(field,value,raw: nil)
    field_block = if value.is_a?(Array)
                    "#{field}:\n" + value.map { |entry| "  - #{entry.dump}\n" }.join
                  else
                    "#{field}: #{raw || value.to_s.dump}\n"
                  end

    SecurityFixtures.advisory_text(omit: [field]) + field_block
  end

  describe "Advisory parsing" do
    it "rejects duplicate YAML keys which would hide a widened range" do
      body = SecurityFixtures.advisory_text({'patched_versions' => ['>= 9.9.9']})
      body << "patched_versions:\n  - \">= 0\"\n"

      path = write_advisory('CVE-2020-0001.yml',body)

      expect {
        Bundler::Audit::Advisory.load(path)
      }.to raise_error(Bundler::Audit::Advisory::Invalid,/duplicate YAML key/)
    end

    it "rejects a requirement which matches every version" do
      body = parse('patched_versions',['>= 0'])
      path = write_advisory('CVE-2020-0001.yml',body)

      expect {
        Bundler::Audit::Advisory.load(path)
      }.to raise_error(Bundler::Audit::Advisory::Invalid,/matches every version/)
    end

    it "rejects an empty requirement instead of treating everything as patched" do
      body = parse('patched_versions',[''])
      path = write_advisory('CVE-2020-0001.yml',body)

      expect {
        Bundler::Audit::Advisory.load(path)
      }.to raise_error(Bundler::Audit::Advisory::Invalid)
    end

    it "rejects a widened unaffected_versions range which would hide a vulnerability" do
      body = SecurityFixtures.advisory_text({'unaffected_versions' => ['>= 0']})
      path = write_advisory('CVE-2020-0001.yml',body)

      expect {
        Bundler::Audit::Advisory.load(path)
      }.to raise_error(Bundler::Audit::Advisory::Invalid,/matches every version/)
    end

    it "rejects a repeated key inside the same mapping even when the last value is benign" do
      body = SecurityFixtures.advisory_text
      body << "title:\n  \"Demo advisory\"\n"

      path = write_advisory('CVE-2020-0001.yml',body)

      expect {
        Bundler::Audit::Advisory.load(path)
      }.to raise_error(Bundler::Audit::Advisory::Invalid,/duplicate YAML key/)
    end

    it "rejects a scalar patched_versions field instead of widening it" do
      body = SecurityFixtures.advisory_text(omit: ['patched_versions'])
      body << "patched_versions: \">= 9.9.9\"\n"

      path = write_advisory('CVE-2020-0001.yml',body)

      expect {
        Bundler::Audit::Advisory.load(path)
      }.to raise_error(Bundler::Audit::Advisory::Invalid,/must be an Array/)
    end

    it "rejects additional YAML documents which would be silently ignored" do
      body = SecurityFixtures.advisory_text(omit: ['patched_versions'])
      body << "---\npatched_versions:\n  - \">= 9.9.9\"\n"

      path = write_advisory('CVE-2020-0001.yml',body)

      expect {
        Bundler::Audit::Advisory.load(path)
      }.to raise_error(Bundler::Audit::Advisory::Invalid,/exactly one YAML document/)
    end

    it "rejects YAML merge keys used to smuggle in a patched range" do
      body = <<~YAML
        ---
        defaults: &defaults
          patched_versions:
            - ">= 0"
        gem: demo
        url: https://example.com/
        title: Demo advisory
        description: A harmless advisory used by the security specs.
        <<: *defaults
      YAML

      path = write_advisory('CVE-2020-0001.yml',body)

      expect {
        Bundler::Audit::Advisory.load(path)
      }.to raise_error(Bundler::Audit::Advisory::Invalid,/merge keys/)
    end

    it "rejects explicit tags which could request arbitrary object construction" do
      body = SecurityFixtures.advisory_text(omit: ['patched_versions'])
      body << "patched_versions:\n  - !ruby/object:Object {}\n"

      path = write_advisory('CVE-2020-0001.yml',body)

      expect {
        Bundler::Audit::Advisory.load(path)
      }.to raise_error(Bundler::Audit::Advisory::Invalid,/explicit YAML tags/)
    end

    it "rejects non-String scalar fields which would render misleadingly" do
      body = parse('title',true,raw: 'true')

      path = write_advisory('CVE-2020-0001.yml',body)

      expect {
        Bundler::Audit::Advisory.load(path)
      }.to raise_error(Bundler::Audit::Advisory::Invalid,/title must be a String/)
    end

    it "rejects malformed version requirements" do
      body = parse('patched_versions',['>= banana'])
      path = write_advisory('CVE-2020-0001.yml',body)

      expect {
        Bundler::Audit::Advisory.load(path)
      }.to raise_error(Bundler::Audit::Advisory::Invalid,/invalid patched_versions requirement/)
    end

    it "rejects identifier values containing control characters" do
      body = parse('cve',"2015-1234\nNot checked")
      path = write_advisory('CVE-2020-0001.yml',body)

      expect {
        Bundler::Audit::Advisory.load(path)
      }.to raise_error(Bundler::Audit::Advisory::Invalid,/unsafe characters/)
    end

    it "still loads a well-formed advisory and reports the gem as vulnerable" do
      body = SecurityFixtures.advisory_text
      path = write_advisory('CVE-2020-0001.yml',body)

      advisory = Bundler::Audit::Advisory.load(path)

      expect(advisory.id).to eq('CVE-2020-0001')
      expect(advisory.patched_versions.map(&:to_s)).to eq(['>= 2.0.0'])
      expect(advisory.vulnerable?(Gem::Version.new('1.0.0'))).to be true
    end
  end

  describe "Database enumeration" do
    it "reports each bad advisory instead of silently skipping it" do
      SecurityFixtures.database(File.join(@tmp,'db'),
                                'demo' => {
                                  'CVE-2020-0001.yml' => parse('patched_versions',['>= 0']),
                                  'CVE-2020-0002.yml' => SecurityFixtures.advisory_text
                                })

      database = Bundler::Audit::Database.new(File.join(@tmp,'db'))
      errors   = []
      loaded   = database.advisories(on_error: ->(error) { errors << error }).map(&:id)

      expect(loaded).to eq(['CVE-2020-0002'])
      expect(errors.length).to eq(1)
      expect(errors.first).to be_kind_of(Bundler::Audit::Database::AdvisoryError)
      expect(errors.first.message).to include('CVE-2020-0001.yml')
    end

    it "raises rather than returning a partial list when no error handler is given" do
      SecurityFixtures.database(File.join(@tmp,'db'),
                                'demo' => {
                                  'CVE-2020-0001.yml' => parse('patched_versions',['>= 0'])
                                })

      database = Bundler::Audit::Database.new(File.join(@tmp,'db'))

      expect {
        database.advisories.to_a
      }.to raise_error(Bundler::Audit::Database::AdvisoryError)
    end

    it "refuses gem names which would escape the selected database" do
      outside = File.join(@tmp,'outside')
      FileUtils.mkdir_p(outside)
      File.write(File.join(outside,'CVE-2020-0001.yml'),SecurityFixtures.advisory_text)

      SecurityFixtures.database(File.join(@tmp,'db'),
                                'demo' => {'CVE-2020-0002.yml' => SecurityFixtures.advisory_text})

      database = Bundler::Audit::Database.new(File.join(@tmp,'db'))

      ['../../outside','../outside','/etc/passwd','..',''].each do |name|
        expect {
          database.advisories_for(name).to_a
        }.to raise_error(ArgumentError,/invalid gem name/)
      end
    end

    it "does not load advisories outside the database even when a path is supplied directly" do
      outside = File.join(@tmp,'outside.yml')
      File.write(outside,SecurityFixtures.advisory_text)

      SecurityFixtures.database(File.join(@tmp,'db'),
                                'demo' => {'CVE-2020-0001.yml' => SecurityFixtures.advisory_text})

      database = Bundler::Audit::Database.new(File.join(@tmp,'db'))

      allow(Bundler::Audit::Advisory).to receive(:load).and_call_original
      errors = []

      # Simulates a subclass or future enumeration bug yielding an outside path.
      database.send(:load_advisory,outside,->(error) { errors << error })

      expect(errors.length).to eq(1)
      expect(errors.first.message).to include('could not load advisory')
      expect(Bundler::Audit::Advisory).not_to have_received(:load)
    end

    it "refuses a symlinked directory which points outside the database" do
      secret_dir = File.join(@tmp,'secret')
      FileUtils.mkdir_p(secret_dir)
      File.write(File.join(secret_dir,'CVE-2020-0009.yml'),SecurityFixtures.advisory_text)

      db_dir = SecurityFixtures.database(File.join(@tmp,'db'),
                                         'demo' => {'CVE-2020-0002.yml' => SecurityFixtures.advisory_text})
      File.symlink(secret_dir,File.join(db_dir,'gems','escaped'))

      database = Bundler::Audit::Database.new(db_dir)
      loaded   = []
      errors   = []

      database.advisories(on_error: ->(error) { errors << error }).each do |advisory|
        loaded << advisory.id
      end

      expect(loaded).to eq(['CVE-2020-0002'])
      expect(errors.length).to eq(1)
      expect(errors.first.advisory_path).to include('escaped')
    end
  end

  describe "Scanner completeness" do
    it "keeps confirmable findings while marking the scan incomplete" do
      SecurityFixtures.database(File.join(@tmp,'db'),
                                'demo' => {
                                  'CVE-2020-0001.yml' => parse('patched_versions',['>= 0'])
                                },
                                'stable' => {
                                  'CVE-2020-0002.yml' => SecurityFixtures.advisory_text({'gem' => 'stable','patched_versions' => ['>= 2.0.0']})
                                })

      bundle  = SecurityFixtures.bundle(File.join(@tmp,'bundle'))
      database = Bundler::Audit::Database.new(File.join(@tmp,'db'))
      scanner  = Bundler::Audit::Scanner.new(bundle,'Gemfile.lock',database)

      report = scanner.report

      expect(report.vulnerable?).to be true
      expect(SecurityFixtures.evidence(report)).to eq(['CVE-2020-0002'])
      expect(report.results.first.gem.name).to eq('stable')
      expect(report.incomplete?).to be true
      expect(report.errors.length).to eq(1)
      expect(report.errors.first.scope).to eq('demo')
      expect(report.errors.first.path).to include('CVE-2020-0001.yml')
    end

    it "marks the scan incomplete even when no findings exist" do
      SecurityFixtures.database(File.join(@tmp,'db'),
                                'demo' => {
                                  'CVE-2020-0001.yml' => parse('patched_versions',['>= 0'])
                                })

      bundle  = SecurityFixtures.bundle(File.join(@tmp,'bundle'))
      database = Bundler::Audit::Database.new(File.join(@tmp,'db'))
      scanner  = Bundler::Audit::Scanner.new(bundle,'Gemfile.lock',database)

      report = scanner.report

      expect(report.results).to be_empty
      expect(report.vulnerable?).to be false
      expect(report.complete?).to be false
    end

    it "keeps a clean report complete when every advisory is trustworthy" do
      SecurityFixtures.database(File.join(@tmp,'db'),
                                'stable' => {
                                  'CVE-2020-0002.yml' => SecurityFixtures.advisory_text({'gem' => 'stable','patched_versions' => ['>= 1.0.0','< 1.0.0']})
                                })

      bundle  = SecurityFixtures.bundle(File.join(@tmp,'bundle'))
      database = Bundler::Audit::Database.new(File.join(@tmp,'db'))
      scanner  = Bundler::Audit::Scanner.new(bundle,'Gemfile.lock',database)

      report = scanner.report

      expect(report.results).to be_empty
      expect(report.vulnerable?).to be false
      expect(report.complete?).to be true
    end

    it "records the failure when a gem name cannot be looked up safely" do
      FileUtils.mkdir_p(File.join(@tmp,'bundle'))
      File.write(File.join(@tmp,'bundle','Gemfile.lock'), <<~LOCK)
        GEM
          remote: https://rubygems.org/
          specs:
            ../../outside (1.0.0)

        PLATFORMS
          ruby

        DEPENDENCIES
          ../../outside
      LOCK

      SecurityFixtures.database(File.join(@tmp,'db'),
                                'demo' => {'CVE-2020-0001.yml' => SecurityFixtures.advisory_text})

      database = Bundler::Audit::Database.new(File.join(@tmp,'db'))
      scanner  = Bundler::Audit::Scanner.new(File.join(@tmp,'bundle'),'Gemfile.lock',database)

      report = scanner.report

      expect(report.results).to be_empty
      expect(report.complete?).to be false
      expect(report.errors.first).to be_kind_of(Bundler::Audit::ScanError)
      expect(report.errors.first.scope).to eq('../../outside')
    end
  end

  describe "source completeness" do
    it "records a source which could not be inspected instead of dropping it" do
      bundle = SecurityFixtures.bundle(File.join(@tmp,'bundle'))
      db_dir = SecurityFixtures.database(File.join(@tmp,'db'),{})
      database = Bundler::Audit::Database.new(db_dir)
      scanner  = Bundler::Audit::Scanner.new(bundle,'Gemfile.lock',database)

      failing_source = Struct.new(:uri, :remotes).new('git://example.com/repo.git', [])
      stub_const('Bundler::Source::Git',failing_source.class)
      allow(scanner.lockfile).to receive(:sources).and_return([failing_source])
      allow(scanner).to receive(:internal_source?).and_raise(Errno::EACCES)

      errors = []
      scanner.scan_sources { |result| errors << result }

      expect(errors.length).to eq(1)
      expect(errors.first).to be_kind_of(Bundler::Audit::ScanError)
      expect(errors.first.code).to eq(:unchecked_source)
      expect(errors.first.scope).to eq(:sources)
    end
  end

  describe "report status" do
    it "does not call a scan vulnerable merely because it was incomplete" do
      report = Bundler::Audit::Report.new
      report << Bundler::Audit::ScanError.new('advisory could not be checked',scope: 'demo')

      expect(report.vulnerable?).to be false
      expect(report.complete?).to be false
      expect(report.errors.length).to eq(1)
    end

    it "exposes completeness in the JSON view" do
      report = Bundler::Audit::Report.new
      report << Bundler::Audit::ScanError.new('advisory could not be checked',scope: 'demo')

      hash = report.to_h

      expect(hash).to include(complete: false)
      expect(hash[:errors].length).to eq(1)
      expect(hash[:results]).to be_empty
    end

    it "does not print a clean message when the text format is incomplete" do
      report = Bundler::Audit::Report.new
      report << Bundler::Audit::ScanError.new('advisory could not be checked',scope: 'demo')

      output = StringIO.new
      cli = Bundler::Audit::CLI.new([],{})
      cli.extend Bundler::Audit::CLI::Formats::Text

      cli.print_report(report,output)

      expect(output.string).not_to include('No vulnerabilities found')
      expect(output.string).to include('Scan incomplete')
    end

    it "emits an error testcase in the JUnit view" do
      report = Bundler::Audit::Report.new
      report << Bundler::Audit::ScanError.new('advisory could not be checked',scope: 'demo')

      output = StringIO.new
      cli = Bundler::Audit::CLI.new([],{})
      cli.extend Bundler::Audit::CLI::Formats::Junit

      cli.print_report(report,output)

      expect(output.string).to include('complete="false"')
      expect(output.string).to include('<error')
      expect(output.string).to include('NOT CHECKED')
      expect(output.string).to match(%r{<testsuite [^>]*failures="0"[^>]*errors="1">})
      expect(output.string.scan('<testsuite ').length).to eq(1)
    end

    it "emits a complete=false marker in the JSON view when advisories were skipped" do
      report = Bundler::Audit::Report.new
      report << Bundler::Audit::ScanError.new('advisory could not be checked',scope: 'demo')

      output = StringIO.new
      cli = Bundler::Audit::CLI.new([],{})
      cli.extend Bundler::Audit::CLI::Formats::JSON

      cli.print_report(report,output)

      parsed = ::JSON.parse(output.string,symbolize_names: true)

      expect(parsed[:complete]).to be false
      expect(parsed[:errors].length).to eq(1)
      expect(parsed[:errors].first[:code]).to eq('unknown')
    end

    it "exits with status 2 for an incomplete scan and status 1 for a vulnerable scan" do
      bundle = SecurityFixtures.bundle(File.join(@tmp,'bundle'))
      db_dir = SecurityFixtures.database(File.join(@tmp,'db'),
                                         'demo' => {
                                           'CVE-2020-0001.yml' => parse('patched_versions',['>= 0'])
                                         })

      expect {
        Bundler::Audit::CLI.start(['check',bundle,'--database',db_dir,'--quiet'])
      }.to raise_error(SystemExit) do |error|
        expect(error.status).to eq(2)
      end

      db_dir = SecurityFixtures.database(File.join(@tmp,'vulnerable-db'),
                                         'demo' => {
                                           'CVE-2020-0001.yml' => SecurityFixtures.advisory_text
                                         })

      expect {
        Bundler::Audit::CLI.start(['check',bundle,'--database',db_dir,'--quiet'])
      }.to raise_error(SystemExit) do |error|
        expect(error.status).to eq(1)
      end
    end
  end
end
