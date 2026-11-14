require 'spec_helper'
require 'bundler/audit/diff'

describe Bundler::Audit::Diff do
  let(:sample_root) { File.expand_path('../examples/diff',__dir__) }

  let(:database_before) { Database.new(File.join(sample_root,'db_before')) }
  let(:database_after)  { Database.new(File.join(sample_root,'db_after')) }

  let(:before) do
    Bundler::Audit::Diff::Snapshot.capture(File.join(sample_root,'before'),
                                           database: database_before)
  end

  let(:after) do
    Bundler::Audit::Diff::Snapshot.capture(File.join(sample_root,'after'),
                                           database: database_after)
  end

  let(:diff) { described_class.compare(before,after) }

  def entries_for(gem_name)
    diff.entries.select do |entry|
      entry.finding.type == :unpatched_gem &&
        entry.finding.gem_name == gem_name
    end
  end

  describe Bundler::Audit::Diff::Snapshot do
    it "binds the identity of the lockfile" do
      expect(before.lockfile_sha256).to match(/\A[0-9a-f]{64}\z/)
      expect(before.lockfile_sha256).to_not eq(after.lockfile_sha256)
    end

    it "binds the identity of the advisory database" do
      expect(before.database_sha256).to match(/\A[0-9a-f]{64}\z/)
      expect(before.database_sha256).to_not eq(after.database_sha256)
    end

    it "binds the identity of the ignore configuration" do
      expect(before.config_sha256).to match(/\A[0-9a-f]{64}\z/)
      expect(before.config_sha256).to_not eq(after.config_sha256)
    end

    it "keeps the platform of locked gems" do
      expect(before.spec('ffi','x64-mingw32').version.to_s).to eq('1.9.23')
    end
  end

  describe '.compare' do
    it "classifies a finding on a newly introduced dependency" do
      entry = entries_for('bar').first

      expect(entry.classification).to eq(:new_dependency)
      expect(entry.direction).to eq(:appeared)
      expect(entry.evidence[:before_version]).to be_nil
      expect(entry.evidence[:after_version]).to eq('1.0.0')
    end

    it "classifies a newly disclosed advisory on an unchanged dependency" do
      entry = entries_for('rack').first

      expect(entry.classification).to eq(:newly_disclosed)
      expect(entry.direction).to eq(:appeared)
      expect(entry.evidence[:database_before_sha256]).to eq(before.database_sha256)
      expect(entry.evidence[:database_after_sha256]).to eq(after.database_sha256)
    end

    it "classifies a finding caused by revised advisory version ranges" do
      entry = entries_for('json').first

      expect(entry.classification).to eq(:advisory_revised)
      expect(entry.direction).to eq(:appeared)
      expect(entry.evidence[:before_patched_versions]).to eq(['>= 1.7.0'])
      expect(entry.evidence[:after_patched_versions]).to eq(['>= 2.4.0'])
    end

    it "classifies a finding caused by an expired exemption" do
      entry = entries_for('nokogiri').first

      expect(entry.classification).to eq(:exemption_expired)
      expect(entry.direction).to eq(:appeared)
      expect(entry.evidence[:ignored_in_before]).to be(true)
      expect(entry.evidence[:ignored_in_after]).to be(false)
    end

    it "classifies a disappeared finding that was genuinely fixed" do
      entry = entries_for('ffi').first

      expect(entry.classification).to eq(:fixed)
      expect(entry.direction).to eq(:disappeared)
      expect(entry.evidence[:before_version]).to eq('1.9.23')
      expect(entry.evidence[:after_version]).to eq('1.9.24')
    end

    it "keeps findings that cannot be explained as unexplained" do
      entry = entries_for('mystery').first

      expect(entry.classification).to eq(:unexplained)
      expect(entry.direction).to eq(:disappeared)
      expect(entry.evidence[:advisory_absent_in_after_database]).to be(true)
    end

    it "does not create differences for renumbered or retitled advisories" do
      expect(entries_for('baz')).to be_empty
    end

    it "attaches closure conditions to appeared findings" do
      entry = entries_for('rack').first

      expect(entry.closure[:upgrade_to][:patched_versions]).to eq(['>= 2.0.9'])
      expect(entry.closure[:suppress_with]).to include('CVE-2026-1001')
    end
  end

  describe '#to_h' do
    subject(:hash) { diff.to_h }

    it "records the identities of both snapshots" do
      expect(hash[:before][:lockfile][:sha256]).to eq(before.lockfile_sha256)
      expect(hash[:after][:database][:sha256]).to eq(after.database_sha256)
      expect(hash[:before][:config][:sha256]).to eq(before.config_sha256)
    end

    it "locates the original findings without losing the platform" do
      entry = hash[:entries].find do |e|
        e[:finding][:type] == :unpatched_gem &&
          e[:finding][:gem][:name] == 'ffi'
      end

      expect(entry[:finding][:gem][:platform]).to eq('x64-mingw32')
      expect(entry[:finding][:gem][:version]).to eq('1.9.23')
      expect(entry[:finding][:advisory][:id]).to eq('CVE-2018-1000201')
    end

    it "summarizes the classifications" do
      expect(hash[:summary]).to eq(
        new_dependency:    1,
        newly_disclosed:   1,
        advisory_revised:  1,
        exemption_expired: 1,
        fixed:             1,
        unexplained:       1
      )
    end
  end

  describe '#regressions?' do
    it "is true when findings appeared" do
      expect(diff.regressions?).to be(true)
    end

    it "is false when nothing appeared" do
      expect(described_class.compare(before,before).regressions?).to be(false)
    end
  end

  context "when comparing a snapshot with itself" do
    it "produces no entries" do
      expect(described_class.compare(before,before).entries).to be_empty
    end
  end
end
