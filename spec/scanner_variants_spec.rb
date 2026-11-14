require 'spec_helper'
require 'bundler/audit/scanner'
require 'json'

describe Scanner do
  let(:directory) { File.join('spec','bundle','platform_and_source_variants') }
  let(:database)  { Database.new(Fixtures::Database::PATH) }

  subject { described_class.new(directory, 'Gemfile.lock', database) }

  let(:results) { subject.scan.to_a }

  def select_result(kind, name, platform, source_type)
    results.find do |result|
      result.kind_of?(kind) &&
        result.gem.name == name &&
        result.gem.platform == platform &&
        result.gem.source_type == source_type
    end
  end

  describe 'platform and supply-source identity' do
    it 'keeps every locked variant in the report rather than collapsing them' do
      identities = results.map { |r|
        [r.gem.name, r.gem.platform, r.gem.source_type]
      }.uniq

      expect(identities.size).to eq(7)
    end

    it 'reports the linux platform variant as affected' do
      result = select_result(Bundler::Audit::Results::UnpatchedGem,
                             'platform-gem', 'x86_64-linux', :rubygems)

      expect(result).to_not be_nil
      expect(result.advisory.id).to eq('CVE-2026-0001')
    end

    it 'reports the ruby and darwin platform variants as explicitly unaffected' do
      %w[ruby arm64-darwin].each do |platform|
        result = select_result(Bundler::Audit::Results::UnaffectedGem,
                               'platform-gem', platform, :rubygems)

        expect(result).to_not be_nil
        expect(result.reason).to eq(:platform)
        expect(result.advisory.id).to eq('CVE-2026-0001')
      end
    end

    it 'does not remove unaffected variants when a sibling platform is affected' do
      platform_gem_results = results.select { |r| r.gem.name == 'platform-gem' }

      expect(platform_gem_results.size).to eq(3)
      expect(platform_gem_results.map(&:class).uniq).to match_array([
        Bundler::Audit::Results::UnpatchedGem,
        Bundler::Audit::Results::UnaffectedGem
      ])
    end

    it 'reports the rubygems source variant as affected' do
      result = select_result(Bundler::Audit::Results::UnpatchedGem,
                             'source-gem', 'ruby', :rubygems)

      expect(result).to_not be_nil
      expect(result.advisory.id).to eq('CVE-2026-0002')
    end

    it 'reports git and path source variants as inconclusive, not affected or unaffected' do
      [:git, :path].each do |source_type|
        result = select_result(Bundler::Audit::Results::InconclusiveGem,
                               'source-gem', 'ruby', source_type)

        expect(result).to_not be_nil
        expect(result.advisory.id).to eq('CVE-2026-0002')
        expect(result.evidence[:source_type]).to eq(source_type)
      end
    end

    it 'preserves distinct provenance evidence for the git and path variants' do
      git  = select_result(Bundler::Audit::Results::InconclusiveGem,
                           'source-gem', 'ruby', :git)
      path = select_result(Bundler::Audit::Results::InconclusiveGem,
                           'source-gem', 'ruby', :path)

      expect(git.gem.source['uri']).to start_with('https://github.com/')
      expect(git.gem.source['revision']).to_not be_nil
      expect(path.gem.source['path']).to eq('vendor/internal-gem')
    end

    it 'applies a legacy unrestricted advisory to every rubygems instance' do
      result = select_result(Bundler::Audit::Results::UnpatchedGem,
                             'legacy-gem', 'ruby', :rubygems)

      expect(result).to_not be_nil
      expect(result.advisory.id).to eq('CVE-2026-0003')
      expect(result.advisory.platform_restricted?).to be(false)
      expect(result.advisory.source_restricted?).to be(false)
    end

    it 'still reports the report as vulnerable due to affected instances' do
      expect(subject.report.vulnerable?).to be(true)
    end
  end

  describe 'machine-readable report' do
    let(:hash) { JSON.parse(JSON.generate(subject.report.to_h)) }

    it 'distinguishes the three verdicts by result type' do
      types = hash['results'].map { |r| r['type'] }.uniq

      expect(types).to include('unpatched_gem', 'unaffected_gem', 'inconclusive_gem')
    end

    it 'tags each result with the platform and source identity' do
      hash['results'].each do |result|
        gem = result['gem']

        expect(gem).to include('platform', 'source_type', 'source')
      end
    end

    it 'records the unaffected reason' do
      unaffected = hash['results'].find { |r| r['type'] == 'unaffected_gem' }

      expect(unaffected['reason']).to eq('platform')
    end

    it 'records inconclusive evidence explaining the unknown verdict' do
      inconclusive = hash['results'].find { |r| r['type'] == 'inconclusive_gem' }

      expect(inconclusive['evidence']['message']).to match(/cannot prove/i)
      expect(inconclusive['gem']['source']).to be_kind_of(Hash)
    end

    it 'keeps the affected, unaffected and inconclusive instances separate' do
      by_type = hash['results'].group_by { |r| r['type'] }

      affected_keys   = by_type['unpatched_gem'].map { |r| [r['gem']['name'], r['gem']['platform']] }
      unaffected_keys = by_type['unaffected_gem'].map { |r| [r['gem']['name'], r['gem']['platform']] }
      unknown_keys    = by_type['inconclusive_gem'].map { |r| [r['gem']['name'], r['gem']['source_type']] }

      expect(affected_keys).to include(['platform-gem', 'x86_64-linux'])
      expect(unaffected_keys).to include(['platform-gem', 'arm64-darwin'])
      expect(unknown_keys).to include(['source-gem', 'git'])
      expect(unknown_keys).to include(['source-gem', 'path'])
    end
  end
end
