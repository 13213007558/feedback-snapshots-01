require 'spec_helper'
require 'bundler/audit/advisory'
require 'bundler/audit/locked_gem'

describe Bundler::Audit::Advisory do
  def locked_gem(platform: 'ruby', source_type: :rubygems, source: nil, version: '1.2.3')
    source ||= case source_type
               when :git  then { 'type' => 'git', 'uri' => 'https://example.com/x.git' }
               when :path then { 'type' => 'path', 'path' => 'vendor/x' }
               else            { 'type' => 'rubygems', 'remotes' => ['https://rubygems.org/'] }
               end

    Bundler::Audit::LockedGem.new(
      name:        'test',
      version:     Gem::Version.new(version),
      platform:    platform,
      source_type: source_type,
      source:      source
    )
  end

  def advisory(**fields)
    described_class.new.tap do |adv|
      adv.patched_versions = fields[:patched_versions] || [Gem::Requirement.new('>= 1.3.0')]
      adv.unaffected_versions = fields[:unaffected_versions] || []
      adv.affected_platforms = fields[:affected_platforms] || []
      adv.affected_sources = fields[:affected_sources] || []
    end
  end

  describe '#platform_restricted? / #source_restricted?' do
    it 'is unrestricted by default' do
      adv = advisory

      expect(adv.platform_restricted?).to be(false)
      expect(adv.source_restricted?).to be(false)
    end

    it 'detects platform restrictions' do
      expect(advisory(affected_platforms: ['x86_64-linux']).platform_restricted?).to be(true)
    end

    it 'detects source restrictions' do
      expect(advisory(affected_sources: ['rubygems']).source_restricted?).to be(true)
    end
  end

  describe '#affects_platform?' do
    let(:adv) { advisory(affected_platforms: ['x86_64-linux']) }

    it 'matches the restricted platform' do
      expect(adv.affects_platform?(locked_gem(platform: 'x86_64-linux'))).to be(true)
    end

    it 'excludes other platforms' do
      expect(adv.affects_platform?(locked_gem(platform: 'arm64-darwin'))).to be(false)
    end

    it 'treats every platform as in scope when unrestricted' do
      unrestricted = advisory

      expect(unrestricted.affects_platform?(locked_gem(platform: 'arm64-darwin'))).to be(true)
    end
  end

  describe '#affects_source?' do
    it 'matches a plain source type restriction' do
      adv = advisory(affected_sources: ['rubygems'])

      expect(adv.affects_source?(locked_gem(source_type: :rubygems))).to be(true)
      expect(adv.affects_source?(locked_gem(source_type: :git))).to be(false)
    end

    it 'matches a hash restriction with a specific git uri' do
      adv = advisory(affected_sources: [
        { 'type' => 'git', 'uri' => 'https://example.com/x.git' }
      ])

      matching = locked_gem(source_type: :git,
                           source: { 'type' => 'git', 'uri' => 'https://example.com/x.git' })
      other = locked_gem(source_type: :git,
                         source: { 'type' => 'git', 'uri' => 'https://example.com/y.git' })

      expect(adv.affects_source?(matching)).to be(true)
      expect(adv.affects_source?(other)).to be(false)
    end

    it 'treats every source as in scope when unrestricted' do
      expect(advisory.affects_source?(locked_gem(source_type: :path))).to be(true)
    end
  end

  describe '#verdict_for' do
    it 'returns :affected for an in-scope vulnerable rubygems instance' do
      adv = advisory

      expect(adv.verdict_for(locked_gem)).to eq(:affected)
    end

    it 'returns :unaffected for a patched version' do
      adv = advisory

      expect(adv.verdict_for(locked_gem(version: '1.4.0'))).to eq(:unaffected)
    end

    it 'returns :unaffected for a platform outside the restricted scope' do
      adv = advisory(affected_platforms: ['x86_64-linux'])

      expect(adv.verdict_for(locked_gem(platform: 'arm64-darwin'))).to eq(:unaffected)
    end

    it 'returns :unaffected for a rubygems source outside the restricted scope' do
      adv = advisory(affected_sources: ['git'])

      expect(adv.verdict_for(locked_gem(source_type: :rubygems))).to eq(:unaffected)
    end

    it 'returns :unknown for git sources even when name and version match' do
      adv = advisory

      expect(adv.verdict_for(locked_gem(source_type: :git))).to eq(:unknown)
    end

    it 'returns :unknown for path sources even when name and version match' do
      adv = advisory

      expect(adv.verdict_for(locked_gem(source_type: :path))).to eq(:unknown)
    end

    it 'returns :unknown for git sources even when the advisory excludes that source' do
      adv = advisory(affected_sources: ['rubygems'])

      expect(adv.verdict_for(locked_gem(source_type: :git))).to eq(:unknown)
    end

    it 'returns :unaffected (not unknown) for a patched git source' do
      adv = advisory

      expect(adv.verdict_for(locked_gem(source_type: :git, version: '1.4.0'))).to eq(:unaffected)
    end
  end
end
