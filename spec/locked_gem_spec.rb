require 'spec_helper'
require 'bundler/audit/locked_gem'

describe Bundler::Audit::LockedGem do
  def build(**kwargs)
    defaults = {
      name:        'test',
      version:     Gem::Version.new('1.2.3'),
      platform:    'ruby',
      source_type: described_class::RUBYGEMS,
      source:      { 'type' => 'rubygems', 'remotes' => ['https://rubygems.org/'] }
    }

    described_class.new(**defaults.merge(kwargs))
  end

  describe '#rubygems? / #git? / #path? / #unverifiable_source?' do
    it 'treats rubygems as verifiable' do
      gem = build(source_type: described_class::RUBYGEMS)

      expect(gem.rubygems?).to be(true)
      expect(gem.git?).to be(false)
      expect(gem.path?).to be(false)
      expect(gem.unverifiable_source?).to be(false)
    end

    it 'treats git as unverifiable' do
      gem = build(source_type: described_class::GIT,
                  source: { 'type' => 'git', 'uri' => 'https://example.com/x.git' })

      expect(gem.git?).to be(true)
      expect(gem.unverifiable_source?).to be(true)
    end

    it 'treats path as unverifiable' do
      gem = build(source_type: described_class::PATH,
                  source: { 'type' => 'path', 'path' => 'vendor/x' })

      expect(gem.path?).to be(true)
      expect(gem.unverifiable_source?).to be(true)
    end
  end

  describe '#identity' do
    it 'distinguishes platform variants sharing name and version' do
      darwin = build(platform: 'arm64-darwin')
      linux  = build(platform: 'x86_64-linux')

      expect(darwin.identity).to_not eq(linux.identity)
      expect(darwin).to_not eq(linux)
    end

    it 'distinguishes source variants sharing name, version and platform' do
      rubygems = build
      git = build(source_type: described_class::GIT,
                  source: { 'type' => 'git', 'uri' => 'https://example.com/x.git' })

      expect(rubygems.identity).to_not eq(git.identity)
      expect(rubygems).to_not eq(git)
    end
  end

  describe '#to_h' do
    it 'exposes the platform and supply-source identity with evidence' do
      gem = build(platform: 'arm64-darwin')

      expect(gem.to_h).to eq(
        name:        'test',
        version:     Gem::Version.new('1.2.3'),
        platform:    'arm64-darwin',
        source_type: :rubygems,
        source:      { 'type' => 'rubygems', 'remotes' => ['https://rubygems.org/'] }
      )
    end
  end
end
