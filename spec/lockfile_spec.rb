require 'spec_helper'
require 'bundler/audit/lockfile'

describe Bundler::Audit::Lockfile do
  let(:directory) { File.join('spec','bundle','platform_and_source_variants') }
  let(:contents)  { File.read(File.join(directory,'Gemfile.lock')) }

  subject { described_class.parse(contents) }

  describe '#platforms' do
    it 'parses the PLATFORMS section' do
      expect(subject.platforms).to eq(['ruby', 'arm64-darwin', 'x86_64-linux'])
    end
  end

  describe '#gems' do
    it 'preserves every platform and supply-source variant' do
      expect(subject.gems.size).to eq(7)
    end

    it 'keeps all three platform variants of platform-gem' do
      platforms = subject.gems.select { |g| g.name == 'platform-gem' }.map(&:platform)

      expect(platforms).to eq(['ruby', 'arm64-darwin', 'x86_64-linux'])
    end

    it 'keeps the rubygems, git and path copies of the same named gem' do
      source_gems = subject.gems.select { |g| g.name == 'source-gem' }

      expect(source_gems.map(&:source_type)).to eq([:git, :path, :rubygems])
    end

    it 'records git provenance evidence' do
      git_gem = subject.gems.find { |g| g.name == 'source-gem' && g.git? }

      expect(git_gem.source).to eq(
        'type'     => 'git',
        'uri'      => 'https://github.com/example/source-gem.git',
        'revision' => '0123456789abcdef0123456789abcdef01234567',
        'ref'      => 'main'
      )
    end

    it 'records path provenance evidence' do
      path_gem = subject.gems.find { |g| g.name == 'source-gem' && g.path? }

      expect(path_gem.source).to eq(
        'type' => 'path',
        'path' => 'vendor/internal-gem'
      )
    end

    it 'records rubygems remote evidence' do
      gem_gem = subject.gems.find { |g| g.name == 'source-gem' && g.rubygems? }

      expect(gem_gem.source).to eq(
        'type'    => 'rubygems',
        'remotes' => ['https://rubygems.org/']
      )
    end

    it 'parses gem versions as Gem::Version' do
      expect(subject.gems.map(&:version)).to all(be_kind_of(Gem::Version))
    end
  end
end
