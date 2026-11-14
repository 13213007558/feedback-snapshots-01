require 'spec_helper'
require 'bundler/audit/results/unaffected_gem'
require 'bundler/audit/locked_gem'

describe Bundler::Audit::Results::UnaffectedGem do
  let(:gem) do
    Bundler::Audit::LockedGem.new(
      name: 'test', version: Gem::Version.new('1.2.3'),
      platform: 'arm64-darwin', source_type: :rubygems,
      source: { 'type' => 'rubygems', 'remotes' => ['https://rubygems.org/'] }
    )
  end

  let(:advisory) { double('Advisory', id: 'CVE-3000-1234') }

  subject { described_class.new(gem, advisory, :platform) }

  describe '#initialize' do
    it 'sets gem, advisory and reason' do
      expect(subject.gem).to be(gem)
      expect(subject.advisory).to be(advisory)
      expect(subject.reason).to eq(:platform)
    end
  end

  describe '#to_h' do
    before { allow(advisory).to receive(:to_h).and_return({ id: advisory.id }) }

    it 'serializes the type, identity, advisory and reason' do
      hash = subject.to_h

      expect(hash[:type]).to eq(:unaffected_gem)
      expect(hash[:gem][:name]).to eq('test')
      expect(hash[:gem][:platform]).to eq('arm64-darwin')
      expect(hash[:advisory]).to eq({ id: 'CVE-3000-1234' })
      expect(hash[:reason]).to eq(:platform)
    end
  end

  describe '#to_s' do
    it 'returns the advisory id' do
      expect(subject.to_s).to eq('CVE-3000-1234')
    end
  end
end
