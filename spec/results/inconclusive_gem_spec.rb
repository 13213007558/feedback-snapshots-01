require 'spec_helper'
require 'bundler/audit/results/inconclusive_gem'
require 'bundler/audit/locked_gem'

describe Bundler::Audit::Results::InconclusiveGem do
  let(:gem) do
    Bundler::Audit::LockedGem.new(
      name: 'test', version: Gem::Version.new('1.2.3'),
      platform: 'ruby', source_type: :git,
      source: { 'type' => 'git', 'uri' => 'https://example.com/x.git', 'revision' => 'abc' }
    )
  end

  let(:advisory) { double('Advisory', id: 'CVE-3000-1234') }

  subject { described_class.new(gem, advisory) }

  describe '#initialize' do
    it 'sets gem and advisory' do
      expect(subject.gem).to be(gem)
      expect(subject.advisory).to be(advisory)
    end

    it 'builds evidence describing why no conclusion is possible' do
      expect(subject.evidence[:source_type]).to eq(:git)
      expect(subject.evidence[:source]['uri']).to eq('https://example.com/x.git')
      expect(subject.evidence[:message]).to match(/cannot prove/i)
    end
  end

  describe '#to_h' do
    before { allow(advisory).to receive(:to_h).and_return({ id: advisory.id }) }

    it 'serializes the type, identity, advisory and evidence' do
      hash = subject.to_h

      expect(hash[:type]).to eq(:inconclusive_gem)
      expect(hash[:gem][:source_type]).to eq(:git)
      expect(hash[:advisory]).to eq({ id: 'CVE-3000-1234' })
      expect(hash[:evidence][:message]).to match(/cannot prove/i)
    end
  end

  describe '#to_s' do
    it 'returns the advisory id' do
      expect(subject.to_s).to eq('CVE-3000-1234')
    end
  end
end
