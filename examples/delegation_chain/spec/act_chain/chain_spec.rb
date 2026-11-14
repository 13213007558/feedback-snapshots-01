# frozen_string_literal: true

require 'spec_helper'

RSpec.describe ActChain::Chain do
  describe '.from_payload' do
    it 'flattens a nested act claim into an ordered path' do
      payload = { 'sub' => 'user', 'act' => { 'sub' => 'gw', 'act' => { 'sub' => 'billing' } } }
      chain = described_class.from_payload(payload)

      expect(chain.path).to eq(%w[user gw billing])
      expect(chain.depth).to eq(2)
      expect(chain.edges).to eq([%w[user gw], %w[gw billing]])
      expect(chain).to be_delegated
    end

    it 'treats a token without act as depth zero' do
      chain = described_class.from_payload({ 'sub' => 'user' })
      expect(chain.path).to eq(['user'])
      expect(chain.depth).to eq(0)
      expect(chain).not_to be_delegated
    end

    it 'preserves the raw node and any evidence token on each step' do
      payload = { 'sub' => 'user', 'act' => { 'sub' => 'gw', 'act_token' => 'eyJ.x.y' } }
      step = described_class.from_payload(payload).steps.first

      expect(step.subject).to eq('gw')
      expect(step.evidence_token).to eq('eyJ.x.y')
      expect(step.raw).to eq(payload['act'])
      expect(step).to be_evidence
    end

    it 'raises MalformedChain when an act node is not an object' do
      payload = { 'sub' => 'user', 'act' => 'not-an-object' }
      expect { described_class.from_payload(payload) }.to raise_error(ActChain::MalformedChain)
    end

    it 'raises MalformedChain when an act node lacks sub' do
      payload = { 'sub' => 'user', 'act' => { 'act' => { 'sub' => 'gw' } } }
      expect { described_class.from_payload(payload) }.to raise_error(ActChain::MalformedChain)
    end

    it 'reports duplicate subjects for a loop' do
      payload = { 'sub' => 'user', 'act' => { 'sub' => 'gw', 'act' => { 'sub' => 'gw' } } }
      expect(described_class.from_payload(payload).duplicate_subjects).to eq(['gw'])
    end
  end
end
