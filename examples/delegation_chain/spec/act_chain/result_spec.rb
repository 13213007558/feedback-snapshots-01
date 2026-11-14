# frozen_string_literal: true

require 'spec_helper'
require 'support/policy_factory'

RSpec.describe ActChain::Result do
  include Support::PolicyFactory

  let(:verifier) { ActChain::Verifier.new(policy: build_policy) }

  it 'treats a token without act as valid and neutral rather than consent-unverified' do
    result = verifier.inspect({ 'sub' => 'user', 'aud' => audience })

    expect(result).to be_valid
    expect(result).not_to be_delegated
    expect(result).to be_fully_consented
    expect(result.verdict).to eq(:not_delegated)
    expect(result.hop_evidence).to be_empty
  end
end
