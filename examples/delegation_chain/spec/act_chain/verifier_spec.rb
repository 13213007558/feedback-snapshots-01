# frozen_string_literal: true

require 'spec_helper'
require 'support/keyring'
require 'support/policy_factory'

RSpec.describe ActChain::Verifier do
  include Support::PolicyFactory

  let(:keyring) { Support::Keyring.new }
  let(:factory) { Support::TokenFactory.new(keyring) }
  let(:actors) { %w[gw billing shipping] }
  let(:evidence) { ActChain::EvidenceVerifier.new(keys: keyring.public_registry(actors)) }

  def payload_for(**kwargs)
    token = factory.issue(**kwargs)
    JWT.decode(token, nil, false).first
  end

  context 'topology rules' do
    subject(:verifier) { described_class.new(policy: build_policy) }

    it 'accepts a well-formed in-tenant chain on allowed edges' do
      payload = payload_for(sub: 'user', aud: audience, actors: actors)
      result = verifier.inspect(payload)

      expect(result).to be_valid
      expect(result.verdict).to eq(:valid_but_consent_unverified)
      expect(result.original_subject).to eq('user')
    end

    it 'rejects a chain deeper than max_depth' do
      payload = payload_for(sub: 'user', aud: audience, actors: %w[gw billing shipping gw])
      result = verifier.inspect(payload)

      expect(result.policy_errors.map(&:class)).to include(ActChain::DepthExceeded)
    end

    it 'rejects repeated subjects as a delegation loop' do
      payload = payload_for(sub: 'user', aud: audience, actors: %w[gw billing gw])
      result = verifier.inspect(payload)

      expect(result.policy_errors.map(&:class)).to include(ActChain::DuplicateSubject)
    end

    it 'rejects edges absent from the allow list even without tenant or audience issues' do
      payload = payload_for(sub: 'user', aud: audience, actors: %w[shipping])
      result = verifier.inspect(payload)

      expect(result.policy_errors.map(&:class)).to include(ActChain::EdgeNotAllowed)
    end

    it 'rejects cross-tenant jumps by default' do
      payload = payload_for(sub: 'user', aud: audience, actors: %w[gw attacker])
      classes = verifier.inspect(payload).policy_errors.map(&:class)

      expect(classes).to include(ActChain::CrossTenantJump)
      expect(classes).to include(ActChain::EdgeNotAllowed)
      expect(classes).to include(ActChain::AudienceMismatch)
    end

    it 'rejects any path subject not authorized for the final audience' do
      policy = build_policy(
        audience_subjects: { audience => %w[user gw] }
      )
      payload = payload_for(sub: 'user', aud: audience, actors: %w[gw billing])
      result = described_class.new(policy: policy).inspect(payload)

      expect(result.policy_errors.map(&:class)).to include(ActChain::AudienceMismatch)
    end

    it 'verify! raises the first hard error while inspect collects all' do
      payload = payload_for(sub: 'user', aud: audience, actors: %w[gw attacker])
      expect { verifier.verify!(payload) }.to raise_error(ActChain::Error)
    end
  end

  context 'per-hop consent evidence' do
    it 'marks every hop verified when each actor signed valid consent' do
      verifier = described_class.new(policy: build_policy, evidence_verifier: evidence)
      payload = payload_for(sub: 'user', aud: audience, actors: actors, evidence: true)
      result = verifier.inspect(payload)

      expect(result).to be_fully_consented
      expect(result.verdict).to eq(:verified_consent)
      expect(result.hop_evidence.map { |entry| entry[:status] }).to eq(%i[verified verified verified])
    end

    it 'keeps an unverifiable hop as evidence instead of fabricating trust' do
      verifier = described_class.new(policy: build_policy, evidence_verifier: evidence)
      payload = payload_for(sub: 'user', aud: audience, actors: actors, evidence: false)
      result = verifier.inspect(payload)

      expect(result).to be_valid
      expect(result).not_to be_fully_consented
      expect(result.unverified_hops.first[:status]).to eq(:none)
      expect(result.unverified_hops.first[:reason]).to include('no act_token evidence')
    end

    it 'flags evidence signed by an unregistered key as unverified' do
      other_keyring = Support::Keyring.new
      other_factory = Support::TokenFactory.new(other_keyring)
      foreign_token = other_factory.issue(sub: 'user', aud: audience, actors: actors)
      foreign_payload = JWT.decode(foreign_token, nil, false).first

      verifier = described_class.new(policy: build_policy, evidence_verifier: evidence)
      result = verifier.inspect(foreign_payload)

      expect(result).to be_valid
      expect(result).not_to be_fully_consented
      expect(result.unverified_hops.first[:status]).to eq(:unverified)
    end

    it 'in strict mode turns missing consent into a hard rejection' do
      verifier = described_class.new(policy: build_policy, evidence_verifier: evidence, strict_consent: true)
      payload = payload_for(sub: 'user', aud: audience, actors: actors, evidence: false)
      result = verifier.inspect(payload)

      expect(result.policy_errors.map(&:class)).to include(ActChain::UnverifiedEvidence)
    end
  end
end
