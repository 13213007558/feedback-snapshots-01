# frozen_string_literal: true

require 'spec_helper'
require 'support/keyring'
require 'support/policy_factory'

RSpec.describe ActChain::Gateway do
  include Support::PolicyFactory

  let(:keyring) { Support::Keyring.new }
  let(:factory) { Support::TokenFactory.new(keyring) }
  let(:actors) { %w[gw billing] }
  let(:verifier) do
    ActChain::Verifier.new(
      policy: build_policy,
      evidence_verifier: ActChain::EvidenceVerifier.new(keys: keyring.public_registry(actors))
    )
  end
  let(:gateway) do
    described_class.new(
      outer_key: keyring.outer_public,
      verifier: verifier,
      decode_options: { algorithms: %w[RS256], verify_iss: true, iss: 'idp.example', verify_aud: true, aud: audience }
    )
  end

  it 'passes a valid outer token through to chain validation' do
    token = factory.issue(sub: 'user', aud: audience, actors: actors)
    result = gateway.authenticate(token)

    expect(result).to be_valid
    expect(result).to be_fully_consented
  end

  it 'rejects a token whose outer signature cannot be verified' do
    token = factory.issue(sub: 'user', aud: audience, actors: actors)
    foreign_gateway = described_class.new(
      outer_key: Support::Keyring.new.outer_public,
      verifier: verifier,
      decode_options: { algorithms: %w[RS256] }
    )
    expect { foreign_gateway.authenticate(token) }.to raise_error(JWT::VerificationError)
  end

  it 'rejects a token failing a standard ruby-jwt claim (wrong issuer)' do
    token = factory.issue(sub: 'user', aud: audience, actors: actors)
    expect { gateway.authenticate(token) }.not_to raise_error

    strict = described_class.new(
      outer_key: keyring.outer_public,
      verifier: verifier,
      decode_options: { algorithms: %w[RS256], verify_iss: true, iss: 'someone-else' }
    )
    expect { strict.authenticate(token) }.to raise_error(JWT::InvalidIssuerError)
  end
end

RSpec.describe ActChain::AuthorizationDecision do
  include Support::PolicyFactory

  let(:keyring) { Support::Keyring.new }
  let(:factory) { Support::TokenFactory.new(keyring) }
  let(:verifier) { ActChain::Verifier.new(policy: build_policy) }

  it 'grants only permissions the original subject holds, never actor-added ones' do
    payload = JWT.decode(factory.issue(sub: 'user', aud: audience, actors: %w[gw billing]), nil, false).first
    result = verifier.inspect(payload)
    capabilities = { 'user' => %i[orders_read], 'billing' => %i[orders_delete] }
    decision = described_class.new(result, capabilities: capabilities)

    expect(decision.permit?(:orders_read)).to be(true)
    expect(decision.permit?(:orders_delete)).to be(false)
  end

  it 'denies everything when the chain is invalid, regardless of capabilities' do
    payload = JWT.decode(factory.issue(sub: 'user', aud: audience, actors: %w[gw attacker]), nil, false).first
    result = verifier.inspect(payload)
    decision = described_class.new(result, capabilities: { 'user' => %i[orders_read] })

    expect(decision.permit?(:orders_read)).to be(false)
    expect(decision.reason).to start_with('rejected:')
  end
end
