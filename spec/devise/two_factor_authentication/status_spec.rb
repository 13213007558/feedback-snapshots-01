require 'spec_helper'

describe ::Devise::TwoFactorAuthentication::Status do
  it 'reports anonymous sessions as not authenticated and not read-only' do
    status = described_class.anonymous
    expect(status).not_to be_authenticated
    expect(status).not_to be_read_only
    expect(status.prompt).to eq(:authenticate)
  end

  it 'reports legacy sessions as read-only and restricted' do
    status = described_class.legacy(fingerprint: 'fp')
    expect(status).to be_authenticated
    expect(status).to be_read_only
    expect(status).to be_restricted
    expect(status).to be_verification_required
    expect(status).not_to be_eligible_for_sensitive_actions
    expect(status.prompt).to eq(:verify_two_factor)
  end

  it 'reports confirmed sessions as eligible for sensitive actions' do
    status = described_class.confirmed(fingerprint: 'fp')
    expect(status).to be_authenticated
    expect(status).to be_verified
    expect(status).to be_eligible_for_sensitive_actions
    expect(status).not_to be_read_only
    expect(status.prompt).to be_nil
  end

  it 'reports a configuration change with a reverify prompt' do
    status = described_class.configuration_changed(fingerprint: 'new', stale: true)
    expect(status.level).to eq(:pending)
    expect(status).to be_configuration_changed
    expect(status).to be_stale
    expect(status.prompt).to eq(:reverify_two_factor)
    expect(status).not_to be_eligible_for_sensitive_actions
  end

  it 'raises on unknown levels' do
    expect { described_class.new(level: :bogus) }.to raise_error(ArgumentError)
  end
end
