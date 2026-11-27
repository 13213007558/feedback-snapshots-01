require 'spec_helper'
require 'active_model'

class TwoFactorConfigurationTrackingDouble
  extend ::ActiveModel::Callbacks
  include ::ActiveModel::Validations::Callbacks
  extend ::Devise::Models

  attr_accessor :otp_secret, :otp_backup_codes, :otp_required_for_login

  def self.encrypts(*_attrs); end

  define_model_callbacks :update

  devise :two_factor_authenticatable

  def save!(_ = nil)
    true
  end
end

describe ::Devise::Models::TwoFactorConfigurationTracking do
  subject { TwoFactorConfigurationTrackingDouble.new }

  before :each do
    subject.otp_secret = 'JBSWY3DPEHPK3PXP'
    subject.otp_required_for_login = true
    subject.otp_backup_codes = []
  end

  it 'exposes a stable fingerprint for the current configuration' do
    expect(subject.two_factor_configuration_fingerprint).to eq(subject.two_factor_configuration_fingerprint)
  end

  it 'changes when the OTP secret rotates' do
    before = subject.two_factor_configuration_fingerprint
    subject.otp_secret = 'KRSXG5CTMVRXEZLU'
    expect(subject.two_factor_configuration_fingerprint).not_to eq(before)
  end

  it 'changes when the backup codes rotate' do
    before = subject.two_factor_configuration_fingerprint
    subject.otp_backup_codes = ['$2a$12$abcdefghijklmnopqrstuv']
    expect(subject.two_factor_configuration_fingerprint).not_to eq(before)
  end

  it 'is distinct for different accounts with different secrets' do
    other = TwoFactorConfigurationTrackingDouble.new
    other.otp_secret = 'MFRGGZDFMZTWQ2LK'
    other.otp_required_for_login = true
    other.otp_backup_codes = []

    expect(subject.two_factor_configuration_fingerprint).not_to eq(other.two_factor_configuration_fingerprint)
  end
end
