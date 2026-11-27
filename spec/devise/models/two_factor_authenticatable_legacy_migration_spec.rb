require 'spec_helper'
require 'active_record'

ActiveRecord::Base.establish_connection(adapter: 'sqlite3', database: ':memory:')

ActiveRecord::Schema.verbose = false
ActiveRecord::Schema.define do
  create_table :otp_migration_users, force: true do |t|
    t.string  :otp_secret
    t.string  :encrypted_otp_secret
    t.string  :encrypted_otp_secret_iv
    t.string  :encrypted_otp_secret_salt
    t.integer :consumed_timestep
    t.boolean :otp_required_for_login, default: true, null: false
    t.timestamps
  end
end

ActiveRecord::Encryption.configure(
  primary_key: '0' * 32,
  deterministic_key: '1' * 32,
  key_derivation_salt: '2' * 32
)

# A synthetic user record holding an OTP secret stored by devise-two-factor
# 4.x in the legacy `encrypted_otp_secret` columns (attr_encrypted gem,
# AES-256-GCM), alongside the new Rails encrypted `otp_secret` attribute.
class OtpMigrationUser < ActiveRecord::Base
  extend Devise::Models

  LEGACY_ENCRYPTION_KEY = 'legacy-otp-secret-encryption-key'

  devise :two_factor_authenticatable, otp_secret_encryption_key: LEGACY_ENCRYPTION_KEY

  private

  # Decrypts the legacy `encrypted_otp_secret` attribute as described in
  # UPGRADING.md for installs migrated from devise-two-factor 4.x.
  def legacy_otp_secret
    return nil unless self[:encrypted_otp_secret]
    return nil unless self.class.otp_secret_encryption_key

    hmac_iterations = 2000 # a default set by the Encryptor gem
    key = self.class.otp_secret_encryption_key
    salt = Base64.decode64(encrypted_otp_secret_salt)
    iv = Base64.decode64(encrypted_otp_secret_iv)

    raw_cipher_text = Base64.decode64(encrypted_otp_secret)
    cipher_text = raw_cipher_text[0..-17]
    auth_tag = raw_cipher_text[-16..-1]

    cipher = OpenSSL::Cipher.new('aes-256-gcm')
    cipher.decrypt
    cipher.key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(key, salt, hmac_iterations, cipher.key_len)
    cipher.iv = iv
    cipher.auth_tag = auth_tag
    cipher.auth_data = ''

    cipher.update(cipher_text) + cipher.final
  end
end

describe ::Devise::Models::TwoFactorAuthenticatable, 'legacy OTP secret storage migration' do
  let(:otp_secret) { '2z6hxkdwi3uvrnpn' }
  let(:totp) { ROTP::TOTP.new(otp_secret) }
  let(:current_otp) { totp.at(Time.now) }
  let(:current_timestep) { Time.now.to_i / totp.interval }

  before :each do
    travel_to(Time.now)
  end

  after :each do
    travel_back
  end

  # Encrypts a secret the way the attr_encrypted gem did for devise-two-factor
  # 4.x (AES-256-GCM, PBKDF2-HMAC-SHA1 key derivation with 2000 iterations).
  def legacy_encrypt_otp_secret(plaintext)
    cipher = OpenSSL::Cipher.new('aes-256-gcm')
    cipher.encrypt
    salt = SecureRandom.random_bytes(16)
    iv = cipher.random_iv
    cipher.key = OpenSSL::PKCS5.pbkdf2_hmac_sha1(OtpMigrationUser::LEGACY_ENCRYPTION_KEY, salt, 2000, cipher.key_len)
    cipher.iv = iv
    cipher.auth_data = ''
    cipher_text = cipher.update(plaintext) + cipher.final

    {
      encrypted_otp_secret: Base64.strict_encode64(cipher_text + cipher.auth_tag),
      encrypted_otp_secret_iv: Base64.strict_encode64(iv),
      encrypted_otp_secret_salt: Base64.strict_encode64(salt)
    }
  end

  def raw_stored_otp_secret(user)
    OtpMigrationUser.connection.select_value("SELECT otp_secret FROM otp_migration_users WHERE id = #{user.id}")
  end

  context 'with a secret stored only in the legacy format' do
    let!(:user) do
      OtpMigrationUser.create!(legacy_encrypt_otp_secret(otp_secret))
    end

    it 'reads the secret from the legacy columns' do
      expect(user[:otp_secret]).to be_nil
      expect(user.otp_secret).to eq(otp_secret)
    end

    context 'given a valid OTP' do
      it 'establishes the session, records the consumption and upgrades the storage format' do
        expect(user.validate_and_consume_otp!(current_otp)).to be true

        user.reload
        expect(user.consumed_timestep).to eq(current_timestep)
        expect(user[:otp_secret]).to eq(otp_secret)
        expect(raw_stored_otp_secret(user)).not_to eq(otp_secret)
        expect(user.otp_secret).to eq(otp_secret)
      end

      it 'leaves the legacy columns untouched' do
        legacy_values = user.attributes.slice('encrypted_otp_secret', 'encrypted_otp_secret_iv', 'encrypted_otp_secret_salt')

        user.validate_and_consume_otp!(current_otp)

        expect(user.reload.attributes.slice('encrypted_otp_secret', 'encrypted_otp_secret_iv', 'encrypted_otp_secret_salt')).to eq(legacy_values)
      end

      it 'rejects a replay of the consumed code' do
        expect(user.validate_and_consume_otp!(current_otp)).to be true

        other_session = OtpMigrationUser.find(user.id)
        expect(other_session.validate_and_consume_otp!(current_otp)).to be false
      end
    end

    context 'given an invalid OTP' do
      let(:out_of_drift_otp) { totp.at(Time.now + (OtpMigrationUser.otp_allowed_drift * 2)) }

      it 'does not establish the session and keeps the legacy storage' do
        expect(user.validate_and_consume_otp!(out_of_drift_otp)).to be false

        user.reload
        expect(user.consumed_timestep).to be_nil
        expect(user[:otp_secret]).to be_nil
        expect(user.otp_secret).to eq(otp_secret)
      end
    end

    context 'when the save fails after the OTP verified' do
      before :each do
        allow(user).to receive(:save!).and_raise(ActiveRecord::RecordNotSaved)
      end

      it 'does not establish the session' do
        expect { user.validate_and_consume_otp!(current_otp) }.to raise_error(ActiveRecord::RecordNotSaved)
      end

      it 'persists neither the consumption nor the format upgrade' do
        user.validate_and_consume_otp!(current_otp) rescue ActiveRecord::RecordNotSaved

        user.reload
        expect(user.consumed_timestep).to be_nil
        expect(user[:otp_secret]).to be_nil
        expect(raw_stored_otp_secret(user)).to be_nil
        expect(user.otp_secret).to eq(otp_secret)
      end

      context 'and another session submits the same code within the time window' do
        it 'establishes the session and completes consumption and migration on retry' do
          user.validate_and_consume_otp!(current_otp) rescue ActiveRecord::RecordNotSaved

          other_session = OtpMigrationUser.find(user.id)
          expect(other_session.validate_and_consume_otp!(current_otp)).to be true

          other_session.reload
          expect(other_session.consumed_timestep).to eq(current_timestep)
          expect(other_session[:otp_secret]).to eq(otp_secret)
          expect(raw_stored_otp_secret(other_session)).not_to eq(otp_secret)
        end
      end
    end
  end

  context 'with a secret already stored in the new format' do
    let!(:user) do
      OtpMigrationUser.create!(otp_secret: otp_secret)
    end

    it 'verifies through the original path without touching the legacy columns' do
      expect(user).not_to receive(:legacy_otp_secret)
      expect(user.validate_and_consume_otp!(current_otp)).to be true

      user.reload
      expect(user.consumed_timestep).to eq(current_timestep)
      expect(user[:otp_secret]).to eq(otp_secret)
    end
  end
end
