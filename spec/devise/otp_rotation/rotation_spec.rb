require 'spec_helper'

module DeviseTwoFactor
  module OtpRotation
    # Deterministic TOTP stand-in that emits the same code at every timestep
    # for a given secret. Real ROTP time-window semantics are exercised in the
    # non-scripted examples; this only forces two distinct secrets to collide.
    class ScriptedTotp
      attr_reader :secret, :interval

      def initialize(secret, interval: 30, code: '424242')
        @secret = secret
        @interval = interval
        @code = code
      end

      def at(_time)
        @code
      end

      def verify(code, drift_behind: 0, drift_ahead: 0, after: nil, at: Time.now)
        return nil unless code.to_s.gsub(/\s+/, '') == @code

        timestep = at.to_i / interval
        timestamp = timestep * interval
        return nil if after && timestamp <= after

        timestamp
      end
    end
  end
end

RSpec.describe DeviseTwoFactor::OtpRotation::Rotation do
  let(:drift) { 30 }
  let(:old_secret) { '2z6hxkdwi3uvrnpn' }
  let(:new_secret) { 'x5uqxwjirv732wkh' }
  let(:now) { Time.at(1_000_000) }

  let(:old_device) do
    DeviseTwoFactor::OtpRotation::OtpDevice.new(
      id: :old, otp_secret: old_secret, drift: drift
    )
  end
  let(:new_device) do
    DeviseTwoFactor::OtpRotation::OtpDevice.new(
      id: :new, otp_secret: new_secret, drift: drift
    )
  end

  subject(:rotation) { described_class.new(old_device: old_device) }

  before { travel_to(now) }
  after { travel_back }

  describe 'single device usage (pre-rotation behaviour)' do
    it 'accepts a valid code and records its source' do
      result = rotation.validate_and_consume(old_device.current_code)

      expect(result).to be_success
      expect(result.device_id).to eq(:old)
      expect(result.consumption.otp_secret).to eq(old_secret)
      expect(rotation.consumption_for(:old).map(&:device_id)).to eq([:old])
    end

    it 'rejects the same code a second time as a replay without a fresh attempt' do
      code = old_device.current_code
      first = rotation.validate_and_consume(code)
      second = rotation.validate_and_consume(code)

      expect(first).to be_success
      expect(second.status).to eq(:replay)
      expect(rotation.consumption_for(:old).size).to eq(1)
    end

    it 'rejects a bogus code' do
      result = rotation.validate_and_consume('not-a-code')
      expect(result.status).to eq(:invalid_code)
      expect(rotation.consumption_log).to be_empty
    end

    it 'accepts a code inside the allowed drift' do
      future_code = old_device.totp.at(Time.now + drift)
      expect(rotation.validate_and_consume(future_code)).to be_success
    end

    it 'keeps working across timesteps' do
      first = rotation.validate_and_consume(old_device.current_code)
      travel_to(30.seconds.from_now)
      second = rotation.validate_and_consume(old_device.current_code)

      expect(first).to be_success
      expect(second).to be_success
      expect(rotation.consumption_for(:old).map(&:timestep).uniq.size).to eq(2)
    end
  end

  describe 'overlapping window where both devices emit the same digits' do
    let(:shared_code) { '424242' }
    let(:window_start) { Time.at(1_000_020) }

    def scripted_device(id, secret)
      factory = lambda do |s|
        DeviseTwoFactor::OtpRotation::ScriptedTotp.new(s, code: shared_code)
      end
      DeviseTwoFactor::OtpRotation::OtpDevice.new(
        id: id, otp_secret: secret, drift: drift, totp_factory: factory
      )
    end

    let(:old_scripted) { scripted_device(:old, old_secret) }
    let(:new_scripted) { scripted_device(:new, new_secret) }

    subject(:rotation) { described_class.new(old_device: old_scripted) }

    before do
      travel_to(window_start)
      rotation.enroll(new_scripted)
    end

    it 'attributes the shared code to the old device when it authenticates' do
      result = rotation.validate_and_consume(shared_code)

      expect(result).to be_success
      expect(result.device_id).to eq(:old)
      expect(result.consumption.otp_secret).to eq(old_secret)
    end

    it 'still lets the new device consume the same digits independently' do
      old_result = rotation.validate_and_consume(shared_code)

      rotation.begin_verification(:new, shared_code)
      new_result = rotation.commit_verification(:new)

      expect(old_result.device_id).to eq(:old)
      expect(new_result).to be_success
      expect(new_result.device_id).to eq(:new)
      expect(new_result.consumption.otp_secret).to eq(new_secret)

      devices_seen = rotation.consumption_log.map(&:device_id)
      expect(devices_seen).to eq([:old, :new])
      secrets_seen = rotation.consumption_log.map(&:otp_secret)
      expect(secrets_seen).to eq([old_secret, new_secret])
    end

    it 'treats a second use on the old device as an old-device replay' do
      rotation.validate_and_consume(shared_code)
      replay = rotation.validate_and_consume(shared_code)

      expect(replay.status).to eq(:replay)
      expect(replay.device_id).to eq(:old)
    end

    it 'keeps each device replay state separate even with identical digits' do
      rotation.validate_and_consume(shared_code)
      rotation.begin_verification(:new, shared_code)
      rotation.commit_verification(:new)

      # Within the same window both devices consumed the identical digits, but
      # the replay marker is keyed per device. Re-submitting replays each one
      # independently rather than being treated as a single global use.
      old_replay = rotation.validate_and_consume(shared_code)
      expect(old_replay.status).to eq(:replay)
      expect(old_replay.device_id).to eq(:old)

      rotation.begin_verification(:new, shared_code)
      new_replay = rotation.commit_verification(:new)
      expect(new_replay.status).to eq(:replay)
      expect(new_replay.device_id).to eq(:new)

      expect(rotation.consumption_for(:old).size).to eq(1)
      expect(rotation.consumption_for(:new).size).to eq(1)
    end
  end

  describe 'new device verification and takeover' do
    before { rotation.enroll(new_device) }

    it 'does not let a pending device authenticate before verification' do
      result = rotation.validate_and_consume(new_device.current_code)
      expect(result.device_id).to eq(:old)
    end

    it 'rejects a wrong new-device code without consuming an attempt' do
      failed = rotation.verify_new_device('wrong')
      expect(failed).to be_a(DeviseTwoFactor::OtpRotation::LoginResult)
      expect(failed.status).to eq(:invalid_code)
      expect(new_device.consumption_history).to be_empty

      expect(rotation.verify_new_device(new_device.current_code)).to be_success
    end

    it 'refuses to commit before the new device is verified' do
      expect { rotation.commit_rotation! }.to raise_error(
        DeviseTwoFactor::OtpRotation::PendingNotVerified
      )
      expect(old_device).to be_active
    end

    it 'switches active device only after a verified commit' do
      rotation.verify_new_device(new_device.current_code)
      consumption = rotation.commit_rotation!

      expect(rotation).to be_committed
      expect(rotation.active_device).to eq(new_device)
      expect(old_device).to be_retired
      expect(consumption.device_id).to eq(:new)
    end

    it 'keeps the old device usable right up until the switch' do
      before_switch = rotation.validate_and_consume(old_device.current_code)
      expect(before_switch.device_id).to eq(:old)

      rotation.verify_new_device(new_device.current_code)
      rotation.commit_rotation!

      # Advance beyond the drift window so old codes no longer validate at all;
      # the retired device still has to produce an explicit retired result.
      travel_to(60.seconds.from_now)
      after_switch = rotation.validate_and_consume(old_device.current_code)
      expect(after_switch.status).to eq(:retired)
      expect(rotation.active_device).to eq(new_device)
      expect(rotation.validate_and_consume(new_device.current_code).device_id).to eq(:new)
    end

    it 'leaves the old device submitted state untouched after switching' do
      rotation.validate_and_consume(old_device.current_code)
      old_history = old_device.consumption_history.dup

      rotation.verify_new_device(new_device.current_code)
      rotation.commit_rotation!

      expect(old_device.consumption_history).to eq(old_history)
    end
  end

  describe 'in-flight old-device verification racing the switch' do
    it 'ends the old verification explicitly when it commits after retirement' do
      old_code = old_device.current_code

      # The old verification passes cryptographically but has not yet written
      # its replay marker when the new device completes its takeover.
      rotation.begin_verification(:old, old_code)

      rotation.enroll(new_device)
      rotation.verify_new_device(new_device.current_code)
      rotation.commit_rotation!

      result = rotation.commit_verification(:old)

      expect(result.status).to eq(:retired)
      expect(result.device_id).to eq(:old)
      expect(rotation.consumption_for(:old).size).to eq(0)
      expect(rotation.consumption_for(:new).size).to eq(1)
    end

    it 'still commits a normal two-phase verification when no rotation happens' do
      rotation.begin_verification(:old, old_device.current_code)
      result = rotation.commit_verification(:old)

      expect(result).to be_success
      expect(result.device_id).to eq(:old)
    end

    it 'rejects committing a verification that was never started' do
      expect { rotation.commit_verification(:old) }.to raise_error(
        DeviseTwoFactor::OtpRotation::NoInFlightVerification
      )
    end
  end

  describe 'failed switch does not spend the new device attempt' do
    before { rotation.enroll(new_device) }

    it 'allows the correct code through after earlier failed checks' do
      2.times { expect(rotation.verify_new_device('nope').status).to eq(:invalid_code) }
      expect(new_device.consumption_history).to be_empty

      expect(rotation.verify_new_device(new_device.current_code)).to be_success
      consumption = rotation.commit_rotation!
      expect(consumption.device_id).to eq(:new)
      expect(rotation.consumption_for(:new).size).to eq(1)
    end

    it 'prevents enrolling a second device while one is pending' do
      expect { rotation.enroll(new_device) }.to raise_error(
        DeviseTwoFactor::OtpRotation::DeviceAlreadyEnrolled
      )
    end
  end

  describe 'login result after switch' do
    it 'returns success only for the new device and retires old-device logins' do
      rotation.enroll(new_device)
      rotation.verify_new_device(new_device.current_code)
      rotation.commit_rotation!

      # Beyond the drift window the old code cannot validate, but the old
      # device is retired so its login is still ended explicitly rather than
      # reported as a generic invalid code.
      travel_to(60.seconds.from_now)
      old_login = rotation.validate_and_consume(old_device.current_code)
      expect(old_login.status).to eq(:retired)
      expect(old_login.device_id).to eq(:old)

      new_login = rotation.validate_and_consume(new_device.current_code)
      expect(new_login).to be_success
      expect(new_login.device_id).to eq(:new)
    end

    it 'keeps new-device logins working inside the drift window after the switch' do
      rotation.enroll(new_device)
      rotation.verify_new_device(new_device.current_code)
      rotation.commit_rotation!

      travel_to(30.seconds.from_now)

      new_login = rotation.validate_and_consume(new_device.current_code)
      expect(new_login).to be_success
      expect(new_login.device_id).to eq(:new)

      old_login = rotation.validate_and_consume(old_device.current_code)
      expect(old_login.status).to eq(:retired)
    end
  end
end
