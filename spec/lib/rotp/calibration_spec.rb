require 'spec_helper'

FIXED_SECRET = 'JBSWY3DPEHPK3PXP'.freeze

RSpec.describe ROTP::Calibration do

  # A controllable clock: every call advances time by one second, giving the
  # service a stable "now" without touching the global process clock.
  class FakeClock
    def initialize(start)
      @current = start
    end

    def now
      @current
    end

    def advance(seconds)
      @current += seconds
    end

    def call
      @current
    end
  end

  # Deterministic collision points found by scanning the fixed secret
  # (see #matching_timecodes behaviour below).
  COLLISION_TIMECODE_3DIGIT = 59_836_405 # 2026-11-19 12:42:30 UTC, code '022' matches [0, 2]
  COLLISION_TIMECODE_2DIGIT = 59_835_977 # 2026-11-19 09:08:30 UTC, code '82'  matches [0, 1]

  let(:clock)     { FakeClock.new(Time.utc(2026, 11, 19, 9)) }
  let(:service)   { ROTP::Calibration::Service.new(clock: clock) }
  let(:totp)      { ROTP::TOTP.new(FIXED_SECRET) }

  def authenticator(digits: 6, offset_steps: 0)
    ROTP::Calibration::Authenticator.new(
      id: 'authn-1', account_id: 'acct-1', secret: FIXED_SECRET,
      digits: digits, offset_steps: offset_steps
    )
  end

  # Code produced by a physical device whose clock runs `offset_steps`
  # timecode steps away from the server clock.
  def device_code(totp, server_time, offset_steps)
    totp.generate_otp(server_time.to_i / 30 + offset_steps)
  end

  describe ROTP::TOTP do
    describe '#matching_timecodes' do
      it 'returns every timecode whose OTP equals the submitted code' do
        at = Time.at(COLLISION_TIMECODE_3DIGIT * 30, in: 'UTC')
        short_totp = ROTP::TOTP.new(FIXED_SECRET, digits: 3)
        code = short_totp.generate_otp(COLLISION_TIMECODE_3DIGIT)

        expect(code).to eq '022'
        expect(short_totp.matching_timecodes(code, drift_ahead: 90, drift_behind: 90, at: at))
          .to eq [COLLISION_TIMECODE_3DIGIT, COLLISION_TIMECODE_3DIGIT + 2]
      end

      it 'is empty for a code matching nothing in the window' do
        expect(totp.matching_timecodes('000000', at: Time.utc(2026, 11, 19, 9)))
          .to eq []
      end
    end
  end

  describe 'slow clock calibration' do
    let(:server_time) { Time.utc(2026, 11, 19, 9) }
    let(:device)      { authenticator }
    let(:challenge)   { service.start_challenge(device) }

    it 'needs two consecutive codes before saving a negative offset' do
      first_code = device_code(totp, server_time, -2)
      first, unchanged = service.submit(challenge.id, device, first_code, at: server_time)

      expect(first.status).to eq :more_evidence_needed
      expect(first.candidate_offsets).to eq [-2]
      expect(unchanged.offset_steps).to eq 0
      expect(first.report[:explanation]).to include('insufficient')

      second_time = server_time + 30
      second_code = device_code(totp, second_time, -2)
      second, calibrated = service.submit(challenge.id, device, second_code, at: second_time)

      expect(second.status).to eq :calibrated
      expect(second.saved_offset_steps).to eq(-2)
      expect(calibrated.offset_steps).to eq(-2)
      expect(second.evidence_count).to eq 2
    end

    it 'a single correct code never updates the authenticator' do
      code = device_code(totp, server_time, -2)
      result, device_after = service.submit(challenge.id, device, code, at: server_time)

      expect(result.status).to eq :more_evidence_needed
      expect(device_after.offset_steps).to eq 0
      expect(result.report[:candidate_offsets]).to eq [-2]
    end
  end

  describe 'fast clock calibration' do
    it 'saves a positive offset after consecutive evidence' do
      device = authenticator
      challenge = service.start_challenge(device)
      server_time = Time.utc(2026, 11, 19, 9)

      first, = service.submit(challenge.id, device,
                              device_code(totp, server_time, 2), at: server_time)
      expect(first.status).to eq :more_evidence_needed

      second_time = server_time + 30
      second, calibrated = service.submit(challenge.id, device,
                                          device_code(totp, second_time, 2), at: second_time)
      expect(second.status).to eq :calibrated
      expect(calibrated.offset_steps).to eq 2
    end
  end

  describe 'ambiguous short-digit collisions' do
    it 'does not pick the first candidate from one code; a second code disambiguates' do
      short_totp = ROTP::TOTP.new(FIXED_SECRET, digits: 3)
      device = authenticator(digits: 3)
      challenge = service.start_challenge(device)
      first_time = Time.at(COLLISION_TIMECODE_3DIGIT * 30, in: 'UTC')

      # Same first code whether the device is honest (offset 0) or two steps
      # fast (offset 2), so choosing candidate [0] would be arbitrary.
      ambiguous_code = short_totp.generate_otp(COLLISION_TIMECODE_3DIGIT)
      expect(ambiguous_code).to eq '022'

      first, = service.submit(challenge.id, device, ambiguous_code, at: first_time)
      expect(first.status).to eq :more_evidence_needed
      expect(first.candidate_offsets).to eq [0, 2]
      expect(first.report[:explanation]).to include('collide')

      # A genuinely fast device now produces the code at server timecode + 2,
      # which only matches offset 2.
      second_time = first_time + 30
      fast_code = short_totp.generate_otp(COLLISION_TIMECODE_3DIGIT + 1 + 2)
      second, calibrated = service.submit(challenge.id, device, fast_code, at: second_time)

      expect(second.status).to eq :calibrated
      expect(calibrated.offset_steps).to eq 2
    end

    it 'resolves the same ambiguous first code to offset 0 for an honest device' do
      short_totp = ROTP::TOTP.new(FIXED_SECRET, digits: 3)
      device = authenticator(digits: 3)
      challenge = service.start_challenge(device)
      first_time = Time.at(COLLISION_TIMECODE_3DIGIT * 30, in: 'UTC')

      service.submit(challenge.id, device, '022', at: first_time)
      second_time = first_time + 30
      honest_code = short_totp.generate_otp(COLLISION_TIMECODE_3DIGIT + 1)
      second, calibrated = service.submit(challenge.id, device, honest_code, at: second_time)

      expect(second.status).to eq :calibrated
      expect(calibrated.offset_steps).to eq 0
    end

    it 'keeps asking for evidence while the candidate set has multiple offsets' do
      short_totp = ROTP::TOTP.new(FIXED_SECRET, digits: 2)
      device = authenticator(digits: 2)
      challenge = service.start_challenge(device)
      first_time = Time.at(COLLISION_TIMECODE_2DIGIT * 30, in: 'UTC')

      first, = service.submit(challenge.id, device, '82', at: first_time)
      expect(first.candidate_offsets).to eq [0, 1]
      expect(first.status).to eq :more_evidence_needed

      second_time = first_time + 30
      second_code = short_totp.generate_otp(COLLISION_TIMECODE_2DIGIT + 1 + 1)
      second, unchanged = service.submit(challenge.id, device, second_code, at: second_time)

      expect(second.candidate_offsets).to eq [1]
      expect(second.status).to eq :calibrated
      expect(unchanged.offset_steps).to eq 1
    end
  end

  describe 'replayed positions' do
    it 'rejects resubmission of a consumed timecode within the same challenge' do
      device = authenticator
      challenge = service.start_challenge(device)
      server_time = Time.utc(2026, 11, 19, 9)
      code = device_code(totp, server_time, -1)

      first, = service.submit(challenge.id, device, code, at: server_time)
      expect(first.status).to eq :more_evidence_needed

      replay, = service.submit(challenge.id, device, code, at: server_time)
      expect(replay.status).to eq :replayed
      expect(replay.evidence_count).to eq 1
      expect(replay.report[:explanation]).to include('replayed')
    end

    it 'a replayed code does not consume evidence or block a fresh next code' do
      device = authenticator
      challenge = service.start_challenge(device)
      server_time = Time.utc(2026, 11, 19, 9)

      service.submit(challenge.id, device, device_code(totp, server_time, -1), at: server_time)
      replay, = service.submit(challenge.id, device,
                               device_code(totp, server_time, -1), at: server_time)
      expect(replay.status).to eq :replayed

      second_time = server_time + 30
      result, calibrated = service.submit(
        challenge.id, device, device_code(totp, second_time, -1), at: second_time
      )
      expect(result.status).to eq :calibrated
      expect(calibrated.offset_steps).to eq(-1)
    end
  end

  describe 'challenge lifetime and binding' do
    it 'expires after the TTL and refuses late submissions' do
      device = authenticator
      challenge = service.start_challenge(device, ttl: 60)
      server_time = Time.utc(2026, 11, 19, 9)
      service.submit(challenge.id, device, device_code(totp, server_time, 1), at: server_time)

      clock.advance(61)
      late, = service.submit(
        challenge.id, device,
        device_code(totp, clock.now, 1), at: clock.now
      )
      expect(late.status).to eq :expired
      expect(late.report[:explanation]).to include('validity period')
    end

    it 'rejects a challenge presented against another account or authenticator' do
      device = authenticator
      other = ROTP::Calibration::Authenticator.new(
        id: 'authn-2', account_id: 'acct-2', secret: FIXED_SECRET
      )
      challenge = service.start_challenge(device)

      result, returned = service.submit(challenge.id, other, '123456',
                                        at: Time.utc(2026, 11, 19, 9))
      expect(result.status).to eq :binding_mismatch
      expect(returned).to equal other
    end

    it 'reports unknown challenge ids' do
      result, device = service.submit('missing', authenticator, '123456',
                                      at: Time.utc(2026, 11, 19, 9))
      expect(result.status).to eq :challenge_not_found
      expect(result.report[:explanation]).to match(/No active calibration/)
      expect(device.offset_steps).to eq 0
    end

    it 'refuses further submissions once calibration completed' do
      device = authenticator
      challenge = service.start_challenge(device)
      t0 = Time.utc(2026, 11, 19, 9)
      service.submit(challenge.id, device, device_code(totp, t0, 1), at: t0)
      service.submit(challenge.id, device, device_code(totp, t0 + 30, 1), at: t0 + 30)

      extra, = service.submit(challenge.id, device,
                              device_code(totp, t0 + 60, 1), at: t0 + 60)
      expect(extra.status).to eq :challenge_closed
    end
  end

  describe 'invalid and contradictory evidence' do
    it 'rejects codes matching no timecode without recording evidence' do
      device = authenticator
      challenge = service.start_challenge(device)
      result, = service.submit(challenge.id, device, '000000',
                               at: Time.utc(2026, 11, 19, 9))

      expect(result.status).to eq :invalid
      expect(result.evidence_count).to eq 0
      expect(result.consumed_timecodes).to eq []
      expect(result.report[:explanation]).to match(/matches no timecode/)
    end

    it 'marks contradictory consecutive codes inconsistent and saves nothing' do
      device = authenticator
      challenge = service.start_challenge(device)
      t0 = Time.utc(2026, 11, 19, 9)

      service.submit(challenge.id, device, device_code(totp, t0, 1), at: t0)
      # Second code implies offset -1, which cannot intersect the first set [1].
      contradictory, unchanged = service.submit(
        challenge.id, device, device_code(totp, t0 + 30, -1), at: t0 + 30
      )
      expect(contradictory.status).to eq :inconsistent
      expect(unchanged.offset_steps).to eq 0
    end
  end

  describe 'non-default interval' do
    it 'computes offsets against the authenticator interval, not a fixed 30s' do
      interval = 60
      device = ROTP::Calibration::Authenticator.new(
        id: 'authn-1', account_id: 'acct-1', secret: FIXED_SECRET, interval: interval
      )
      custom_totp = ROTP::TOTP.new(FIXED_SECRET, interval: interval)
      challenge = service.start_challenge(device)
      t0 = Time.utc(2026, 11, 19, 9)
      base_timecode = t0.to_i / interval

      first, = service.submit(
        challenge.id, device,
        custom_totp.generate_otp(base_timecode - 1), at: t0
      )
      expect(first.candidate_offsets).to eq [-1]

      second, calibrated = service.submit(
        challenge.id, device,
        custom_totp.generate_otp(base_timecode + 1 - 1), at: t0 + interval
      )
      expect(second.status).to eq :calibrated
      expect(calibrated.offset_steps).to eq(-1)
      expect(calibrated.verify(custom_totp.generate_otp(base_timecode - 1), at: t0))
        .to be_truthy
    end
  end

  describe 'ordinary login' do
    it 'never learns an offset from verify, but applies a saved calibrated offset' do
      t0 = Time.utc(2026, 11, 19, 9)
      uncalibrated = authenticator

      # The slow device code fails against the uncalibrated authenticator...
      slow_code = device_code(totp, t0, -2)
      expect(uncalibrated.verify(slow_code, at: t0)).to be_falsey
      # ...and the failed login leaves no offset behind.
      expect(uncalibrated.offset_steps).to eq 0

      calibrated = authenticator(offset_steps: -2)
      expect(calibrated.verify(slow_code, at: t0)).to be_truthy
      expect(calibrated.offset_steps).to eq(-2)
    end

    it 'does not accept codes outside the small fixed drift window' do
      calibrated = authenticator(offset_steps: -2)
      t0 = Time.utc(2026, 11, 19, 9)
      far_code = device_code(totp, t0, -5)
      expect(calibrated.verify(far_code, at: t0)).to be_falsey
    end
  end
end

RSpec.describe ROTP::Calibration, 'edge coverage' do
  # Fixed fixture where two consecutive codes ('32' then '34') each admit the
  # same two offsets [0, 3] on disjoint absolute timecodes, so even two pieces
  # of evidence cannot disambiguate and no offset may be saved.
  PERSISTENT_AMBIGUITY_TIMECODE = 59_841_109

  let(:service) { ROTP::Calibration::Service.new(clock: -> { Time.utc(2026, 11, 19, 9) }) }

  def authenticator(digits: 2)
    ROTP::Calibration::Authenticator.new(
      id: 'authn-1', account_id: 'acct-1', secret: FIXED_SECRET, digits: digits
    )
  end

  it 'treats non-string codes as invalid instead of raising' do
    device = authenticator
    challenge = service.start_challenge(device)
    result, = service.submit(challenge.id, device, 123, at: Time.utc(2026, 11, 19, 9))

    expect(result.status).to eq :invalid
    expect(result.evidence_count).to eq 0
  end

  it 'reports an explanatory message for every terminal and pending status' do
    device = authenticator(digits: 6)
    challenge = service.start_challenge(device)
    t0 = Time.utc(2026, 11, 19, 9)
    totp6 = ROTP::TOTP.new(FIXED_SECRET)

    # First code implies offset 2 (device two timecode steps fast).
    first, = service.submit(
      challenge.id, device, totp6.generate_otp(t0.to_i / 30 + 2), at: t0
    )
    expect(first.candidate_offsets).to eq [2]

    # Second code implies offset -2 at a fresh, unconsumed timecode; sets [2]
    # and [-2] cannot intersect, so the evidence is contradictory.
    inconsistent, = service.submit(
      challenge.id, device,
      totp6.generate_otp((t0.to_i / 30 + 1) - 2), at: t0 + 30
    )
    expect(inconsistent.status).to eq :inconsistent
    expect(inconsistent.report[:explanation]).to match(/contradictory/)

    closed, = service.submit(challenge.id, device, '000000', at: t0 + 60)
    expect(closed.status).to eq :challenge_closed
    expect(closed.report[:explanation]).to match(/already finished/)

    other = ROTP::Calibration::Authenticator.new(
      id: 'authn-2', account_id: 'acct-2', secret: FIXED_SECRET
    )
    other_challenge = service.start_challenge(other)
    mismatch, = service.submit(other_challenge.id, device, '000000', at: t0)
    expect(mismatch.status).to eq :binding_mismatch
    expect(mismatch.report[:explanation]).to match(/another account/)

    # A fresh successful calibration explains the saved offset.
    success_challenge = service.start_challenge(device)
    service.submit(success_challenge.id, device,
                   totp6.generate_otp(t0.to_i / 30 + 1), at: t0)
    calibrated, = service.submit(
      success_challenge.id, device,
      totp6.generate_otp(t0.to_i / 30 + 2), at: t0 + 30
    )
    expect(calibrated.status).to eq :calibrated
    expect(calibrated.report[:explanation]).to match(/updated/)
  end

  it 'keeps evidence pending when later codes still admit several offsets' do
    device = authenticator
    challenge = service.start_challenge(device)
    first_time = Time.at(PERSISTENT_AMBIGUITY_TIMECODE * 30, in: 'UTC')

    first, = service.submit(challenge.id, device, '32', at: first_time)
    expect(first.candidate_offsets).to eq [0, 3]

    second, unchanged = service.submit(
      challenge.id, device, '34', at: first_time + 30
    )
    expect(second.status).to eq :more_evidence_needed
    expect(second.evidence_count).to eq 2
    expect(second.candidate_offsets).to eq [0, 3]
    expect(unchanged.offset_steps).to eq 0
    expect(second.report[:explanation]).to match(/remain ambiguous/)
  end
end
