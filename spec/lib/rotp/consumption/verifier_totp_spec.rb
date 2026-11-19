require 'spec_helper'

RSpec.describe ROTP::Consumption::Verifier, 'TOTP' do
  let(:secret) { 'JBSWY3DPEHPK3PXP' }
  let(:totp)   { ROTP::TOTP.new(secret) }
  let(:store)  { ROTP::Consumption::MemoryStore.new }
  let(:verifier) { described_class.new(store) }

  # Exactly on a 30-second boundary so the token is unambiguous.
  let(:login_time) { Time.utc(2026, 11, 19, 12, 0, 0) }
  let(:account) { 'account-1' }
  let(:authenticator) { 'phone-a' }
  let(:code) { totp.at(login_time) }

  def verify(code_arg = code, at: login_time, **extra)
    verifier.verify(account_id: account, authenticator_id: authenticator,
                    otp: totp, code: code_arg, at: at, **extra)
  end

  describe 'a single login' do
    it 'accepts a current code and advances the position exactly once' do
      result = verify
      expect(result).to be_ok
      expect(store.get(account, authenticator)).to be_nil

      commit = verifier.commit(result.pending)
      expect(commit).to be_ok
      expect(store.get(account, authenticator).watermark).to eq(login_time.to_i)
      expect(store.get(account, authenticator).version).to eq(0)
    end

    it 'rejects a wrong code without touching the position' do
      result = verify('000000')
      expect(result.status).to eq(:invalid)
      expect(result.pending).to be_nil
      expect(store.get(account, authenticator)).to be_nil
    end
  end

  describe 'duplicate HTTP requests carrying the same code' do
    let!(:first) { verify }
    let!(:second) { verify }

    before do
      verifier.commit(first.pending)
    end

    it 'lets the first commit win and rejects the paused duplicate' do
      expect(verifier.commit(second.pending).status).to eq(:contended)
      expect(store.get(account, authenticator).version).to eq(0)
    end

    it 'classifies a fresh verification of the consumed code as a replay' do
      expect(verify.status).to eq(:replayed)
      expect(store.get(account, authenticator).watermark).to eq(login_time.to_i)
    end
  end

  describe 'a clock that moves backwards' do
    it 'still rejects a code the clock makes look fresh because the stored position wins' do
      verifier.commit(verify.pending)

      later = login_time + 30
      verifier.commit(verify(totp.at(later), at: later).pending)

      # The clock rolls back into the drift window. ROTP on its own would now
      # accept the previously consumed code (it is a valid, in-window token),
      # but the stored watermark turns it into a replay.
      rollback = verify(code, at: login_time, drift_behind: 30)
      expect(rollback.status).to eq(:replayed)
      expect(store.get(account, authenticator).watermark).to eq(later.to_i)
    end
  end

  describe 'a legitimate next code' do
    it 'can still log in after a replay attempt' do
      verifier.commit(verify.pending)
      expect(verify.status).to eq(:replayed)

      next_time = login_time + 30
      next_login = verify(totp.at(next_time), at: next_time)
      expect(next_login).to be_ok
      expect(verifier.commit(next_login.pending)).to be_ok
      expect(store.get(account, authenticator).watermark).to eq(next_time.to_i)
    end
  end

  describe 'drift' do
    it 'consumes the oldest accepted interval when drift looks backwards' do
      previous_time = login_time - 30
      result = verify(totp.at(previous_time), at: login_time, drift_behind: 30)
      expect(result).to be_ok
      verifier.commit(result.pending)
      expect(store.get(account, authenticator).watermark).to eq(previous_time.to_i)
    end
  end

  describe 'multiple authenticators on one account' do
    let(:other_totp) { ROTP::TOTP.new('KRSXG5CTMVRXEZLU') }

    it 'keeps a watermark per authenticator instead of one shared timestamp' do
      first = verifier.verify(account_id: account, authenticator_id: 'phone-a',
                              otp: totp, code: code, at: login_time)
      verifier.commit(first.pending)

      other = verifier.verify(account_id: account, authenticator_id: 'phone-b',
                              otp: other_totp, code: other_totp.at(login_time), at: login_time)
      expect(other).to be_ok
      verifier.commit(other.pending)

      expect(store.get(account, 'phone-a').watermark).to eq(login_time.to_i)
      expect(store.get(account, 'phone-b').watermark).to eq(login_time.to_i)

      # Separate rows: advancing phone-a leaves phone-b at its own watermark.
      next_time = login_time + 30
      advance_a = verifier.verify(account_id: account, authenticator_id: 'phone-a',
                                  otp: totp, code: totp.at(next_time), at: next_time)
      verifier.commit(advance_a.pending)
      expect(store.get(account, 'phone-a').watermark).to eq(next_time.to_i)
      expect(store.get(account, 'phone-b').watermark).to eq(login_time.to_i)

      # Replaying phone-a's code never depends on phone-b's request time.
      replay = verifier.verify(account_id: account, authenticator_id: 'phone-a',
                               otp: totp, code: code, at: login_time)
      expect(replay.status).to eq(:replayed)
    end
  end

  describe 'business commit failure' do
    it 'rolls the consumed position back so the same code can be retried' do
      result = verify

      expect do
        store.transaction do
          verifier.commit(result.pending)
          raise 'downstream service unavailable'
        end
      end.to raise_error('downstream service unavailable')

      expect(store.get(account, authenticator)).to be_nil

      retry_result = verify
      expect(retry_result).to be_ok
      expect(verifier.commit(retry_result.pending)).to be_ok
    end
  end
end
