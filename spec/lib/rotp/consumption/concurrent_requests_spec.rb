require 'spec_helper'

# Models the reported incident: the login backend receives two identical OTP
# requests. Both pass the ROTP code check, then they are paused before any
# state is written. The commits are released one at a time so the compare-and-
# swap race is deterministic rather than relying on thread scheduling.
RSpec.describe ROTP::Consumption::Verifier, 'interleaved duplicate requests' do
  let(:store)    { ROTP::Consumption::MemoryStore.new }
  let(:verifier) { described_class.new(store) }
  let(:account)  { 'account-1' }
  let(:auth)     { 'authenticator-1' }

  shared_examples 'one success, one replay, then a valid next login' do
    # Eagerly evaluate both verifications and pause them before any commit,
    # mirroring two in-flight HTTP requests stopped after the code check.
    before { request_one && request_two }

    it 'accepts the first commit and rejects the second' do
      expect(first_commit.status).to eq(:ok)
      expect(second_commit.status).to eq(:contended)
      expect(store.get(account, auth).version).to eq(0)
    end

    it 'refuses a replay of the same code afterwards' do
      first_commit
      second_commit
      expect(replay.status).to eq(:replayed)
    end

    it 'still lets the legitimate following code log in' do
      first_commit
      second_commit
      expect(next_login).to be_ok
      expect(verifier.commit(next_login.pending)).to be_ok
    end
  end

  describe 'TOTP with a backwards-moving clock' do
    let(:totp)       { ROTP::TOTP.new('JBSWY3DPEHPK3PXP') }
    let(:login_time) { Time.utc(2026, 11, 19, 12, 0, 0) }
    let(:code)       { totp.at(login_time) }

    let(:request_one) do
      verifier.verify(account_id: account, authenticator_id: auth, otp: totp,
                      code: code, at: login_time)
    end
    let(:request_two) do
      verifier.verify(account_id: account, authenticator_id: auth, otp: totp,
                      code: code, at: login_time)
    end

    let(:first_commit)  { verifier.commit(request_one.pending) }
    let(:second_commit) { verifier.commit(request_two.pending) }
    let(:replay) do
      # The same code resubmitted (the clock may even have rolled back to the
      # same interval): the stored watermark, not the request time, rejects it.
      verifier.verify(account_id: account, authenticator_id: auth, otp: totp,
                      code: code, at: login_time)
    end
    let(:next_login) do
      future = login_time + 30
      verifier.verify(account_id: account, authenticator_id: auth, otp: totp,
                      code: totp.at(future), at: future)
    end

    it 'passes the code check in both paused requests' do
      expect(request_one).to be_ok
      expect(request_two).to be_ok
      expect(store.get(account, auth)).to be_nil
    end

    it 'rejects the consumed interval even if the clock is rolled back to it' do
      first_commit
      second_commit

      # Clock rolled back to the exact interval whose code was consumed.
      # ROTP alone would accept this; the stored watermark turns it into a
      # replay and the failed attempt leaves the position untouched.
      rolled_back = verifier.verify(account_id: account, authenticator_id: auth,
                                    otp: totp, code: code, at: login_time)
      expect(rolled_back.status).to eq(:replayed)
      expect(store.get(account, auth).watermark).to eq(login_time.to_i)
    end

    include_examples 'one success, one replay, then a valid next login'
  end

  describe 'HOTP with a skipped counter' do
    let(:hotp) { ROTP::HOTP.new('JBSWY3DPEHPK3PXP') }
    let(:code) { hotp.at(7) }

    let(:request_one) do
      verifier.verify(account_id: account, authenticator_id: auth, otp: hotp,
                      code: code, retries: 10)
    end
    let(:request_two) do
      verifier.verify(account_id: account, authenticator_id: auth, otp: hotp,
                      code: code, retries: 10)
    end

    let(:first_commit)  { verifier.commit(request_one.pending) }
    let(:second_commit) { verifier.commit(request_two.pending) }
    let(:replay) do
      verifier.verify(account_id: account, authenticator_id: auth, otp: hotp,
                      code: code, retries: 10)
    end
    let(:next_login) do
      verifier.verify(account_id: account, authenticator_id: auth, otp: hotp,
                      code: hotp.at(8), retries: 10)
    end

    it 'passes the code check in both paused requests' do
      expect(request_one).to be_ok
      expect(request_two).to be_ok
      expect(store.get(account, auth)).to be_nil
    end

    include_examples 'one success, one replay, then a valid next login'

    it 'records the skipped-to counter rather than request timing' do
      first_commit
      expect(store.get(account, auth).watermark).to eq(7)
    end
  end
end
