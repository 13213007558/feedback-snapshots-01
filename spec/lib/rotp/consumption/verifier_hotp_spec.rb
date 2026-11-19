require 'spec_helper'

RSpec.describe ROTP::Consumption::Verifier, 'HOTP' do
  let(:hotp)    { ROTP::HOTP.new('JBSWY3DPEHPK3PXP') }
  let(:store)   { ROTP::Consumption::MemoryStore.new }
  let(:verifier) { described_class.new(store) }
  let(:account) { 'account-1' }
  let(:authenticator) { 'hardware-key' }

  def verify(counter, **extra)
    verifier.verify(account_id: account, authenticator_id: authenticator,
                    otp: hotp, code: hotp.at(counter), **extra)
  end

  describe 'a single login' do
    it 'consumes the matched counter' do
      result = verify(0)
      expect(result).to be_ok
      expect(verifier.commit(result.pending)).to be_ok
      expect(store.get(account, authenticator).watermark).to eq(0)
    end

    it 'rejects a wrong code without advancing the counter' do
      result = verifier.verify(account_id: account, authenticator_id: authenticator,
                               otp: hotp, code: '000000')
      expect(result.status).to eq(:invalid)
      expect(store.get(account, authenticator)).to be_nil
    end
  end

  describe 'counter progression' do
    before do
      verifier.commit(verify(0).pending)
    end

    it 'rejects an already consumed counter as a replay' do
      expect(verify(0).status).to eq(:replayed)
      expect(store.get(account, authenticator).watermark).to eq(0)
    end

    it 'accepts the next counter and moves forward once' do
      result = verify(1)
      expect(result).to be_ok
      expect(verifier.commit(result.pending).status).to eq(:ok)
      expect(store.get(account, authenticator).watermark).to eq(1)

      duplicate = verifier.verify(account_id: account, authenticator_id: authenticator,
                                  otp: hotp, code: hotp.at(1))
      expect(duplicate.status).to eq(:replayed)
      expect(store.get(account, authenticator).version).to eq(1)
    end

    it 'follows an authenticator that skips counters within the retry window' do
      # Device generated counters 1..4 off-line and presents counter 5.
      result = verify(5, retries: 10)
      expect(result).to be_ok
      expect(result.pending.next_state.watermark).to eq(5)
      verifier.commit(result.pending)

      # Every counter up to and including 5 is now spent, even ones never sent.
      expect(verify(2, retries: 10).status).to eq(:replayed)
      expect(verify(6, retries: 10)).to be_ok
    end

    it 'treats a code beyond the retry window as invalid' do
      expect(verify(99, retries: 5).status).to eq(:invalid)
      expect(store.get(account, authenticator).watermark).to eq(0)
    end
  end

  describe 'two authenticators on one account' do
    let(:other_hotp) { ROTP::HOTP.new('KRSXG5CTMVRXEZLU') }

    it 'maintains an independent counter per authenticator' do
      first = verifier.verify(account_id: account, authenticator_id: 'key-a',
                              otp: hotp, code: hotp.at(0))
      verifier.commit(first.pending)

      other = verifier.verify(account_id: account, authenticator_id: 'key-b',
                              otp: other_hotp, code: other_hotp.at(0))
      expect(other).to be_ok
      verifier.commit(other.pending)

      expect(store.get(account, 'key-a').watermark).to eq(0)
      expect(store.get(account, 'key-b').watermark).to eq(0)

      # Advancing key-a cannot push key-b's counter, regardless of request order.
      advance_a = verifier.verify(account_id: account, authenticator_id: 'key-a',
                                  otp: hotp, code: hotp.at(3), retries: 5)
      verifier.commit(advance_a.pending)
      expect(store.get(account, 'key-a').watermark).to eq(3)
      expect(store.get(account, 'key-b').watermark).to eq(0)
    end
  end

  describe 'business commit failure' do
    it 'rolls the counter back so the code remains usable' do
      result = verify(0)

      expect do
        store.transaction do
          verifier.commit(result.pending)
          raise 'business commit failed'
        end
      end.to raise_error('business commit failed')

      expect(store.get(account, authenticator)).to be_nil
      expect(verifier.commit(verify(0).pending)).to be_ok
    end
  end
end
