require 'spec_helper'

RSpec.describe ROTP::Consumption, 'defensive guards' do
  let(:store)    { ROTP::Consumption::MemoryStore.new }
  let(:verifier) { ROTP::Consumption::Verifier.new(store) }

  describe ROTP::Consumption::State do
    it 'rejects an unknown kind' do
      expect { described_class.new(:bogus, 0, nil) }.to raise_error(ArgumentError, /unknown kind/)
    end

    it 'rejects a non-integer watermark' do
      expect { described_class.totp('0', version: nil) }.to raise_error(ArgumentError, /Integer/)
    end

    it 'is value based and usable as a hash key' do
      a = described_class.hotp(3, version: 1)
      b = described_class.hotp(3, version: 1)
      expect(a).to eq(b)
      expect(a.eql?(b)).to be(true)
      expect(a.hash).to eq(b.hash)
    end
  end

  describe ROTP::Consumption::Result do
    it 'rejects an unknown status' do
      expect { ROTP::Consumption::Result.new(:nope) }.to raise_error(ArgumentError, /unknown status/)
    end

    it 'reports success versus rejection' do
      expect(ROTP::Consumption::Result.new(:ok)).to be_ok
      expect(ROTP::Consumption::Result.new(:invalid)).to be_rejected
    end

    it 'renders a readable inspect' do
      result = ROTP::Consumption::Result.new(:replayed, detail: 'already used')
      expect(result.inspect).to include('status=replayed', 'already used')
    end
  end

  describe ROTP::Consumption::PendingCommit do
    it 'exposes its composite key and renders an inspect' do
      state = ROTP::Consumption::State.hotp(0, version: 0)
      pending = ROTP::Consumption::PendingCommit.new('acct', 'auth', state, state.advance(1))
      expect(pending.key).to eq(['acct', 'auth'])
      expect(pending.inspect).to include('PendingCommit')
    end
  end

  describe ROTP::Consumption::State do
    it 'renders a readable inspect' do
      expect(ROTP::Consumption::State.totp(30, version: 2).inspect).to include('kind=totp', 'watermark=30')
    end
  end

  describe ROTP::Consumption::Verifier do
    it 'verify_and_consume commits a valid code in one step' do
      totp = ROTP::TOTP.new('JBSWY3DPEHPK3PXP')
      at = Time.utc(2026, 11, 19, 12, 0, 0)

      result = verifier.verify_and_consume(account_id: 'a', authenticator_id: 'b',
                                           otp: totp, code: totp.at(at), at: at)
      expect(result).to be_ok
      expect(store.get('a', 'b').watermark).to eq(at.to_i)
    end

    it 'verify_and_consume does not open a write for an invalid code' do
      totp = ROTP::TOTP.new('JBSWY3DPEHPK3PXP')
      result = verifier.verify_and_consume(account_id: 'a', authenticator_id: 'b',
                                           otp: totp, code: '000000')
      expect(result.status).to eq(:invalid)
      expect(store.get('a', 'b')).to be_nil
    end

    it 'rejects an OTP object that is neither TOTP nor HOTP' do
      expect do
        verifier.verify(account_id: 'a', authenticator_id: 'b', otp: 'x', code: '1')
      end.to raise_error(ArgumentError, /must be a ROTP::TOTP or ROTP::HOTP/)
    end

    it 'refuses to treat an existing authenticator as a different OTP kind' do
      totp = ROTP::TOTP.new('JBSWY3DPEHPK3PXP')
      hotp = ROTP::HOTP.new('JBSWY3DPEHPK3PXP')
      at = Time.utc(2026, 11, 19, 12, 0, 0)

      first = verifier.verify(account_id: 'a', authenticator_id: 'b', otp: totp,
                              code: totp.at(at), at: at)
      verifier.commit(first.pending)

      expect do
        verifier.verify(account_id: 'a', authenticator_id: 'b', otp: hotp, code: hotp.at(0))
      end.to raise_error(ArgumentError, /kind cannot change/)
    end
  end

  describe ROTP::Consumption::Store do
    it 'documents the contract methods as abstract' do
      klass = Class.new { include ROTP::Consumption::Store }
      instance = klass.new
      expect { instance.get('a', 'b') }.to raise_error(NotImplementedError)
      expect do
        instance.compare_and_swap('a', 'b', nil, nil)
      end.to raise_error(NotImplementedError)
      expect { instance.transaction {} }.to raise_error(NotImplementedError)
    end
  end
end
