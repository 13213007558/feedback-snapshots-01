require 'spec_helper'

RSpec.describe ROTP::Consumption::MemoryStore do
  let(:store) { described_class.new }
  let(:key) { ['account-1', 'authenticator-1'] }

  def totp_state(watermark, version)
    ROTP::Consumption::State.totp(watermark, version: version)
  end

  describe '#get' do
    it 'returns nil for an unknown authenticator' do
      expect(store.get(*key)).to be_nil
    end

    it 'stores positions independently per (account, authenticator)' do
      insert = totp_state(-1, nil).advance(100)
      expect(store.compare_and_swap(*key, nil, insert)).to be(true)

      expect(store.get('account-1', 'other-authenticator')).to be_nil
      expect(store.get('other-account', 'authenticator-1')).to be_nil
      expect(store.get(*key)).to eq(insert)
    end
  end

  describe '#compare_and_swap' do
    it 'inserts when the row is absent and the expected version is nil' do
      inserted = totp_state(-1, nil).advance(100)
      expect(store.compare_and_swap(*key, nil, inserted)).to be(true)
      expect(store.get(*key)).to eq(inserted)
    end

    it 'refuses an insert when another commit created the row first' do
      winner = totp_state(-1, nil).advance(100)
      loser = totp_state(-1, nil).advance(200)

      expect(store.compare_and_swap(*key, nil, winner)).to be(true)
      expect(store.compare_and_swap(*key, nil, loser)).to be(false)
      expect(store.get(*key)).to eq(winner)
    end

    it 'updates only when the expected version still matches' do
      v0 = totp_state(-1, nil).advance(100)
      v1 = v0.advance(200)
      stale = v0.advance(300)

      expect(store.compare_and_swap(*key, nil, v0)).to be(true)
      expect(store.compare_and_swap(*key, v0, v1)).to be(true)
      expect(store.compare_and_swap(*key, v0, stale)).to be(false)
      expect(store.get(*key)).to eq(v1)
    end

    it 'is atomic across concurrent threads' do
      starting = totp_state(-1, nil).advance(0)
      store.compare_and_swap(*key, nil, starting)

      # Every thread reads the same state before racing, so all swaps are
      # built on the identical (stale-except-for-one) version.
      observed = store.get(*key)
      winners = 0
      counter_lock = Mutex.new
      threads = Array.new(20) do |index|
        Thread.new do
          candidate = observed.advance(observed.watermark + index + 1)
          if store.compare_and_swap(*key, observed, candidate)
            counter_lock.synchronize { winners += 1 }
          end
        end
      end
      threads.each(&:join)

      expect(winners).to eq(1)
      expect(store.get(*key).version).to eq(1)
    end
  end

  describe '#transaction' do
    it 'commits when the block returns normally' do
      store.transaction do
        state = totp_state(-1, nil).advance(100)
        store.compare_and_swap(*key, nil, state)
      end

      expect(store.get(*key).watermark).to eq(100)
    end

    it 'rolls the OTP position back when the business write fails' do
      state = totp_state(-1, nil).advance(100)
      store.compare_and_swap(*key, nil, state)

      expect do
        store.transaction do
          store.compare_and_swap(*key, state, state.advance(200))
          raise 'business commit failed'
        end
      end.to raise_error('business commit failed')

      expect(store.get(*key)).to eq(state)
    end

    it 'supports nesting by flattening inner blocks into the outer transaction' do
      expect do
        store.transaction do
          store.transaction do
            raise 'inner failure'
          end
        end
      end.to raise_error('inner failure')

      expect(store.get(*key)).to be_nil
    end

    it 'commits nested work when every level returns normally' do
      first = totp_state(-1, nil).advance(100)
      store.compare_and_swap(*key, nil, first)

      store.transaction do
        store.transaction do
          store.compare_and_swap(*key, first, first.advance(200))
        end
      end

      expect(store.get(*key).watermark).to eq(200)
      expect(store.get(*key).version).to eq(1)
    end
  end

  describe ROTP::Consumption::State do
    it 'starts unpersisted and versions from zero on the first advance' do
      state = described_class.totp
      expect(state.initial?).to be(true)
      advanced = state.advance(90)
      expect(advanced.version).to eq(0)
      expect(advanced.watermark).to eq(90)
    end

    it 'increments the version on every advance' do
      state = described_class.hotp(0, version: 0)
      expect(state.advance(1).version).to eq(1)
    end

    it 'refuses to move a position backwards' do
      state = described_class.hotp(5, version: 1)
      expect { state.advance(5) }.to raise_error(ArgumentError)
      expect { state.advance(4) }.to raise_error(ArgumentError)
    end
  end
end
