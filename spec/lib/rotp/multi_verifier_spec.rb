require 'spec_helper'

# Fixed secrets used by every example. The second secret is a different
# authenticator for the same account, not a rotation of the first.
SECRET_A = 'JBSWY3DPEHPK3PXP'.freeze
SECRET_B = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'.freeze

# Reference times chosen once so the examples are fully deterministic.
UNIQUE_TIME = Time.at(1_767_227_100).utc # 2026-01-01 00:25:00 UTC
UNIQUE_TOKEN = '301999'.freeze
COLLISION_TIME = Time.at(1_767_229_890).utc # 2026-01-01 01:11:30 UTC
COLLISION_TOKEN = '32'.freeze # 2-digit token shared by both secrets there

# Records the exact inputs of every HMAC so tests can assert on the real
# amount of work rather than on an estimate.
class RecordingHMAC
  attr_reader :calls

  def initialize
    @calls = []
  end

  def digest(digest_name, key, data)
    @calls << { digest: digest_name, key: key, data: data }
    OpenSSL::HMAC.digest(OpenSSL::Digest.new(digest_name), key, data)
  end

  def count
    calls.size
  end
end

RSpec.describe ROTP::MultiVerifier do
  let(:recorder) { RecordingHMAC.new }
  let(:verifier) { described_class.new(max_hmac: 50, hmac: recorder) }
  let(:authenticator_a) { described_class.authenticator(SECRET_A, id: :a) }
  let(:authenticator_b) { described_class.authenticator(SECRET_B, id: :b) }
  let(:consumed) { [] }

  def consume
    ->(candidate, unit) { consumed << [candidate.id, unit]; true }
  end

  describe 'candidate configuration' do
    it 'keeps digest, digits and window unit explicit' do
      candidate = described_class.authenticator(
        SECRET_A, id: :a, digest: 'sha256', digits: 8,
        interval: 60, drift_behind: 60, drift_ahead: 30
      )

      expect(candidate.digest).to eq 'sha256'
      expect(candidate.digits).to eq 8
      expect(candidate.interval).to eq 60
      expect(candidate.unit).to eq :seconds
      expect(candidate.window_size).to eq 2
    end

    it 'uses counters as the unit for HOTP' do
      candidate = described_class.authenticator(
        SECRET_B, type: :hotp, counter: 4, retries: 2
      )

      expect(candidate.unit).to eq :counter
      expect(candidate.window_size).to eq 3
    end

    it 'rejects unknown digests, types, digit counts and negative windows' do
      expect { described_class.authenticator(SECRET_A, digest: 'nope') }
        .to raise_error(ArgumentError, /unknown digest/)
      expect { described_class.authenticator(SECRET_A, type: :webauthn) }
        .to raise_error(ArgumentError, /unknown OTP type/)
      expect { described_class.authenticator(SECRET_A, digits: 0) }
        .to raise_error(ArgumentError, /digits/)
      expect { described_class.authenticator(SECRET_A, digits: 12) }
        .to raise_error(ArgumentError, /digits/)
      expect { described_class.authenticator(SECRET_A, drift_behind: -1) }
        .to raise_error(ArgumentError, /drift_behind/)
      expect { described_class.authenticator('not base32!') }
        .to raise_error(ROTP::Base32::Base32Error)
    end

    it 'freezes a configuration snapshot of the supplied authenticators' do
      snapshot = verifier.snapshot([authenticator_a, authenticator_b])

      expect(snapshot).to be_frozen
      expect(snapshot).to all(be_frozen)
    end
  end

  describe 'unique match' do
    it 'searches every candidate and consumes exactly the matched position' do
      result = verifier.verify(
        UNIQUE_TOKEN, [authenticator_a, authenticator_b],
        at: UNIQUE_TIME, consume: consume
      )

      expect(result).to be_unique
      expect(result.authenticator.id).to eq :a
      expect(result.position).to eq 58_907_570
      expect(result.unit).to eq UNIQUE_TIME.to_i
      expect(result.consumed_at).to eq UNIQUE_TIME.to_i
      expect(consumed).to eq [[:a, UNIQUE_TIME.to_i]]
    end

    it 'does not reach before the Unix epoch when drift is large' do
      early = described_class.authenticator(
        SECRET_A, id: :a, drift_behind: 10_000
      )
      result = verifier.verify(UNIQUE_TOKEN, [early], at: 30, consume: consume)

      expect(result).to be_invalid
      expect(recorder.count).to eq 2
    end

    it 'reports the real number of HMACs, one per candidate window' do
      verifier.verify(
        UNIQUE_TOKEN, [authenticator_a, authenticator_b],
        at: UNIQUE_TIME, consume: consume
      )

      # Both candidates are searched in full before a decision is made, so a
      # later collision cannot be mistaken for a unique match.
      expect(recorder.count).to eq 2
    end

    it 'counts drift windows per candidate, not per call' do
      drifted = described_class.authenticator(
        SECRET_B, id: :b, drift_behind: 60, drift_ahead: 60
      )
      result = verifier.verify(
        UNIQUE_TOKEN, [authenticator_a, drifted],
        at: UNIQUE_TIME, consume: consume
      )

      expect(result).to be_unique
      expect(result.authenticator.id).to eq :a
      expect(recorder.count).to eq 1 + 5
    end

    it 'supports a three-argument compare-and-swap callback' do
      store = { a: nil }
      candidate = described_class.authenticator(SECRET_A, id: :a, consumed_through: nil)
      cas = lambda do |auth, expected, unit|
        return false unless store[auth.id] == expected

        store[auth.id] = unit
      end

      result = verifier.verify(UNIQUE_TOKEN, [candidate], at: UNIQUE_TIME, consume: cas)

      expect(result).to be_unique
      expect(store[:a]).to eq UNIQUE_TIME.to_i
    end

    it 'keeps a stale snapshot from being redirected by later mutation' do
      candidates = [
        described_class.authenticator(SECRET_A, id: :a),
        described_class.authenticator(SECRET_B, id: :b)
      ]
      snapshot = verifier.snapshot(candidates)

      candidates.clear

      result = verifier.verify(UNIQUE_TOKEN, snapshot, at: UNIQUE_TIME, consume: consume)

      expect(result).to be_unique
      expect(result.authenticator.id).to eq :a
    end
  end

  describe 'ambiguity' do
    let(:collision_a) do
      described_class.authenticator(SECRET_A, id: :a, digits: 2)
    end
    let(:collision_b) do
      described_class.authenticator(SECRET_B, id: :b, digits: 2)
    end

    it 'refuses to choose when two authenticators share the token' do
      result = verifier.verify(
        COLLISION_TOKEN, [collision_a, collision_b],
        at: COLLISION_TIME, consume: consume
      )

      expect(result).to be_ambiguous
      expect(result).not_to be_unique
      expect(result.message).to include '2'
      expect(result.authenticator).to be_nil
      expect(result.consumed_at).to be_nil
      expect(consumed).to be_empty
    end

    it 'treats the same code at two positions of one window as ambiguous' do
      # '66' appears at both timecodes 58_907_597 and 58_907_601, ten seconds
      # apart inside this 11-position window.
      candidate = described_class.authenticator(
        SECRET_A, id: :a, digits: 2, drift_ahead: 300
      )
      reference = Time.at(58_907_597 * 30).utc

      result = verifier.verify(
        '66', [candidate], at: reference, consume: consume
      )

      expect(result).to be_ambiguous
      expect(result.message).to include '2'
      expect(consumed).to be_empty
    end

    it 'still spends the HMACs needed to discover the ambiguity' do
      verifier.verify(
        COLLISION_TOKEN, [collision_a, collision_b],
        at: COLLISION_TIME, consume: consume
      )

      expect(recorder.count).to eq 2
    end

    it 'detects ambiguity across TOTP and HOTP candidates in one snapshot' do
      # SECRET_B makes the same 2-digit code at HOTP counter 20 and at
      # 2026-01-01 00:04:30 UTC, even though the two use different units.
      shared_time = Time.at(58_907_529 * 30).utc
      shared = ROTP::HOTP.new(SECRET_B, digits: 2).at(20)
      expect(ROTP::TOTP.new(SECRET_B, digits: 2).at(shared_time)).to eq shared

      hotp = described_class.authenticator(
        SECRET_B, type: :hotp, id: :hotp, counter: 20, digits: 2
      )
      totp = described_class.authenticator(
        SECRET_B, type: :totp, id: :totp, digits: 2
      )
      result = verifier.verify(
        shared, [hotp, totp], at: shared_time, consume: consume
      )

      expect(result).to be_ambiguous
      expect(result.message).to include '2'
      expect(consumed).to be_empty
    end
  end

  describe 'total HMAC budget' do
    it 'does not allow splitting a wide window into narrow ones to exceed the total' do
      narrow = described_class.new(max_hmac: 4, hmac: RecordingHMAC.new)
      a = described_class.authenticator(SECRET_A, id: :a, drift_behind: 60)
      b = described_class.authenticator(SECRET_B, id: :b, drift_behind: 60)

      result = narrow.verify('000000', [a, b], at: UNIQUE_TIME, consume: consume)

      expect(result).to be_exhausted
      expect(consumed).to be_empty
    end

    it 'cannot exceed the total by splitting one window into several candidates' do
      # One candidate with an 11-position window versus two candidates that
      # split it. Both must stop at the same shared limit.
      wide = described_class.authenticator(
        SECRET_A, id: :wide, drift_ahead: 300
      )
      left = described_class.authenticator(
        SECRET_A, id: :left, drift_ahead: 150
      )
      right = described_class.authenticator(
        SECRET_A, id: :right, drift_behind: 150
      )
      tight = described_class.new(max_hmac: 6, hmac: recorder)
      reference = Time.at(58_907_597 * 30).utc

      single = tight.verify('000000', [wide], at: reference, consume: consume)
      expect(single).to be_exhausted
      expect(recorder.count).to eq 6

      split_recorder = RecordingHMAC.new
      split = described_class.new(max_hmac: 6, hmac: split_recorder)
      split_result = split.verify(
        '000000', [left, right], at: reference + 150, consume: consume
      )

      expect(split_result).to be_exhausted
      expect(split_recorder.count).to eq 6
      expect(consumed).to be_empty
    end

    it 'charges one shared total no matter how the windows are arranged' do
      wide = described_class.authenticator(
        SECRET_A, id: :a, drift_behind: 120, drift_ahead: 120
      )
      narrow = described_class.new(max_hmac: 3, hmac: recorder)

      result = narrow.verify('000000', [wide], at: UNIQUE_TIME, consume: consume)

      expect(result).to be_exhausted
      expect(result.hmac_count).to eq 3
      expect(recorder.count).to eq 3
    end

    it 'stops even before a colliding match is known to be ambiguous' do
      collision_b = described_class.authenticator(SECRET_B, id: :b, digits: 2)
      collision_a = described_class.authenticator(SECRET_A, id: :a, digits: 2)
      tight = described_class.new(max_hmac: 1, hmac: recorder)

      result = tight.verify(
        COLLISION_TOKEN, [collision_a, collision_b],
        at: COLLISION_TIME, consume: consume
      )

      expect(result).to be_exhausted
      expect(recorder.count).to eq 1
      expect(consumed).to be_empty
    end

    it 'rejects invalid parameters without spending any budget' do
      [
        verifier.verify(12_345, [authenticator_a], at: UNIQUE_TIME, consume: consume),
        verifier.verify(UNIQUE_TOKEN + "\n", [authenticator_a], at: UNIQUE_TIME, consume: consume),
        verifier.verify(UNIQUE_TOKEN, authenticator_a, at: UNIQUE_TIME, consume: consume),
        verifier.verify(UNIQUE_TOKEN, [], at: UNIQUE_TIME, consume: consume),
        verifier.verify(UNIQUE_TOKEN, [authenticator_a], at: -1, consume: consume),
        verifier.verify(UNIQUE_TOKEN, [authenticator_a], at: UNIQUE_TIME, consume: :nope),
        verifier.verify(UNIQUE_TOKEN, ['bogus'], at: UNIQUE_TIME, consume: consume)
      ].each do |result|
        expect(result).to be_rejected
        expect(result.hmac_count).to eq 0
        expect(result.consumed_at).to be_nil
      end

      expect(recorder.count).to eq 0
      expect(consumed).to be_empty
    end
  end

  describe 'consumption safety' do
    it 'does not consume B when B could also accept some other code' do
      # B's 2-digit code at UNIQUE_TIME is different from the 6-digit A code,
      # yet B is fully searched. The commit must target A's own position.
      b2 = described_class.authenticator(SECRET_B, id: :b, digits: 2)
      result = verifier.verify(
        UNIQUE_TOKEN, [b2, authenticator_a],
        at: UNIQUE_TIME, consume: consume
      )

      expect(result).to be_unique
      expect(result.authenticator.id).to eq :a
      expect(result.position).to eq 58_907_570
      expect(consumed).to eq [[:a, UNIQUE_TIME.to_i]]
    end

    it 'never consumes another authenticator that happens to share a token' do
      # SECRET_B verifies the token at the same instant with 2 digits; the
      # 6-digit request must stay pinned to SECRET_A and leave B untouched.
      other = described_class.authenticator(SECRET_B, id: :b, digits: 2)
      result = verifier.verify(
        UNIQUE_TOKEN, [authenticator_a, other],
        at: UNIQUE_TIME, consume: consume
      )

      expect(result).to be_unique
      expect(result.authenticator.id).to eq :a
      expect(consumed).to eq [[:a, UNIQUE_TIME.to_i]]
      expect(recorder.calls.map { |call| call[:key] }.uniq.size).to eq 2
    end

    it 'returns :conflict and consumes nothing when the CAS loses a race' do
      candidate = described_class.authenticator(
        SECRET_A, id: :a, consumed_through: nil
      )
      losing = lambda do |_auth, expected, unit|
        # Simulate another request moving the stored value between the read
        # and this compare-and-swap.
        expected.nil? && unit == UNIQUE_TIME.to_i ? false : true
      end

      result = verifier.verify(
        UNIQUE_TOKEN, [candidate], at: UNIQUE_TIME, consume: losing
      )

      expect(result).to be_conflict
      expect(result).not_to be_unique
      expect(result.consumed_at).to be_nil
    end

    it 'does not spend a HMAC on a window at or before the consumed unit' do
      candidate = described_class.authenticator(
        SECRET_A, id: :a, consumed_through: UNIQUE_TIME.to_i
      )

      result = verifier.verify(
        UNIQUE_TOKEN, [candidate], at: UNIQUE_TIME, consume: consume
      )

      expect(result).to be_invalid
      expect(recorder.count).to eq 0
      expect(consumed).to be_empty
    end

    it 'reports :unavailable instead of consuming without a callback' do
      result = verifier.verify(UNIQUE_TOKEN, [authenticator_a], at: UNIQUE_TIME)

      expect(result).to be_unavailable
      expect(result.authenticator.id).to eq :a
      expect(result.consumed_at).to be_nil
    end
  end

  describe 'legacy single-authenticator API' do
    it 'keeps TOTP#verify working unchanged' do
      totp = ROTP::TOTP.new(SECRET_A)

      expect(totp.verify(UNIQUE_TOKEN, at: UNIQUE_TIME)).to eq UNIQUE_TIME.to_i
      expect(totp.verify('000000', at: UNIQUE_TIME)).to be_nil
    end

    it 'keeps HOTP#verify working unchanged' do
      hotp = ROTP::HOTP.new(SECRET_B)

      expect(hotp.verify('287922', 6)).to eq 6
      expect(hotp.verify('287922', 7)).to be_nil
    end

    it 'accepts existing TOTP and HOTP instances as candidates' do
      hotp = ROTP::HOTP.new(SECRET_B)
      hotp_token = hotp.at(6)
      result = verifier.verify(
        hotp_token, [ROTP::TOTP.new(SECRET_A)], at: UNIQUE_TIME, consume: consume
      )
      # The HOTP token is not valid at UNIQUE_TIME, but the call must not
      # raise and must not consume.
      expect(result).to be_invalid
      expect(consumed).to be_empty
    end
  end

  describe 'OTP HMAC injection' do
    it 'lets a single TOTP count its own HMACs' do
      totp = ROTP::TOTP.new(SECRET_A, hmac: recorder)

      expect(totp.at(UNIQUE_TIME)).to eq UNIQUE_TOKEN
      expect(recorder.count).to eq 1
      expect(recorder.calls.first[:digest]).to eq 'sha1'
    end

    it 'rejects a backend that cannot digest' do
      expect { ROTP::TOTP.new(SECRET_A, hmac: Object.new) }
        .to raise_error(ArgumentError, /hmac/)
    end
  end
end
