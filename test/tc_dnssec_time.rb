require_relative 'spec_helper'
require_relative 'tc_key_cache_identity'
require 'minitest/mock'
require 'openssl'

class DnssecSerialTimeTest < Minitest::Test
  MODULUS = 1 << 32
  HALF = MODULUS >> 1

  def test_serial_comparison_orders_across_the_wrap
    assert_equal(-1, Dnsruby::DnssecTime.compare(MODULUS - 16, 16))
    assert_equal(1, Dnsruby::DnssecTime.compare(16, MODULUS - 16))
    assert_equal(0, Dnsruby::DnssecTime.compare(3, 3 + MODULUS))
    assert_nil(Dnsruby::DnssecTime.compare(0, HALF))
    assert_nil(Dnsruby::DnssecTime.compare(HALF, 0))
  end

  def test_distance_is_signed_and_undefined_at_the_half_range
    assert_equal(16, Dnsruby::DnssecTime.distance(MODULUS - 8, 8))
    assert_equal(-16, Dnsruby::DnssecTime.distance(8, MODULUS - 8))
    assert_nil(Dnsruby::DnssecTime.distance(0, HALF))
  end

  def test_cross_wrap_validity_boundaries
    inception = MODULUS - 256
    expiration = 256
    assert_equal(Dnsruby::DnssecTime::VALID,
      Dnsruby::DnssecTime.signature_validity(inception, expiration, 0))
    assert_equal(Dnsruby::DnssecTime::VALID,
      Dnsruby::DnssecTime.signature_validity(inception, expiration, inception))
    assert_equal(Dnsruby::DnssecTime::VALID,
      Dnsruby::DnssecTime.signature_validity(inception, expiration, expiration))
    assert_equal(Dnsruby::DnssecTime::NOT_YET_VALID,
      Dnsruby::DnssecTime.signature_validity(inception, expiration, inception - 1))
    assert_equal(Dnsruby::DnssecTime::EXPIRED,
      Dnsruby::DnssecTime.signature_validity(inception, expiration, expiration + 1))
  end

  def test_non_wrapping_validity_boundaries
    inception = 1000
    expiration = 2000
    assert_equal(Dnsruby::DnssecTime::NOT_YET_VALID,
      Dnsruby::DnssecTime.signature_validity(inception, expiration, 999))
    assert_equal(Dnsruby::DnssecTime::VALID,
      Dnsruby::DnssecTime.signature_validity(inception, expiration, 1000))
    assert_equal(Dnsruby::DnssecTime::VALID,
      Dnsruby::DnssecTime.signature_validity(inception, expiration, 2000))
    assert_equal(Dnsruby::DnssecTime::EXPIRED,
      Dnsruby::DnssecTime.signature_validity(inception, expiration, 2001))
    assert_equal(Dnsruby::DnssecTime::INVALID,
      Dnsruby::DnssecTime.signature_validity(expiration, inception, 1500))
  end

  def test_indeterminate_intervals_are_rejected
    assert_equal(Dnsruby::DnssecTime::INDETERMINATE,
      Dnsruby::DnssecTime.signature_validity(0, HALF, 0))
    assert_equal(Dnsruby::DnssecTime::INDETERMINATE,
      Dnsruby::DnssecTime.signature_validity(0, 10, HALF))
    refute(Dnsruby::DnssecTime.valid?(0, HALF, 0))
  end

  def test_expiration_time_follows_the_serial_view
    now = MODULUS - 512
    assert_equal(now + 512, Dnsruby::DnssecTime.expiration_time(0, now))
    assert_nil(Dnsruby::DnssecTime.expiration_time(HALF, 0))
  end
end

class KeyCacheIdentityTest
  def test_verifier_uses_inclusive_serial_validity_boundaries
    now = @now.to_i
    records = resigned(signed(@record, @a, 0), @a, 0,
      inception: now, expiration: now + 60)
    [now, now + 60].each do |clock|
      Time.stub(:now, Time.at(clock)) do
        assert(@verifier.verify_rrset(records, @a))
      end
    end
    [[:before, now - 1], [:after, now + 61]].each do |_mode, clock|
      Time.stub(:now, Time.at(clock)) do
        error = assert_raises(Dnsruby::VerifyError) { @verifier.verify_rrset(records, @a) }
        assert_match(/not in validity period/, error.message)
      end
    end
  end

  def test_cross_wrap_signature_and_learned_key_expiry
    now = (1 << 32) - 512
    key_expiration = (now + 512) % (1 << 32)
    answer_expiration = (now + 600) % (1 << 32)
    verifier = Dnsruby::SingleVerifier.new(Dnsruby::SingleVerifier::VerifierType::ANCHOR)
    verifier.add_trust_anchor(Dnsruby::RR::DS.from_key(@a, 2))

    Time.stub(:now, Time.at(now)) do
      key_rrset = resigned(signed(@a, @a, 0), @a, 0,
        inception: (now - 60) % (1 << 32), expiration: key_expiration)
      assert(verifier.verify(key_rrset))
      assert_equal([Dnsruby::KeyCache.key_identity(@a)],
        verifier.get_keys_to_check.map { |key| Dnsruby::KeyCache.key_identity(key) })
      assert(verifier.verify(resigned(signed(@record, @a, 0), @a, 0,
        inception: (now - 60) % (1 << 32), expiration: answer_expiration)))
    end

    Time.stub(:now, Time.at(now + 511)) do
      assert_equal([Dnsruby::KeyCache.key_identity(@a)],
        verifier.get_keys_to_check.map { |key| Dnsruby::KeyCache.key_identity(key) })
    end

    Time.stub(:now, Time.at(now + 513)) do
      # The answer's own signature is still valid; the key learned from the
      # DS-signed DNSKEY RRset must not outlive its authenticating signature.
      assert_empty(verifier.get_keys_to_check)
      error = assert_raises(Dnsruby::VerifyError) do
        verifier.verify(resigned(signed(@record, @a, 0), @a, 0,
          inception: (now - 60) % (1 << 32), expiration: answer_expiration))
      end
      assert_match(/Signing key not found/, error.message)
    end
  end

  def test_key_cache_stores_wrapped_expiration_as_civil_time
    now = (1 << 32) - 512
    key_rrset = resigned(signed(@a, @a, 0), @a, 0,
      inception: (now - 60) % (1 << 32), expiration: (now + 512) % (1 << 32))
    Time.stub(:now, Time.at(now)) do
      @cache.add_rrset(key_rrset)
      expirations, keys = @cache.keys_and_expirations.transpose
      assert_equal([now + 512], expirations)
      assert_equal([Dnsruby::KeyCache.key_identity(@a)],
        keys.map { |key| Dnsruby::KeyCache.key_identity(key) })
    end
    Time.stub(:now, Time.at(now + 511)) do
      assert_equal([Dnsruby::KeyCache.key_identity(@a)],
        @cache.keys.map { |key| Dnsruby::KeyCache.key_identity(key) })
    end
    Time.stub(:now, Time.at(now + 513)) { assert_empty(@cache.keys) }
  end

  def test_key_cache_does_not_add_keys_from_expired_wrapped_signatures
    now = 0
    expired = resigned(signed(@a, @a, 0), @a, 0,
      inception: (1 << 32) - 256, expiration: (1 << 32) - 16)
    Time.stub(:now, Time.at(now)) do
      @cache.add_rrset(expired)
      assert_empty(@cache.keys)
    end
  end

  private

  def resigned(records, key, signer, inception:, expiration:, ttl: 300)
    record = records.rrs.first
    signature = Dnsruby::RR.create(name: record.name, type: 'RRSIG', ttl: ttl,
      type_covered: record.type, algorithm: 13, labels: record.name.labels.length,
      original_ttl: ttl, expiration: expiration, inception: inception,
      key_tag: key.key_tag, signers_name: key.name)
    data = Dnsruby::MessageEncoder.new { |encoder| encoder.put_rr(record, true) }.to_s
    der = @private_keys[signer].dsa_sign_asn1(OpenSSL::Digest::SHA256.digest(signature.sig_data + data))
    signature.signature = OpenSSL::ASN1.decode(der).value.map { |n| n.value.to_s(2).rjust(32, "\0") }.join
    Dnsruby::RRSet.new([record, signature])
  end
end

class DnssecSerialValidationViewTest < Minitest::Test
  def setup
    Dnsruby::Dnssec.reset
    @rsa = OpenSSL::PKey::RSA.generate(2048)
    exponent = @rsa.e.to_s(2)
    key_data = Base64.strict_encode64([exponent.bytesize].pack('C') + exponent + @rsa.n.to_s(2))
    @key = Dnsruby::RR.create("serial.invalid. 300 IN DNSKEY 257 3 8 #{key_data}")
    @record = Dnsruby::RR.create('www.serial.invalid. 300 IN A 192.0.2.10')
  end

  def teardown
    Dnsruby::Dnssec.reset
  end

  def test_one_validation_uses_one_time_view_across_wrap
    now = (1 << 32) - 10
    key_set = signed(@key, @key, inception: now - 60, expiration: (now + 100) % (1 << 32))
    answer = signed(@record, @key, inception: now - 60, expiration: (now + 200) % (1 << 32))

    verifier = Dnsruby::SingleVerifier.new(Dnsruby::SingleVerifier::VerifierType::ANCHOR)
    # Anchor expiry is absolute Unix time; keep it beyond the simulated clock.
    verifier.add_trust_anchor_with_expiration(@key, now + 3600)

    # The budget captures the validation view once. Advancing the wall clock
    # after that must not change any decision in the same validation.
    clock = now
    Time.stub(:now, -> { Time.at(clock) }) do
      budget = Dnsruby::ValidationBudget.new(now: now)
      Dnsruby::ValidationBudget.with(budget) do
        clock = now + 150
        assert(verifier.verify_key_rrset(key_set))
        assert(verifier.verify_rrset(answer))
      end
    end
  end

  def test_expired_signature_cannot_leave_its_chain_trusted
    now = 10_000
    verifier = Dnsruby::SingleVerifier.new(Dnsruby::SingleVerifier::VerifierType::ANCHOR)
    verifier.add_trust_anchor(Dnsruby::RR::DS.from_key(@key, 2))
    key_set = signed(@key, @key, inception: now - 60, expiration: now + 10)
    answer = signed(@record, @key, inception: now - 60, expiration: now + 3600)

    Time.stub(:now, Time.at(now)) do
      assert(verifier.verify(key_set))
      assert(verifier.verify(answer))
    end

    Time.stub(:now, Time.at(now + 11)) do
      assert_empty(verifier.trusted_keys.select { |key| key.type == Dnsruby::Types.DNSKEY })
      error = assert_raises(Dnsruby::VerifyError) { verifier.verify(answer) }
      assert_match(/Signing key not found/, error.message)
    end
  end

  private

  def signed(record, key, inception:, expiration:, ttl: 300)
    signature = Dnsruby::RR.create(name: record.name, type: 'RRSIG', ttl: ttl,
      type_covered: record.type, algorithm: 8, labels: record.name.labels.length,
      original_ttl: ttl, expiration: expiration, inception: inception,
      key_tag: key.key_tag, signers_name: key.name)
    data = Dnsruby::MessageEncoder.new { |encoder| encoder.put_rr(record, true) }.to_s
    signature.signature = @rsa.sign(OpenSSL::Digest::SHA256.new, signature.sig_data + data)
    Dnsruby::RRSet.new([record, signature])
  end
end
