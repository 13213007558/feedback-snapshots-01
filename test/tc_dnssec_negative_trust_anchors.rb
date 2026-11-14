require_relative 'spec_helper'
require 'openssl'
require 'base64'
require 'timeout'

class DnssecNegativeTrustAnchorsTest < Minitest::Test
  ZONE = 'broken.example.'.freeze
  SIBLING_ZONE = 'other.example.'.freeze
  EXTERNAL = 'cdn.external.test.'.freeze

  def setup
    Dnsruby::Dnssec.reset
    Dnsruby::Dnssec.validation_policy = Dnsruby::Dnssec::ValidationPolicy::ALWAYS_LOCAL_ANCHORS_ONLY
    @rsa = OpenSSL::PKey::RSA.generate(2048)
    @key = dnskey(ZONE)
    @key_rrset = signed(@key, @key, 'DNSKEY')
    Dnsruby::Dnssec.add_trust_anchor(@key)
    key_rrset = @key_rrset
    # Chain discovery would otherwise query the network; the configured anchor
    # is exactly the key the bogus zone uses, so verify with it directly.
    verifier.define_singleton_method(:follow_chain) do |anchor, _name|
      verify(key_rrset, anchor)
      key_rrset
    end
  end

  def teardown
    Dnsruby::Dnssec.reset
  end

  def test_registry_is_disabled_by_default
    assert(registry.empty?)
    assert_empty(registry.anchors)
    refute(Dnsruby::Dnssec.remove_negative_trust_anchor(ZONE))
  end

  def test_anchor_covers_apex_and_descendants_only
    Dnsruby::Dnssec.add_negative_trust_anchor(ZONE, Time.now + 60)
    anchor = registry.anchors.first
    assert(anchor.covers?(Dnsruby::Name.create('broken.example.')))
    assert(anchor.covers?(Dnsruby::Name.create('host.broken.example.')))
    assert(anchor.covers?(Dnsruby::Name.create('a.b.broken.example.')))
    refute(anchor.covers?(Dnsruby::Name.create('other.example.')))
    refute(anchor.covers?(Dnsruby::Name.create('example.')))
    # Case-insensitive canonical matching, but still the same scope.
    assert(anchor.covers?(Dnsruby::Name.create('HOST.Broken.Example.')))
  end

  def test_rejects_non_future_expiration
    assert_raises(ArgumentError) do
      Dnsruby::Dnssec.add_negative_trust_anchor(ZONE, Time.now - 1)
    end
    assert_raises(ArgumentError) do
      Dnsruby::Dnssec.add_negative_trust_anchor(ZONE, Time.now.to_i)
    end
    [Float::NAN, Float::INFINITY, 'tomorrow', nil].each do |bad|
      assert_raises(ArgumentError) do
        Dnsruby::Dnssec.add_negative_trust_anchor(ZONE, bad)
      end
    end
    assert(registry.empty?)
  end

  def test_bogus_response_without_exception_still_fails
    message = bogus_a_message("host.#{ZONE}")
    error = assert_raises(Dnsruby::VerifyError) { validate(message) }
    assert_equal(Dnsruby::Message::SecurityLevel.BOGUS, message.security_level)
    refute_nil(error)
  end

  def test_scoped_exception_marks_unverified_but_never_secure
    Dnsruby::Dnssec.add_negative_trust_anchor(ZONE, Time.now + 60)
    message = bogus_a_message("host.#{ZONE}")
    assert(validate(message))
    assert_equal(Dnsruby::Message::SecurityLevel.UNVERIFIEDEXCEPTION, message.security_level)
    refute_equal(Dnsruby::Message::SecurityLevel.SECURE, message.security_level)
    assert_nil(message.security_error)
    # Nothing observed during the failed validation is retained as trusted.
    assert_empty(verifier.trusted_keys)
  end

  def test_exception_does_not_downgrade_a_genuinely_secure_response
    Dnsruby::Dnssec.add_negative_trust_anchor(ZONE, Time.now + 60)
    message = secure_a_message("host.#{ZONE}")
    validate(message)
    assert_equal(Dnsruby::Message::SecurityLevel.SECURE, message.security_level)
  end

  def test_exception_does_not_relabel_an_insecure_unsigned_response
    # A provably unsigned zone with no trust anchor is INSECURE, not BOGUS;
    # the NTA must never relabel a response that did not fail validation.
    Dnsruby::Dnssec.clear_trust_anchors
    Dnsruby::Dnssec.clear_trusted_keys
    Dnsruby::Dnssec.add_negative_trust_anchor('unsigned.zone.', Time.now + 60)
    name = 'host.unsigned.zone.'
    message = Dnsruby::Message.new(name, 'A')
    message.add_answer(Dnsruby::RR.create("#{name} 300 IN A 192.0.2.7"))
    validate(message)
    assert_equal(Dnsruby::Message::SecurityLevel.INSECURE, message.security_level)
  end

  def test_sibling_zone_is_not_covered_by_the_exception
    sibling_key = dnskey(SIBLING_ZONE)
    Dnsruby::Dnssec.add_trust_anchor(sibling_key)
    Dnsruby::Dnssec.add_negative_trust_anchor(ZONE, Time.now + 60)
    message = bogus_a_message("host.#{SIBLING_ZONE}", sibling_key)
    # The sibling has its own anchor, so the broken signature is a real failure.
    assert_raises(Dnsruby::VerifyError) { validate(message) }
    assert_equal(Dnsruby::Message::SecurityLevel.BOGUS, message.security_level)
  end

  def test_cname_target_outside_scope_still_validates_and_fails
    Dnsruby::Dnssec.add_negative_trust_anchor(ZONE, Time.now + 60)
    qname = "www.#{ZONE}"
    message = Dnsruby::Message.new(qname, 'A')
    cname = Dnsruby::RR.create("#{qname} 300 IN CNAME #{EXTERNAL}")
    target = Dnsruby::RR.create("#{EXTERNAL} 300 IN A 192.0.2.9")
    message.add_answer(cname)
    message.add_answer(signed(cname, @key, 'CNAME').sigs.first)
    message.add_answer(target)
    message.add_answer(bogus_signature(target, @key).first)
    assert_raises(Dnsruby::VerifyError) { validate(message) }
    assert_equal(Dnsruby::Message::SecurityLevel.BOGUS, message.security_level)
  end

  def test_cname_target_inside_scope_is_covered
    Dnsruby::Dnssec.add_negative_trust_anchor(ZONE, Time.now + 60)
    qname = "www.#{ZONE}"
    target_name = "edge.#{ZONE}"
    message = Dnsruby::Message.new(qname, 'A')
    cname = Dnsruby::RR.create("#{qname} 300 IN CNAME #{target_name}.")
    target = Dnsruby::RR.create("#{target_name} 300 IN A 192.0.2.10")
    message.add_answer(cname)
    message.add_answer(signed(cname, @key, 'CNAME').sigs.first)
    message.add_answer(target)
    message.add_answer(bogus_signature(target, @key).first)
    assert(validate(message))
    assert_equal(Dnsruby::Message::SecurityLevel.UNVERIFIEDEXCEPTION, message.security_level)
  end

  def test_expired_exception_no_longer_bypasses_failure
    Dnsruby::Dnssec.add_negative_trust_anchor(ZONE, Time.now + 2)
    covered = bogus_a_message("host.#{ZONE}")
    assert(validate(covered))
    assert_equal(Dnsruby::Message::SecurityLevel.UNVERIFIEDEXCEPTION, covered.security_level)
    sleep 3
    message = bogus_a_message("host.#{ZONE}")
    assert_raises(Dnsruby::VerifyError) { validate(message) }
    assert_equal(Dnsruby::Message::SecurityLevel.BOGUS, message.security_level)
    assert(registry.empty?)
  end

  def test_revocation_takes_effect_immediately
    Dnsruby::Dnssec.add_negative_trust_anchor(ZONE, Time.now + 60)
    assert(Dnsruby::Dnssec.remove_negative_trust_anchor(ZONE))
    message = bogus_a_message("host.#{ZONE}")
    assert_raises(Dnsruby::VerifyError) { validate(message) }
    assert_equal(Dnsruby::Message::SecurityLevel.BOGUS, message.security_level)
  end

  def test_clear_revokes_all_exceptions
    Dnsruby::Dnssec.add_negative_trust_anchor(ZONE, Time.now + 60)
    Dnsruby::Dnssec.add_negative_trust_anchor(SIBLING_ZONE, Time.now + 60)
    Dnsruby::Dnssec.clear_negative_trust_anchors
    assert(registry.empty?)
    message = bogus_a_message("host.#{ZONE}")
    assert_raises(Dnsruby::VerifyError) { validate(message) }
  end

  def test_policy_change_during_validation_cannot_extend_the_exception
    # The NTA exists when validation starts but is revoked before the failure
    # decision. The captured generation must reject the late exception.
    Dnsruby::Dnssec.add_negative_trust_anchor(ZONE, Time.now + 60)
    message = bogus_a_message("host.#{ZONE}")
    pause_after(verifier, :find_closest_anchor_for,
      -> { Dnsruby::Dnssec.remove_negative_trust_anchor(ZONE) }) do
      assert_raises(Dnsruby::VerifyError) { validate(message) }
    end
    assert_equal(Dnsruby::Message::SecurityLevel.BOGUS, message.security_level)
    assert(registry.empty?)
  end

  def test_exception_added_during_validation_does_not_cover_in_flight_failure
    # No NTA at entry; one added while validation runs must not rescue a result
    # that began under the stricter policy.
    message = bogus_a_message("host.#{ZONE}")
    pause_after(verifier, :find_closest_anchor_for,
      -> { Dnsruby::Dnssec.add_negative_trust_anchor(ZONE, Time.now + 60) }) do
      assert_raises(Dnsruby::VerifyError) { validate(message) }
    end
    assert_equal(Dnsruby::Message::SecurityLevel.BOGUS, message.security_level)
    # A subsequent validation under the new generation may use the exception.
    later = bogus_a_message("host.#{ZONE}")
    assert(validate(later))
    assert_equal(Dnsruby::Message::SecurityLevel.UNVERIFIEDEXCEPTION, later.security_level)
  end

  def test_delayed_result_after_expiry_is_not_covered
    # The NTA is active when validation enters but expires while the result is
    # still in flight, so the failure decision must observe the expiry.
    Dnsruby::Dnssec.add_negative_trust_anchor(ZONE, Time.now + 1)
    message = bogus_a_message("host.#{ZONE}")
    pause_after(verifier, :find_closest_anchor_for, -> { sleep 2 }) do
      assert_raises(Dnsruby::VerifyError) { validate(message) }
    end
    assert_equal(Dnsruby::Message::SecurityLevel.BOGUS, message.security_level)
    assert(registry.empty?)
  end

  def test_exception_responses_are_not_cached
    Dnsruby::PacketSender.clear_caches
    Dnsruby::Dnssec.add_negative_trust_anchor(ZONE, Time.now + 60)
    query = Dnsruby::Message.new("host.#{ZONE}", 'A')
    message = bogus_a_message("host.#{ZONE}")
    assert(validate(message))
    Dnsruby::PacketSender.cache(query, message)
    assert_equal(0, Dnsruby::PacketSender.recursive_cache_length)
  ensure
    Dnsruby::PacketSender.clear_caches
  end

  def test_keys_seen_during_failed_validation_are_not_learned_as_trusted
    # Warm a genuinely learned descendant key through the anchor first.
    assert(verifier.verify(@key_rrset))
    refute_empty(verifier.trusted_keys)
    Dnsruby::Dnssec.add_negative_trust_anchor(ZONE, Time.now + 60)
    message = bogus_a_message("host.#{ZONE}")
    assert(validate(message))
    assert_equal(Dnsruby::Message::SecurityLevel.UNVERIFIEDEXCEPTION, message.security_level)
    # Learned trust is discarded on the exception; the configured anchor stays.
    assert_empty(verifier.trusted_keys)
    assert_equal([@key], Dnsruby::Dnssec.trust_anchors)
    # And the bogus key material cannot verify anything afterwards.
    assert_raises(Dnsruby::VerifyError) { verifier.verify_rrset(message.answer.rrsets('A').first) }
  end

  private

  def registry
    Dnsruby::Dnssec.negative_trust_anchors
  end

  def verifier
    Dnsruby::Dnssec.anchor_verifier
  end

  def validate(message)
    query = Dnsruby::Message.new(message.question.first.qname, message.question.first.qtype)
    query.header.cd = true
    Dnsruby::Dnssec.validate_with_query(query, message)
  end

  def dnskey(name)
    exponent = @rsa.e.to_s(2)
    key_data = Base64.strict_encode64([exponent.bytesize].pack('C') + exponent + @rsa.n.to_s(2))
    Dnsruby::RR.create("#{name} 300 IN DNSKEY 257 3 8 #{key_data}")
  end

  def sign(record, key, type_covered)
    signature = Dnsruby::RR.create(
      name: record.name, type: 'RRSIG', ttl: 300, type_covered: type_covered,
      algorithm: 8, labels: record.name.labels.length, original_ttl: 300,
      expiration: Time.now.to_i + 3600, inception: Time.now.to_i - 60,
      key_tag: key.key_tag, signers_name: key.name)
    data = Dnsruby::MessageEncoder.new { |encoder| encoder.put_rr(record, true) }.to_s
    signature.signature = @rsa.sign(OpenSSL::Digest::SHA256.new, signature.sig_data + data)
    signature
  end

  def signed(record, key, type_covered)
    Dnsruby::RRSet.new([record, sign(record, key, type_covered)])
  end

  def bogus_signature(record, key)
    signature = sign(record, key, record.type)
    signature.signature = signature.signature.dup.tap { |bytes| bytes.setbyte(0, bytes.getbyte(0) ^ 1) }
    [signature]
  end

  def address_message(name)
    record = Dnsruby::RR.create("#{name} 300 IN A 192.0.2.5")
    message = Dnsruby::Message.new(name, 'A')
    [message, record]
  end

  def bogus_a_message(name, key = @key)
    message, record = address_message(name)
    message.add_answer(record)
    message.add_answer(bogus_signature(record, key).first)
    message
  end

  def secure_a_message(name)
    message, record = address_message(name)
    message.add_answer(record)
    message.add_answer(sign(record, @key, 'A'))
    message
  end

  def pause_after(object, method_name, mutation)
    arrived, resume, start = Queue.new, Queue.new, Queue.new
    original = object.method(method_name)
    own_method = object.singleton_class.instance_methods(false).include?(method_name)
    object.singleton_class.remove_method(method_name) if own_method
    thread = nil
    object.define_singleton_method(method_name) do |*args|
      result = original.call(*args)
      if Thread.current.equal?(thread)
        arrived << true
        resume.pop
      end
      result
    end
    thread = Thread.new { start.pop; yield }
    start << true
    Timeout.timeout(5) { arrived.pop }
    Timeout.timeout(5) { mutation.call }
    resume << true
    Timeout.timeout(5) { thread.value }
  ensure
    object.singleton_class.remove_method(method_name) if original
    object.define_singleton_method(method_name, original) if own_method
    thread.kill if thread && thread.alive?
    thread.join if thread
  end
end
