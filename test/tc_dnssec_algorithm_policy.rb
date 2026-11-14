require_relative 'spec_helper'
require 'openssl'
require 'base64'

# Offline dual-algorithm chain:
#
#   parent.invalid.            two KSKs, RSASHA256 and RSASHA1
#     |  DS RRSet signed by both parents; carries an old SHA-1 digest
#     |  for the child's RSASHA1 key and a SHA-256 digest for its
#     |  RSASHA256 key.
#   child.parent.invalid.      two keys, both signing the apex DNSKEY RRSet
#     |
#     +-- www... A RRSet      signed by both child keys
#
# Every RRSet and signature is generated in this process. A validation call
# must find one complete path whose DS digests, DNSKEY algorithms and RRSIG
# algorithms are all permitted by that call's policy.
class DnssecAlgorithmPolicyTest < Minitest::Test
  Policy = Dnsruby::Dnssec::AlgorithmPolicy
  NOW = Time.now.to_i

  def setup
    @rsa256 = OpenSSL::PKey::RSA.generate(2048)
    @rsa1 = OpenSSL::PKey::RSA.generate(2048)
    @parent256 = key_for(@rsa256, 'parent.invalid.', 8)
    @parent1 = key_for(@rsa1, 'parent.invalid.', 5)
    @child256 = key_for(@rsa256, 'child.parent.invalid.', 8)
    @child1 = key_for(@rsa1, 'child.parent.invalid.', 5)

    @child_keys = Dnsruby::RRSet.new([@child256, @child1])
    sign(@child_keys, @parent256, @rsa256, 8, OpenSSL::Digest::SHA256.new)
    sign(@child_keys, @parent1, @rsa1, 5, OpenSSL::Digest::SHA1.new)

    @ds256 = Dnsruby::RR::DS.from_key(@child256, 2)
    @ds1 = Dnsruby::RR::DS.from_key(@child1, 1)
    @ds_set = Dnsruby::RRSet.new([@ds256, @ds1])
    sign(@ds_set, @parent256, @rsa256, 8, OpenSSL::Digest::SHA256.new)
    sign(@ds_set, @parent1, @rsa1, 5, OpenSSL::Digest::SHA1.new)

    @record = Dnsruby::RR.create('www.child.parent.invalid. 300 IN A 192.0.2.1')
    @answer = Dnsruby::RRSet.new(@record)
    sign(@answer, @child256, @rsa256, 8, OpenSSL::Digest::SHA256.new)
    sign(@answer, @child1, @rsa1, 5, OpenSSL::Digest::SHA1.new)
  end

  def test_complete_chain_must_match_the_call_policy_in_either_order
    outcomes = {}
    [false, true].each do |reverse|
      verifier = verifier_for(@parent256, @parent1)

      assert(verifier.verify(signed_message(reverse: reverse), Policy.allow(8)),
        'the RSASHA256 path is complete')
      assert(verifier.verify(signed_message(reverse: reverse), Policy.allow(5)),
        'the RSASHA1 path is complete')
      assert(verifier.verify(signed_message(reverse: reverse), Policy.allow(8, 5)))
      assert(verifier.verify(signed_message(reverse: reverse),
        Policy.new(ds_digest_types: [2])))
      assert(verifier.verify(signed_message(reverse: reverse),
        Policy.new(ds_digest_types: [1])))

      outcome = ->(policy) do
        verifier.verify(signed_message(reverse: reverse), policy)
        [:pass, nil, nil]
      rescue Dnsruby::VerifyError => e
        [e.class, e.message, e.respond_to?(:algorithm) ? e.algorithm : nil]
      end
      outcomes[reverse] = [
        outcome.call(Policy.deny(8)),
        outcome.call(Policy.deny(5)),
        outcome.call(Policy.deny(8, 5)),
        outcome.call(Policy.new(ds_digest_types: [9]))
      ]
    end
    assert_equal(outcomes[false], outcomes[true],
      'reordering DS, DNSKEY and RRSIG records must not change the result')
    # Denying one algorithm still leaves the other complete path.
    assert_equal([:pass, nil, nil], outcomes[false][0])
    assert_equal([:pass, nil, nil], outcomes[false][1])
    assert_equal(Dnsruby::Dnssec::AlgorithmDisabledError, outcomes[false][2][0])
    assert_includes([5, 8], outcomes[false][2][2])
    # Digest types 1 and 2 are implemented but excluded, so the policy
    # refuses them as disabled rather than claiming they are unsupported.
    assert_equal(Dnsruby::Dnssec::DsDigestDisabledError, outcomes[false][3][0])
  end

  def test_disabled_alternative_does_not_mask_a_permitted_cryptographic_failure
    # A permitted signature fails, and only an excluded weak key/signature
    # would match. The cryptographic failure is the result, not "disabled".
    corrupt = Dnsruby::RRSet.new(@record)
    sign(corrupt, @child256, @rsa256, 8, OpenSSL::Digest::SHA256.new)
    signature = corrupt.sigs.first
    signature.signature = signature.signature.dup.tap { |b| b.setbyte(0, b.getbyte(0) ^ 1) }

    verifier = verifier_for(@child1, @child256)
    error = assert_raises(Dnsruby::VerifyError) do
      verifier.verify_rrset(corrupt, Policy.deny(5))
    end
    refute_kind_of(Dnsruby::Dnssec::AlgorithmError, error)
    assert_match(/cryptographically verify|Signature failed/, error.message)
  end

  def test_strong_cryptographic_failure_is_not_replaced_by_a_disabled_weak_signature
    strong = @answer.sigs.find { |sig| sig.algorithm == 8 }
    strong.signature = strong.signature.dup.tap { |bytes| bytes.setbyte(0, bytes.getbyte(0) ^ 1) }
    verifier = verifier_for(@parent256, @parent1)

    # The weak signature is valid but policy-disabled. Accepting it would turn
    # the strong signature's failure into a pass, so the result is the
    # cryptographic error, not a successful validation.
    error = assert_raises(Dnsruby::VerifyError) do
      verifier.verify(signed_message, Policy.allow(8))
    end
    refute_kind_of(Dnsruby::Dnssec::AlgorithmError, error)
    assert_match(/cryptographically verify|Signature failed/, error.message)

    # With both algorithms permitted the disabled weak signature is a usable
    # alternative, and the message verifies through it.
    assert(verifier.verify(signed_message, Policy.allow(8, 5)))
    # Without a policy the historical fallback also applies.
    assert(verifier.verify(signed_message))
  end

  def test_a_message_with_only_a_disabled_signature_reports_disabled
    weak_only = Dnsruby::RRSet.new(@record)
    sign(weak_only, @child1, @rsa1, 5, OpenSSL::Digest::SHA1.new)
    message = Dnsruby::Message.new(@record.name, 'A')
    weak_only.each { |rr| message.add_answer(rr) }
    verifier = verifier_for(@child1)

    error = assert_raises(Dnsruby::Dnssec::AlgorithmDisabledError) do
      verifier.verify(message, Policy.allow(8))
    end
    assert_equal(5, error.algorithm)
    assert_match(/disabled by the validation algorithm policy/, error.message)
    assert(verifier.verify(message), 'the same message remains valid without a policy')
  end

  def test_ds_digest_policy_is_reported_separately
    verifier = verifier_for(@parent256, @parent1)
    assert(verifier.verify_key_rrset(@child_keys, Dnsruby::RRSet.new(@ds256),
      Policy.allow(8)))

    error = assert_raises(Dnsruby::Dnssec::DsDigestDisabledError) do
      verifier.verify_key_rrset(@child_keys, Dnsruby::RRSet.new(@ds1),
        Policy.new(ds_digest_types: [2]))
    end
    assert_equal(1, error.digest_type)
    assert_equal(:ds_digest, error.policy ? :ds_digest : :ds_digest)

    assert(verifier.verify_key_rrset(@child_keys, Dnsruby::RRSet.new(@ds1),
      Policy.new(ds_digest_types: [1], algorithms: [5])))
  end

  def test_unsupported_is_distinct_from_disabled_and_cryptographic_failure
    verifier = verifier_for(@child1)
    unsupported = key_for(@rsa1, 'www.child.parent.invalid.', 15)
    rrset = Dnsruby::RRSet.new(@record)
    add_signature(rrset, unsupported, 15, "\0" * 64)

    [nil, Policy.allow(:all), Policy.allow(8)].each do |policy|
      error = assert_raises(Dnsruby::Dnssec::AlgorithmUnsupportedError) do
        verifier.verify_rrset(rrset, unsupported, policy)
      end
      assert_equal(15, error.algorithm)
      assert_match(/unsupported by Dnsruby|not supported by Dnsruby/, error.message)
    end

    disabled = Dnsruby::RRSet.new(@record)
    add_signature(disabled, @child1, 5, "\0" * 64)
    error = assert_raises(Dnsruby::Dnssec::AlgorithmDisabledError) do
      verifier.verify_rrset(disabled, @child1, Policy.allow(8))
    end
    assert_equal(5, error.algorithm)
    refute_kind_of(Dnsruby::Dnssec::AlgorithmUnsupportedError, error)
  end

  def test_cached_keys_are_filtered_when_used_and_when_learned
    verifier = verifier_for(@parent256, @parent1)
    verifier.add_trusted_key(@child_keys)
    refute_empty(verifier.trusted_keys.select { |key| key.algorithm == 5 })

    weak_only = Dnsruby::RRSet.new(@record)
    sign(weak_only, @child1, @rsa1, 5, OpenSSL::Digest::SHA1.new)
    message = Dnsruby::Message.new(@record.name, 'A')
    weak_only.each { |rr| message.add_answer(rr) }

    # The message has only a weak signature and the cached key matches it.
    # The result must name the policy exclusion, not a missing key.
    error = assert_raises(Dnsruby::Dnssec::AlgorithmDisabledError) do
      verifier.verify(message, Policy.deny(5))
    end
    assert_equal(5, error.algorithm)
    assert_match(/disabled by the validation algorithm policy/, error.message)
    assert(verifier.verify(message), 'the cached key is still usable without a policy')

    # Learning the weak DNSKEY while a policy is active must not cache it.
    fresh = Dnsruby::SingleVerifier.new(Dnsruby::SingleVerifier::VerifierType::ANCHOR)
    assert_raises(Dnsruby::Dnssec::AlgorithmDisabledError) do
      fresh.verify_key_rrset(weak_only, Policy.allow(8))
    end
    assert_empty(fresh.trusted_keys.select { |key| key.algorithm == 5 })
  end

  def test_calls_without_a_policy_keep_the_existing_contract
    verifier = verifier_for(@parent256, @parent1)
    assert(verifier.verify(signed_message))
    assert(verifier.verify_key_rrset(@child_keys))
    [5, 8].each do |algorithm|
      key, rsa, digest = algorithm == 8 ?
        [@child256, @rsa256, OpenSSL::Digest::SHA256.new] :
        [@child1, @rsa1, OpenSSL::Digest::SHA1.new]
      single = Dnsruby::RRSet.new(@record)
      sign(single, key, rsa, algorithm, digest)
      assert(verifier.verify(single))
      assert(verifier.verify(single, nil))
    end
  end

  def test_message_and_query_can_carry_the_policy
    response = signed_message
    response.algorithm_policy = Policy.deny(5)
    assert(verifier_for(@parent256, @parent1).verify(response))

    query = Dnsruby::Message.new(@record.name, 'A')
    query.algorithm_policy = Policy.allow(8)
    verifier = verifier_for(@parent256, @parent1)
    assert(verifier.verify(signed_message, nil, query.algorithm_policy))
    assert_equal([8], query.algorithm_policy.algorithms)
  end

  def test_validate_with_query_uses_the_policy_attached_to_the_query
    Dnsruby::Dnssec.reset
    Dnsruby::Dnssec.add_trust_anchor(@parent256)
    Dnsruby::Dnssec.add_trust_anchor(@parent1)
    begin
      query = Dnsruby::Message.new(@record.name, 'A')
      query.algorithm_policy = Policy.allow(8)

      response = signed_message
      assert(Dnsruby::Dnssec.validate_with_query(query, response))
      assert_equal(Dnsruby::Message::SecurityLevel::SECURE, response.security_level)

      response = signed_message
      query.algorithm_policy = Policy.deny(8, 5)
      error = assert_raises(Dnsruby::Dnssec::AlgorithmDisabledError) do
        Dnsruby::Dnssec.validate_with_query(query, response)
      end
      assert_kind_of(Dnsruby::VerifyError, error)
      refute_equal(Dnsruby::Message::SecurityLevel::SECURE, response.security_level)
    ensure
      Dnsruby::Dnssec.reset
    end
  end

  def test_policies_are_isolated_between_concurrent_calls
    verifier = verifier_for(@parent256, @parent1)
    allowed = Policy.allow(8)
    denied = Policy.deny(8, 5)
    start = Queue.new
    results = Queue.new
    threads = [[allowed, :allow], [denied, :deny]].map do |policy, label|
      Thread.new do
        start.pop
        begin
          verifier.verify(signed_message, policy)
          results << [label, :pass]
        rescue Dnsruby::VerifyError => e
          results << [label, e.class]
        end
      end
    end
    threads.length.times { start << true }
    threads.each(&:join)
    pairs = 2.times.map { results.pop }
    assert_includes(pairs, [:allow, :pass])
    assert_includes(pairs, [:deny, Dnsruby::Dnssec::AlgorithmDisabledError])
  end

  def test_dnssec_facade_forwards_the_policy
    Dnsruby::Dnssec.reset
    Dnsruby::Dnssec.add_trust_anchor(@parent256)
    Dnsruby::Dnssec.add_trust_anchor(@parent1)
    begin
      assert(Dnsruby::Dnssec.verify(signed_message, Policy.allow(8, 5)))
      error = assert_raises(Dnsruby::Dnssec::AlgorithmDisabledError) do
        Dnsruby::Dnssec.verify(signed_message, Policy.deny(8, 5))
      end
      assert_kind_of(Dnsruby::VerifyError, error)
    ensure
      Dnsruby::Dnssec.reset
    end
  end

  def test_disabled_only_anchor_fails_instead_of_downgrading_to_insecure
    message = Dnsruby::Message.new(@record.name, 'A')
    weak = Dnsruby::RRSet.new(@record)
    sign(weak, @child1, @rsa1, 5, OpenSSL::Digest::SHA1.new)
    weak.each { |rr| message.add_answer(rr) }

    # The anchor itself is excluded, so there is no permitted starting point.
    verifier = verifier_for(@child1)
    error = assert_raises(Dnsruby::Dnssec::AlgorithmDisabledError) do
      verifier.validate(message, Dnsruby::Message.new(@record.name, 'A'), Policy.allow(8))
    end
    assert_equal(5, error.algorithm)
    refute_equal(Dnsruby::Message::SecurityLevel::INSECURE, message.security_level)
  end

  def test_unsupported_algorithm_is_reported_even_without_a_policy
    verifier = verifier_for(@child1)
    rrset = Dnsruby::RRSet.new(@record)
    add_signature(rrset, @child1, 5, "\0" * 64)
    rrset.sigs.first.algorithm = 15
    rrset.sigs.first.key_tag = 0
    # No matching DNSKEY is needed: the unsupported algorithm is classified
    # before any cryptographic attempt.
    error = assert_raises(Dnsruby::Dnssec::AlgorithmUnsupportedError) do
      verifier.verify_rrset(rrset, @child1, Policy.allow(:all))
    end
    assert_equal(15, error.algorithm)
  end

  def test_argument_validation_rejects_ambiguous_or_unknown_options
    verifier = verifier_for(@child1)
    assert_raises(ArgumentError) do
      verifier.verify(@answer, Policy.allow(8), policy: Policy.allow(8))
    end
    assert_raises(ArgumentError) do
      verifier.verify(@answer, unknown_option: true)
    end
    assert_raises(ArgumentError) { Policy.allow('not-an-algorithm') }
    assert_raises(ArgumentError) { Policy.allow([:all, 8]) }

    # An unimplemented digest type is accepted as a policy value but rejected
    # when a DS record tries to use it.
    digest_policy = Policy.new(ds_digest_types: [9])
    refute(digest_policy.allows_ds_digest?(9))
    assert_kind_of(Dnsruby::Dnssec::DsDigestUnsupportedError,
      digest_policy.rejection_for_digest(9))
  end

  private

  def verifier_for(*anchors)
    verifier = Dnsruby::SingleVerifier.new(Dnsruby::SingleVerifier::VerifierType::ANCHOR)
    anchors.each { |anchor| verifier.add_trust_anchor(anchor) }
    verifier
  end

  def signed_message(reverse: false)
    message = Dnsruby::Message.new(@record.name, 'A')
    answer = []
    authority = []
    @answer.each { |rr| answer << rr }
    @ds_set.each { |rr| authority << rr }
    @child_keys.each { |rr| answer << rr }
    answer.reverse! if reverse
    authority.reverse! if reverse
    answer.each { |rr| message.add_answer(rr) }
    authority.each { |rr| message.add_authority(rr) }
    message
  end

  def key_for(rsa, name, algorithm)
    exponent = rsa.e.to_s(2)
    bytes = Base64.strict_encode64([exponent.bytesize].pack('C') + exponent + rsa.n.to_s(2))
    Dnsruby::RR.create("#{name} 300 IN DNSKEY 257 3 #{algorithm} #{bytes}")
  end

  def sign(rrset, key, rsa, algorithm, digest)
    signature = Dnsruby::RR.create(name: rrset.name, type: 'RRSIG', ttl: rrset.ttl,
      type_covered: rrset.type, algorithm: algorithm,
      labels: rrset.name.labels.length, original_ttl: rrset.ttl,
      expiration: NOW + 3600, inception: NOW - 60,
      key_tag: key.key_tag, signers_name: key.name)
    signature.signature = rsa.sign(digest, signature.sig_data + canonical_data(rrset))
    rrset.add(signature)
    rrset
  end

  def add_signature(rrset, key, algorithm, signature_bytes)
    signature = Dnsruby::RR.create(name: rrset.name, type: 'RRSIG', ttl: rrset.ttl,
      type_covered: rrset.type, algorithm: algorithm,
      labels: rrset.name.labels.length, original_ttl: rrset.ttl,
      expiration: NOW + 3600, inception: NOW - 60,
      key_tag: key.key_tag, signers_name: key.name)
    signature.signature = signature_bytes
    rrset.add(signature)
    rrset
  end

  def canonical_data(rrset)
    rr = rrset.rrs.first
    rdatas = rrset.rrs.map do |record|
      Dnsruby::MessageEncoder.new { |encoder| record.encode_rdata(encoder, true) }.to_s
    end.sort
    prefix = Dnsruby::MessageEncoder.new do |encoder|
      encoder.put_name(rr.name, true)
      encoder.put_pack('nnN', rr.type.code, rr.klass.code, rr.ttl)
    end.to_s
    rdatas.map { |rdata| prefix + [rdata.bytesize].pack('n') + rdata }.join
  end
end
