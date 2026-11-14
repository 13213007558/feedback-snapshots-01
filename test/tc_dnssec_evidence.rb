require_relative 'spec_helper'
require 'minitest/mock'
require 'json'
require_relative 'dnssec_evidence_fixture'
require 'open3'
require 'rbconfig'
require 'tmpdir'

# Exercises the DNSSEC evidence export and its offline replay. The hierarchy
# is built in memory so no test depends on real DNS or long-lived keys.
class TestDnssecEvidence < Minitest::Test
  include Dnsruby

  TIME = Time.utc(2026, 11, 14, 12)
  ROOT = '.'
  ZONE = 'example.'
  HOST = 'www.example.'

  def setup
    @root_key = DnssecEvidenceFixture.key_for(ROOT).last
    @zone_key = DnssecEvidenceFixture.key_for(ZONE).last
    @root_keys = DnssecEvidenceFixture.zone_keys(ROOT)
    @zone_keys = DnssecEvidenceFixture.zone_keys(ZONE)
    @zone_ds = DnssecEvidenceFixture.ds_for(@zone_key)

    @root_keys.add(DnssecEvidenceFixture.sign(@root_keys, @root_key, at: TIME))
    @zone_keys.add(DnssecEvidenceFixture.sign(@zone_keys, @zone_key, at: TIME))
    @ds_rrset = RRSet.new([@zone_ds])
    @ds_rrset.add(DnssecEvidenceFixture.sign(@ds_rrset, @root_key, at: TIME))

    @answer = DnssecEvidenceFixture.signed(
      RR.create("#{HOST} 300 IN A 192.0.2.5"), @zone_key, at: TIME)
    # Apex answer used where the chain must terminate at the zone itself.
    @apex_answer = DnssecEvidenceFixture.signed(
      RR.create("#{ZONE} 300 IN A 192.0.2.6"), @zone_key, at: TIME)

    @responses = {
      [ROOT, Types.DNSKEY.code] => message_for(@root_keys),
      [ZONE, Types.DNSKEY.code] => message_for(@zone_keys),
      [ZONE, Types.DS.code] => message_for(@ds_rrset)
    }
    Dnsruby::Dnssec.default_resolver = FakeResolver.new(@responses)
  end

  def teardown
    Dnsruby::Dnssec.reset
  end

  def test_secure_capture_replays_offline_at_the_validation_time
    message = validate_secure
    evidence = message.validation_evidence
    refute_nil(evidence)
    assert_equal('SECURE', evidence.conclusion)
    assert_equal(TIME.to_i, evidence.validation_time)

    result = evidence.replay
    assert_equal('SECURE', result.security_level)
    assert_equal(evidence.explanation_digest, result.explanation_digest)

    steps = evidence.steps.select { |step| evidence.used_step_ids.include?(step['id']) }
    kinds = steps.map { |step| step['kind'] }
    assert_includes(kinds, 'trust_anchor')
    assert_includes(kinds, 'delegation')
    assert_includes(kinds, 'dnskey')
    assert(steps.any? { |step| step['kind'] == 'signature' && step['role'] == 'data' })
    assert(evidence.records.key?(steps.find { |s| s['kind'] == 'delegation' }['ds'].first))
  end

  def test_replay_from_json_string_does_not_touch_the_network
    evidence = validate_secure.validation_evidence
    document = evidence.to_json
    # Remove the resolver entirely: replay must not need one.
    Dnsruby::Dnssec.default_resolver = nil
    Dnsruby::Dnssec.do_validation_with_recursor(true)
    result = Dnsruby::ValidationEvidence.replay(document)
    assert_equal('SECURE', result.security_level)
  end

  def test_removing_a_required_evidence_record_fails_replay
    evidence = validate_secure.validation_evidence
    data_step = evidence.steps.find { |s| s['kind'] == 'signature' && s['role'] == 'data' }
    tampered = evidence.without_record(data_step['signature'])
    error = assert_raises(Dnsruby::ValidationEvidence::ReplayError) { tampered.replay }
    assert_match(/missing/, error.message)

    # Same for a key on the trust path.
    tampered = evidence.without_record(data_step['key'])
    assert_raises(Dnsruby::ValidationEvidence::ReplayError) { tampered.replay }
  end

  def test_removing_a_delegation_proof_fails_replay
    evidence = validate_secure.validation_evidence
    delegation = evidence.steps.find { |s| s['kind'] == 'delegation' }
    tampered = evidence.without_record(delegation['ds'].first)
    assert_raises(Dnsruby::ValidationEvidence::ReplayError) { tampered.replay }
  end

  def test_an_unrelated_valid_record_does_not_change_the_explanation
    evidence = validate_secure.validation_evidence
    unrelated = DnssecEvidenceFixture.signed(
      RR.create("other.example. 300 IN A 192.0.2.99"), @zone_key, at: TIME).sigs.first
    copy = evidence.with_record(unrelated)
    assert_equal(evidence.explanation_digest, copy.explanation_digest)
    assert_equal('SECURE', copy.replay.security_level)
    assert_equal(evidence.used_step_ids, copy.used_step_ids)
  end

  def test_an_extra_matching_signature_is_a_candidate_not_a_success_path
    # Capture a response that really carries two valid signatures over the
    # answer; the validator selects one and leaves the other a candidate.
    extra = DnssecEvidenceFixture.sign(RRSet.new(@answer.rrs), @zone_key, at: TIME)
    message = validate(extra_signatures: [extra])
    evidence = message.validation_evidence
    data_steps = evidence.used_steps.select { |s| s['kind'] == 'signature' && s['role'] == 'data' }
    assert_equal(1, data_steps.length)
    selected = data_steps.first['signature']
    assert(copy_candidates = evidence.candidates.select { |c| c['signature'] })
    refute(copy_candidates.any? { |c| c['signature'] == selected })
    assert_equal(1, evidence.candidates.length)
    assert(evidence.candidates.first['selected'] == false)
    # Candidates are not part of the explanation.
    assert_equal(evidence.explanation_digest, evidence.recompute_explanation_digest)
    assert_equal('SECURE', evidence.replay.security_level)
    # Dropping the unused candidate changes nothing either.
    doc = evidence.to_h
    doc['candidates'] = []
    assert_equal('SECURE', Dnsruby::ValidationEvidence.new(doc).replay.security_level)
  end

  def test_adding_a_valid_extra_signature_to_the_actual_response_keeps_the_digest
    baseline = validate_secure.validation_evidence
    extra = DnssecEvidenceFixture.sign(RRSet.new(baseline_answer_rrs), @zone_key, at: TIME)
    extended = validate(extra_signatures: [extra]).validation_evidence
    assert_equal(baseline.explanation_digest, extended.explanation_digest)
    assert_equal(baseline.used_step_ids, extended.used_step_ids)
    assert_equal('SECURE', extended.replay.security_level)
    # The unused signature is accounted for, but outside the explanation.
    excluded = extended.candidates.map { |c| c['signature'] }
    selected = extended.used_steps.select { |s| s['kind'] == 'signature' }
      .map { |s| s['signature'] }
    refute_empty(excluded)
    assert_empty(excluded & selected)
  end

  def test_replay_honours_a_fixed_time_that_makes_the_signature_expire
    evidence = validate_secure.validation_evidence
    assert_raises(Dnsruby::ValidationEvidence::ReplayError) do
      evidence.replay(time: TIME + 30 * 24 * 3600)
    end
  end

  def test_replay_at_a_recorded_time_and_policy_round_trips_through_json
    evidence = validate_secure.validation_evidence
    pinned = Dnsruby::ValidationEvidence.from(evidence.to_json)
    pinned = pinned.with_validation_time(evidence.validation_time)
    result = pinned.replay(time: pinned.validation_time, policy: pinned.policy)
    assert_equal('SECURE', result.security_level)
    assert_equal(evidence.explanation_digest, result.explanation_digest)
    assert(result.steps.all? { |step| evidence.used_step_ids.include?(step) })
  end

  def test_failed_candidate_signature_stays_out_of_the_success_explanation
    evidence = validate_secure.validation_evidence
    doc = evidence.to_h
    # A candidate that would not verify is listed separately and must not
    # become part of the explanation digest.
    doc['candidates'] << { 'name' => HOST, 'type' => 'A', 'signature' => nil,
                           'selected' => false, 'reason' => 'corrupt candidate' }
    copy = Dnsruby::ValidationEvidence.new(doc)
    assert_equal(evidence.explanation_digest, copy.explanation_digest)
    assert_equal('SECURE', copy.replay.security_level)
    assert_equal(1, copy.candidates.length)
  end

  def test_replay_requires_the_policy_anchor
    evidence = validate_secure.validation_evidence
    policy = Dnsruby::ValidationEvidence.deep_copy(evidence.policy)
    policy['trust_anchors'] = []
    assert_raises(Dnsruby::ValidationEvidence::ReplayError) do
      evidence.replay(policy: policy)
    end
  end

  def test_tampered_integrity_is_detected
    evidence = validate_secure.validation_evidence
    doc = evidence.to_h
    record = doc['records'][evidence.explanation_record_ids.first]
    # Flip one signature/key byte while keeping the record's shape valid.
    wire = record['wire'].dup
    wire[-2, 2] = format('%02x', wire[-2, 2].to_i(16) ^ 1)
    record['wire'] = wire
    tampered = Dnsruby::ValidationEvidence.new(doc)
    refute(tampered.integrity_ok?)
    assert_raises(Dnsruby::ValidationEvidence::ReplayError) { tampered.replay }
  end

  def test_warm_key_cache_reuse_cites_the_prior_validation
    first = validate_secure
    assert_equal('SECURE', first.security_level.to_s)
    second = validate(name: 'other.example.', reset: false,
      answer: DnssecEvidenceFixture.signed(
        RR.create("other.example. 300 IN A 192.0.2.7"), @zone_key, at: TIME))
    evidence = second.validation_evidence
    assert_equal('SECURE', evidence.conclusion)
    assert_equal('SECURE', evidence.replay.security_level)
    # The warm path starts at a learned key, and that key is justified by the
    # earlier proof included in the export.
    learned = evidence.used_steps.find { |step| step['kind'] == 'learned_key' }
    refute_nil(learned)
    refute_empty(evidence.data['prior_evidence'])
    prior = evidence.data['prior_evidence'].first
    assert_equal(first.validation_evidence.explanation_digest, prior['explanation_digest'])

    # Removing the cited prior proof breaks the warm-cache explanation.
    doc = evidence.to_h
    doc['prior_evidence'] = []
    assert_raises(Dnsruby::ValidationEvidence::ReplayError) do
      Dnsruby::ValidationEvidence.new(doc).replay
    end
  end

  def test_bogus_conclusion_keeps_the_steps_that_failed
    message = validate(answer: @apex_answer, name: ZONE,
      mutate_answer: ->(rrset) { corrupt_signature(rrset.sigs.first) })
    evidence = message.validation_evidence
    assert_equal('BOGUS', evidence.conclusion)
    assert_equal('BOGUS', message.security_level.to_s)
    failures = evidence.steps.select { |s| s['status'] == 'verified' && s['kind'] == 'signature_failure' }
    refute_empty(failures, 'a bogus conclusion must retain the failing step')
    # The replay reproduces BOGUS from the recorded failure.
    assert_equal('BOGUS', evidence.replay.security_level)
  end

  def test_nxdomain_evidence_contains_the_signed_denial_proof
    message = validate_denial
    evidence = message.validation_evidence
    assert_equal('SECURE', evidence.conclusion)
    denial = evidence.steps.find { |step| step['kind'] == 'denial' }
    refute_nil(denial)
    assert_equal('name_error', denial['proof'])
    refute_empty(denial['records'])
    refute_empty(denial['signature_steps'], 'the denial must cite its own signature step')
    nsec_id = denial['records'].first
    assert_equal('NSEC', evidence.records[nsec_id]['type'])
    assert_equal('SECURE', evidence.replay.security_level)

    tampered = evidence.without_record(nsec_id)
    assert_raises(Dnsruby::ValidationEvidence::ReplayError) { tampered.replay }
  end

  def test_cache_hit_without_prior_evidence_says_so
    message = Message.new(HOST, 'A')
    (DnssecEvidenceFixture.signed(RR.create("#{HOST} 300 IN A 192.0.2.5"), @zone_key, at: TIME)).rrs.each do |rr|
      message.add_answer(rr)
    end
    message.security_level = Message::SecurityLevel.UNCHECKED
    cache = Dnsruby::Cache.new
    cache.add(message)
    cached = cache.find(HOST, Types.A)
    assert(cached.cached)
    assert_nil(cached.validation_evidence)
  end

  def test_cache_hit_carries_the_original_evidence
    message = validate_secure
    evidence = message.validation_evidence
    cache = Dnsruby::Cache.new
    cache.add(message)
    cached = cache.find(HOST, Types.A)
    assert(cached.cached)
    assert_equal(message.security_level, cached.security_level)
    assert_equal(evidence.explanation_digest, cached.validation_evidence.explanation_digest)
    assert(cached.validation_evidence.cache_hit?)
    assert_equal('SECURE', cached.validation_evidence.cache['original_conclusion'])
    assert_equal(evidence.explanation_digest,
      cached.validation_evidence.cache['original_explanation_digest'])
    assert_equal('SECURE', cached.validation_evidence.replay.security_level)
  end

  def test_cli_replays_an_exported_document
    evidence = validate_secure.validation_evidence
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'evidence.json')
      File.write(path, evidence.to_json)
      command = [RbConfig.ruby, '-I', File.expand_path('../lib', __dir__),
                 File.expand_path('../bin/dnssec-evidence', __dir__), 'replay', path]
      stdout, stderr, status = Open3.capture3(*command)
      assert(status.success?, "#{stdout}\n#{stderr}")
      assert_empty(stderr)
      report = JSON.parse(stdout)
      assert_equal('SECURE', report['conclusion'])
      assert_equal(evidence.explanation_digest, report['explanation_digest'])
    end
  end

  def test_cli_reports_a_missing_record_as_a_failure
    evidence = validate_secure.validation_evidence
    data_step = evidence.steps.find { |s| s['kind'] == 'signature' && s['role'] == 'data' }
    tampered = evidence.without_record(data_step['key'])
    Dir.mktmpdir do |dir|
      path = File.join(dir, 'evidence.json')
      File.write(path, tampered.to_json)
      _stdout, stderr, status = Open3.capture3(
        RbConfig.ruby, File.expand_path('../bin/dnssec-evidence', __dir__), 'replay', path)
      refute(status.success?)
      assert_match(/missing/, stderr)
    end
  end

  private

  def message_for(rrset)
    message = Message.new(rrset.name.to_s(true), rrset.type)
    rrset.rrs.each { |rr| message.add_answer(rr) }
    rrset.sigs.each { |rr| message.add_answer(rr) }
    message
  end

  def validate_secure
    validate
  end

  def baseline_answer_rrs
    @answer.rrs
  end

  def validate_denial
    soa = RR.create("#{ZONE} 300 IN SOA ns.example. host.example. 1 60 60 60 60")
    soa_set = DnssecEvidenceFixture.signed(soa, @zone_key, at: TIME)
    # Two NSECs: one covers m.example., the other shows no wildcard expansion.
    nsec_sets = [
      RRSet.new([RR.create("#{ZONE} 300 IN NSEC zzz.example. A NS SOA NSEC RRSIG DNSKEY")]),
      RRSet.new([RR.create('zzz.example. 300 IN NSEC example. A NS SOA NSEC RRSIG DNSKEY')])
    ]
    nsec_sets.each { |rrset| rrset.add(DnssecEvidenceFixture.sign(rrset, @zone_key, at: TIME)) }

    Dnsruby::Dnssec.reset
    Dnsruby::Dnssec.clear_trust_anchors
    Dnsruby::Dnssec.clear_trusted_keys
    Dnsruby::Dnssec.add_trust_anchor(@root_key)
    Dnsruby::Dnssec.default_resolver = FakeResolver.new(@responses)
    Dnsruby::Dnssec.do_validation_with_recursor(false)
    Dnsruby::Dnssec.validation_policy = Dnsruby::Dnssec::ValidationPolicy::ALWAYS_LOCAL_ANCHORS_ONLY

    query = Message.new('m.example.', 'A')
    query.header.cd = true
    message = Message.new('m.example.', 'A')
    message.header.rcode = RCode.NXDOMAIN
    ([soa_set] + nsec_sets).each do |rrset|
      rrset.rrs.each { |rr| message.add_authority(rr) }
      rrset.sigs.each { |rr| message.add_authority(rr) }
    end
    Dnsruby::ValidationClock.with_time(TIME) do
      Dnsruby::Dnssec.validate_with_query(query, message)
    end
    message
  end

  def validate(answer: @answer, name: HOST, mutate_answer: nil, extra_signatures: [], reset: true)
    if mutate_answer
      rrset = RRSet.new(answer.rrs)
      answer.sigs.each { |sig| rrset.add(sig) }
      mutate_answer.call(rrset)
      answer = rrset
    end
    if reset
      Dnsruby::Dnssec.reset
      Dnsruby::Dnssec.clear_trust_anchors
      Dnsruby::Dnssec.clear_trusted_keys
      Dnsruby::Dnssec.add_trust_anchor(@root_key)
      Dnsruby::Dnssec.default_resolver = FakeResolver.new(@responses)
      Dnsruby::Dnssec.do_validation_with_recursor(false)
      Dnsruby::Dnssec.validation_policy = Dnsruby::Dnssec::ValidationPolicy::ALWAYS_LOCAL_ANCHORS_ONLY
    end

    query = Message.new(name, 'A')
    query.header.cd = true
    message = Message.new(name, 'A')
    answer.rrs.each { |rr| message.add_answer(rr) }
    (answer.sigs + extra_signatures).each { |rr| message.add_answer(rr) }
    begin
      Dnsruby::ValidationClock.with_time(TIME) do
        Dnsruby::Dnssec.validate_with_query(query, message)
      end
    rescue Dnsruby::VerifyError
      # Bogus conclusions still carry evidence; asserts check the level.
    end
    message
  end

  def corrupt_signature(signature)
    bytes = signature.signature.dup
    bytes.setbyte(0, bytes.getbyte(0) ^ 1)
    signature.signature = bytes
  end

  class FakeResolver
    attr_accessor :dnssec

    def initialize(responses)
      @responses = responses
      @dnssec = true
    end

    def query_no_validation_or_recursion(name, type)
      key = [Dnsruby::Name.create(name).to_s(true), Dnsruby::Types.new(type).code]
      response = @responses[key]
      raise Dnsruby::ResolvError, "no fixture for #{key.inspect}" unless response
      response.clone
    end
  end
end
