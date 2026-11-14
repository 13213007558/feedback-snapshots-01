# --
# Copyright 2007 Nominet UK
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ++

require_relative 'spec_helper'
require_relative 'fixtures/nsec3/nsec3_zone_builder'

# End-to-end checks of RFC 5155 authenticated denial of existence. The zone
# material is generated locally (see Nsec3ZoneBuilder); every negative answer
# carries real RRSIGs over a coherent NSEC3 chain, so each mutation below
# demonstrates exactly which proof record keeps the answer verifiable.
class Nsec3VerificationTest < Minitest::Test
  include Dnsruby

  def setup
    @zone = Nsec3ZoneBuilder.build
    @verifier = SingleVerifier.new(SingleVerifier::VerifierType::ANCHOR)
    @verifier.add_trust_anchor(@zone.dnskey)
    @responses = @zone.responses
  end

  # ----------------------------------------------------------------------
  # NSEC3 hash primitives
  # ----------------------------------------------------------------------

  def test_nsec3_matches_its_original_owner_name
    @zone.nsec3s.each do |nsec3|
      original = Nsec3ZoneBuilder::NAMES.find do |name|
        nsec3.name.labels[0].string == @zone.hash_hex(name)
      end
      assert(original, "chain record must correspond to a fixture name")
      assert(nsec3.matches_name?(original), "#{nsec3.name} should match #{original}")
      refute(nsec3.covers_name?(original), "a matching record must not also cover its owner")
    end
  end

  def test_nsec3_span_covers_names_between_owner_and_next
    # H(corp.example.) sits inside one ordinary span of the generated chain.
    cover = @zone.nsec3s.find { |n| n.covers_name?('corp.example.') }
    refute_nil(cover)
    refute(cover.matches_name?('corp.example.'))
  end

  def test_final_nsec3_wraps_around_the_hash_ring
    last = @zone.nsec3s.find { |n| n.owner_hash >= n.next_hashed }
    refute_nil(last, "a finite chain has one wrap-around record")
    record = fixed_span(last)
    record.target_hash = midpoint(+"\x00" * 20, last.next_hashed)
    assert(record.covers_name?(TARGET_NAME), "hash below next_hashed is covered")
    record.target_hash = midpoint(last.owner_hash, +"\xff" * 20)
    assert(record.covers_name?(TARGET_NAME), "hash above owner hash is covered")
    record.target_hash = last.owner_hash
    refute(record.covers_name?(TARGET_NAME), "owner hash matches, it is not covered")
  end

  def test_non_wrapping_span_uses_strict_between_ordering
    middle = @zone.nsec3s.find { |n| n.owner_hash < n.next_hashed }
    refute_nil(middle)
    record = fixed_span(middle)
    record.target_hash = midpoint(middle.owner_hash, middle.next_hashed)
    assert(record.covers_name?(TARGET_NAME))
    record.target_hash = midpoint(+"\x00" * 20, middle.owner_hash)
    refute(record.covers_name?(TARGET_NAME), "hash before owner is outside the span")
    record.target_hash = midpoint(middle.next_hashed, +"\xff" * 20)
    refute(record.covers_name?(TARGET_NAME), "hash after next_hashed is outside the span")
    record.target_hash = middle.owner_hash
    refute(record.covers_name?(TARGET_NAME))
  end

  # Arithmetic mean of two 20-octet big-endian values.
  def midpoint(left, right)
    left_int = left.bytes.reduce(0) { |acc, byte| (acc << 8) | byte }
    right_int = right.bytes.reduce(0) { |acc, byte| (acc << 8) | byte }
    mean = (left_int + right_int) / 2
    20.times.map { |shift| (mean >> (8 * (19 - shift))) & 0xff }.pack('C20')
  end

  def test_unknown_hash_algorithm_record_cannot_match_or_cover
    target = @zone.nsec3_matching('ns1.example.')
    altered = RR.create(
      "#{target.name.to_s(true)} 3600 IN NSEC3 2 0 #{Nsec3ZoneBuilder::ITERATIONS} " \
      "#{target.salt} ( #{target.encode_next_hashed(target.next_hashed)} A RRSIG NSEC3 )"
    )
    refute(altered.supported_hash_algorithm?)
    refute(altered.matches_name?('ns1.example.'))
    refute(altered.covers_name?('ns1.example.'))
  end

  def test_records_from_another_zone_never_match
    foreign = RR.create(
      "#{@zone.hash_hex('ns1.example.')}.other.example. 3600 IN NSEC3 1 0 12 aabbccdd " \
      "#{@zone.base32(@zone.hash_binary('a.example.'))} A RRSIG")
    refute(foreign.in_zone?('ns1.example.'))
    refute(foreign.matches_name?('ns1.example.'))
    assert_equal('other.example.', foreign.zone_name.to_s(true))
  end

  def test_parameter_compatibility_requires_matching_alg_iterations_and_salt
    reference = @zone.nsec3s.first
    altered = RR.create(reference.to_s.tap { |text| text.sub!(/ aabbccdd /, ' beefbeef ') })
    refute(reference.compatible_with?(altered))
    assert(reference.compatible_with?(RR.create(reference.to_s)))
  end

  # ----------------------------------------------------------------------
  # Complete, valid proofs (RFC 5155 sections 8.4 - 8.8)
  # ----------------------------------------------------------------------

  def test_nxdomain_requires_closest_encloser_next_closer_and_wildcard_cover
    msg = @responses.fetch(:nxdomain)
    assert_equal(RCode.NXDOMAIN, msg.rcode)
    assert(@verifier.verify_nsecs(msg))
    assert(@verifier.verify(msg, @zone.dnskey))
  end

  def test_plain_nodata_requires_matching_nsec3_without_qtype_or_cname
    msg = @responses.fetch(:nodata)
    assert_equal(RCode.NOERROR, msg.rcode)
    assert(@verifier.verify_nsecs(msg))
    assert(@verifier.verify(msg, @zone.dnskey))
  end

  def test_wildcard_nodata_requires_encloser_proof_and_matching_wildcard
    msg = @responses.fetch(:wildcard_nodata)
    assert(@verifier.verify_nsecs(msg))
    assert(@verifier.verify(msg, @zone.dnskey))
  end

  def test_wildcard_answer_requires_next_closer_cover
    msg = @responses.fetch(:wildcard_answer)
    assert(@verifier.verify_nsecs(msg))
    assert(@verifier.verify(msg, @zone.dnskey))
  end

  def test_secure_ds_nodata_matches_qname_without_ds_bit
    msg = @responses.fetch(:ds_nodata_secure)
    assert(@verifier.verify_nsecs(msg))
    assert(@verifier.verify(msg, @zone.dnskey))
    refute(msg.nsec3_insecure_delegation)
  end

  def test_optout_ds_nodata_is_authenticated_but_insecure
    msg = @responses.fetch(:ds_nodata_optout)
    result = @verifier.verify_nsecs(msg)
    assert_kind_of(SingleVerifier::Nsec3InsecureDelegation, result)
    assert(@verifier.verify(msg, @zone.dnskey))
    assert(msg.nsec3_insecure_delegation)
    @verifier.send(:apply_nsec3_security_level, msg)
    assert_equal(Message::SecurityLevel.INSECURE, msg.security_level)
  end

  def test_secure_proofs_are_marked_secure
    %i[nxdomain nodata wildcard_nodata wildcard_answer ds_nodata_secure].each do |key|
      msg = @responses.fetch(key)
      @verifier.verify(msg, @zone.dnskey)
      @verifier.send(:apply_nsec3_security_level, msg)
      assert_equal(Message::SecurityLevel.SECURE, msg.security_level, key.to_s)
    end
  end

  # ----------------------------------------------------------------------
  # NXDOMAIN mutation: each missing record must break the proof
  # ----------------------------------------------------------------------

  def test_nxdomain_without_next_closer_cover_is_rejected
    owner = @zone.nsec3_covering('c.x.w.example.').name
    assert_rejected(:nxdomain, owner)
  end

  def test_nxdomain_without_wildcard_cover_is_rejected
    owner = @zone.nsec3_covering('*.x.w.example.').name
    assert_rejected(:nxdomain, owner)
  end

  def test_nxdomain_without_closest_encloser_match_is_rejected
    owner = @zone.nsec3_matching('x.w.example.').name
    assert_rejected(:nxdomain, owner)
  end

  def test_nxdomain_with_a_matching_wildcard_is_contradictory
    msg = clone(@responses.fetch(:nxdomain))
    # Replace the wildcard-covering span with an NSEC3 that *matches* the
    # wildcard, which would prove the wildcard exists and so forbid NXDOMAIN.
    wildcard = '*.x.w.example.'
    replacement = @zone.make_nsec3(
      @zone.nsec3_owner(wildcard), 0,
      @zone.nsec3_covering(wildcard).next_hashed, %w[MX RRSIG NSEC3]
    )
    swap_nsec3(msg, @zone.nsec3_covering(wildcard).name, replacement)
    assert_verify_nsecs_error(msg, /contradicted by matching wildcard/)
  end

  # ----------------------------------------------------------------------
  # NODATA mutation
  # ----------------------------------------------------------------------

  def test_nodata_without_matching_nsec3_is_rejected
    owner = @zone.nsec3_matching('ns1.example.').name
    assert_rejected(:nodata, owner)
  end

  def test_nodata_whose_nsec3_lists_qtype_is_rejected
    msg = clone(@responses.fetch(:nodata))
    original = @zone.nsec3_matching('ns1.example.')
    replacement = @zone.make_nsec3(
      original.name.to_s(true), 0, original.next_hashed,
      %w[A MX RRSIG NSEC3]
    )
    swap_nsec3(msg, original.name, replacement)
    assert_verify_nsecs_error(msg, /lists MX/)
  end

  def test_nodata_whose_nsec3_lists_cname_is_rejected
    msg = clone(@responses.fetch(:nodata))
    original = @zone.nsec3_matching('ns1.example.')
    replacement = @zone.make_nsec3(
      original.name.to_s(true), 0, original.next_hashed,
      %w[A CNAME RRSIG NSEC3]
    )
    swap_nsec3(msg, original.name, replacement)
    assert_verify_nsecs_error(msg, /lists CNAME/)
  end

  def test_nodata_cannot_use_a_closest_encloser_proof_without_match
    # A non-DS query answered only with an Opt-Out span must not be accepted.
    msg = clone(@responses.fetch(:ds_nodata_optout))
    msg.instance_variable_get(:@question).clear
    msg.add_question(Question.new('opt.corp.example.', Types.A))
    assert_verify_nsecs_error(msg, /requires an NSEC3 matching the QNAME/)
  end

  # ----------------------------------------------------------------------
  # Wildcard NODATA mutation
  # ----------------------------------------------------------------------

  def test_wildcard_nodata_without_wildcard_match_is_rejected
    owner = @zone.nsec3_matching('*.w.example.').name
    assert_rejected(:wildcard_nodata, owner)
  end

  def test_wildcard_nodata_without_next_closer_cover_is_rejected
    owner = @zone.nsec3_covering('z.w.example.').name
    assert_rejected(:wildcard_nodata, owner)
  end

  def test_wildcard_nodata_whose_wildcard_lists_qtype_is_rejected
    msg = clone(@responses.fetch(:wildcard_nodata))
    original = @zone.nsec3_matching('*.w.example.')
    replacement = @zone.make_nsec3(
      original.name.to_s(true), 0, original.next_hashed,
      %w[MX AAAA RRSIG NSEC3]
    )
    swap_nsec3(msg, original.name, replacement)
    assert_verify_nsecs_error(msg, /lists AAAA/)
  end

  # ----------------------------------------------------------------------
  # Parameter coherence (RFC 5155 8.2)
  # ----------------------------------------------------------------------

  def test_incompatible_salt_in_proof_is_rejected
    msg = clone(@responses.fetch(:nxdomain))
    target = @zone.nsec3_matching('x.w.example.')
    altered = RR.create(
      "#{target.name.to_s(true)} 3600 IN NSEC3 1 0 #{Nsec3ZoneBuilder::ITERATIONS} beefbeef " \
      "( #{target.encode_next_hashed(target.next_hashed)} MX RRSIG NSEC3 )"
    )
    swap_nsec3(msg, target.name, altered)
    assert_verify_nsecs_error(msg, /Incompatible NSEC3 parameters/)
  end

  def test_incompatible_iterations_in_proof_is_rejected
    # Use the NXDOMAIN response, which carries several NSEC3 RRs sharing one
    # parameter set; altering only one of them makes the proof incoherent.
    msg = clone(@responses.fetch(:nxdomain))
    target = @zone.nsec3_covering('c.x.w.example.')
    altered = RR.create(
      "#{target.name.to_s(true)} 3600 IN NSEC3 1 0 #{Nsec3ZoneBuilder::ITERATIONS + 1} aabbccdd " \
      "( #{target.encode_next_hashed(target.next_hashed)} SOA NS RRSIG NSEC3 )"
    )
    swap_nsec3(msg, target.name, altered)
    assert_verify_nsecs_error(msg, /Incompatible NSEC3 parameters/)
  end

  def test_unknown_hash_algorithm_record_is_ignored_and_proof_fails
    msg = clone(@responses.fetch(:nodata))
    target = @zone.nsec3_matching('ns1.example.')
    altered = RR.create(
      "#{target.name.to_s(true)} 3600 IN NSEC3 2 0 #{Nsec3ZoneBuilder::ITERATIONS} " \
      "#{target.salt} ( #{target.encode_next_hashed(target.next_hashed)} A RRSIG NSEC3 )"
    )
    swap_nsec3(msg, target.name, altered)
    # RFC 5155 8.1 : an unknown hash algorithm disqualifies the record, so the
    # proof cannot be built from it.
    assert_verify_nsecs_error(msg, /unsupported hash algorithm/)
  end

  # ----------------------------------------------------------------------
  # Closest encloser sanity (RFC 5155 8.3)
  # ----------------------------------------------------------------------

  def test_encloser_record_with_dname_bit_is_rejected
    msg = clone(@responses.fetch(:nxdomain))
    target = @zone.nsec3_matching('x.w.example.')
    altered = @zone.make_nsec3(
      target.name.to_s(true), 0, target.next_hashed,
      %w[MX DNAME RRSIG NSEC3]
    )
    swap_nsec3(msg, target.name, altered)
    assert_verify_nsecs_error(msg, /must not carry the DNAME type/)
  end

  def test_encloser_record_with_ns_but_no_soa_is_rejected
    msg = clone(@responses.fetch(:nxdomain))
    target = @zone.nsec3_matching('x.w.example.')
    altered = @zone.make_nsec3(
      target.name.to_s(true), 0, target.next_hashed,
      %w[MX NS RRSIG NSEC3]
    )
    swap_nsec3(msg, target.name, altered)
    assert_verify_nsecs_error(msg, /carries NS without SOA/)
  end

  # ----------------------------------------------------------------------
  # Opt-Out: unsigned delegations must never be upgraded to secure denial
  # ----------------------------------------------------------------------

  def test_clearing_optout_flag_rejects_insecure_delegation_proof
    msg = clone(@responses.fetch(:ds_nodata_optout))
    signed = @zone.opt_out
    plain = @zone.make_nsec3(
      signed.name.to_s(true), 0, signed.next_hashed,
      signed.types.map(&:string)
    )
    swap_nsec3(msg, signed.name, plain)
    assert_verify_nsecs_error(msg, /must have the Opt-Out flag set/)
    refute(msg.nsec3_insecure_delegation)
  end

  def test_optout_span_does_not_authenticate_names_outside_the_zone
    refute(@zone.opt_out.matches_name?('opt.corp.example.'))
    assert(@zone.opt_out.covers_name?('corp.example.'))
  end

  def test_deep_name_under_unsigned_delegation_stays_insecure
    # A name several labels below the unsigned delegation still resolves
    # through the same Opt-Out next closer cover and must not be upgraded.
    msg = clone(@responses.fetch(:ds_nodata_optout))
    msg.instance_variable_get(:@question).clear
    msg.add_question(Question.new('deep.opt.corp.example.', Types.DS, Classes.IN))
    result = @verifier.verify_nsecs(msg)
    assert_kind_of(SingleVerifier::Nsec3InsecureDelegation, result)
    assert_equal('example.', result.encloser.to_s(true))
    assert_equal('corp.example.', result.next_closer.to_s(true))
  end

  def test_wildcard_answer_with_full_label_count_is_not_treated_as_wildcard
    # An RRSIG whose label count equals the QNAME labels asserts a direct
    # owner name, so the wildcard-expansion precondition must fail.
    msg = clone(@responses.fetch(:wildcard_answer))
    rrsig = msg.answer.find { |rr| rr.type == Types.RRSIG }
    rrsig.labels = msg.question[0].qname.labels.length
    assert_verify_nsecs_error(msg, /does not prove wildcard expansion/)
  end

  def test_empty_non_terminal_nodata_matches_with_empty_bitmap
    ent = @zone.nsec3_matching('empty.ent.example.')
    msg = Message.new
    msg.header.rcode = RCode.NOERROR
    msg.add_question(Question.new('empty.ent.example.', Types.TXT, Classes.IN))
    set = RRSet.new([ent])
    @zone.sign_rrset(set)
    (set.rrs + set.sigs).each { |rr| msg.add_authority(rr) }
    assert(@verifier.verify_nsecs(msg))
    refute(ent.types.include?(Types.TXT))
  end

  # ----------------------------------------------------------------------
  # Mixed mechanisms and cryptographic integrity
  # ----------------------------------------------------------------------

  def test_mixing_nsec_and_nsec3_in_one_response_is_rejected
    msg = clone(@responses.fetch(:nodata))
    msg.add_authority(RR.create(
      "ns1.example. 3600 NSEC ns2.example. A RRSIG NSEC"))
    assert_verify_nsecs_error(msg, /mixes NSEC and NSEC3/)
  end

  def test_corrupted_nsec3_signature_makes_full_verification_fail
    msg = clone(@responses.fetch(:nodata))
    rrsig = msg.authority.find { |rr| rr.type == Types.RRSIG && rr.type_covered == Types.NSEC3 }
    refute_nil(rrsig)
    corrupted = rrsig.signature.dup
    corrupted.setbyte(0, corrupted.getbyte(0) ^ 0xff)
    rrsig.signature = corrupted
    assert_raises(VerifyError) { @verifier.verify(msg, @zone.dnskey) }
  end

  def test_removing_a_proof_record_makes_full_verification_fail
    msg = clone(@responses.fetch(:nxdomain))
    owner = @zone.nsec3_covering('c.x.w.example.').name
    delete_owner(msg, owner)
    assert_raises(VerifyError) { @verifier.verify(msg, @zone.dnskey) }
  end

  TARGET_NAME = Dnsruby::Name.create('target.example.')

  private

  # An NSEC3 whose target hash is fixed directly, so ring ordering can be
  # exercised against a real chain record without inverting SHA-1.
  class FixedTargetNsec3 < RR::NSEC3
    attr_writer :target_hash

    def initialize(template)
      super()
      @name = template.name
      @hash_alg = template.hash_alg
      @flags = template.flags
      @iterations = template.iterations
      @salt = template.salt_raw
      @hash_length = template.hash_length
      @next_hashed = template.next_hashed
      @types = template.types
      @target_hash = nil
    end

    def hash_for(_name)
      @target_hash
    end
  end

  def fixed_span(template)
    FixedTargetNsec3.new(template)
  end

  def clone(message)
    Message.decode(message.encode)
  end

  def delete_owner(message, owner)
    message.authority.delete_if do |rr|
      rr.name.canonical == owner.canonical &&
        (rr.type == Types.NSEC3 || (rr.type == Types.RRSIG && rr.type_covered == Types.NSEC3))
    end
    message.update_counts
  end

  def swap_nsec3(message, old_owner, new_record)
    message.authority.delete_if do |rr|
      rr.name.canonical == old_owner.canonical &&
        (rr.type == Types.NSEC3 || (rr.type == Types.RRSIG && rr.type_covered == Types.NSEC3))
    end
    message.add_authority(new_record)
    message.update_counts
  end

  def assert_rejected(key, owner)
    msg = clone(@responses.fetch(key))
    delete_owner(msg, owner)
    assert_verify_nsecs_error(msg, /proof|NSEC3|cover|match/i)
    assert_raises(VerifyError) { @verifier.verify(msg, @zone.dnskey) }
  end

  def assert_verify_nsecs_error(message, pattern)
    error = assert_raises(VerifyError) { @verifier.verify_nsecs(message) }
    assert_match(pattern, error.message)
  end
end
