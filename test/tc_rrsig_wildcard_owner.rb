require_relative 'spec_helper'
require 'openssl'
require 'base64'

# Generated, fully offline tests for RFC 4034 section 3.1.8 wildcard signing.
#
# The signed owner name is not taken from the RRSIG owner verbatim: the RRSIG
# Labels field together with the answer RRSet owner decides which name enters
# the signature input. With Labels smaller than the owner label count, the
# leading labels are replaced by a single "*", so one signature created for
# "*.example.org." validates any answer under the wildcard, but never a name
# outside the wildcard scope.
#
# The signed bytes are built independently here (no dnsruby signing helper
# exists) and cross-checked against the verifier's own canonical builder before
# the generated signatures are exercised.
class RrsigWildcardOwnerTest < Minitest::Test
  ZONE = 'example.org.'.freeze
  ALGORITHM = Dnsruby::Algorithms::RSASHA256
  ORIGINAL_TTL = 3600
  ANSWER_TTL = 300

  def setup
    @rsa = OpenSSL::PKey::RSA.generate(2048)
    exponent = @rsa.e.to_s(2)
    key_bytes = [exponent.bytesize].pack('C') + exponent + @rsa.n.to_s(2)
    @key = Dnsruby::RR.create(
      "#{ZONE} #{ORIGINAL_TTL} IN DNSKEY 256 3 8 #{Base64.strict_encode64(key_bytes)}")
    @verifier = Dnsruby::SingleVerifier.new(Dnsruby::SingleVerifier::VerifierType::ANCHOR)
  end

  def test_independent_signed_bytes_match_verifier_for_wildcard_and_exact_owners
    wildcard_rrs = [a_rr('host.Example.ORG.', '192.0.2.1'), a_rr('host.Example.ORG.', '192.0.2.2')]
    wildcard_sig = build_rrsig('host.Example.ORG.', labels: 2)
    wildcard_body = sign(wildcard_rrs, wildcard_sig)
    wildcard_set = Dnsruby::RRSet.new(wildcard_rrs.reverse)
    wildcard_set.add(wildcard_sig)
    assert_equal(wildcard_body,
      @verifier.send(:canonical_rrset_data, wildcard_set, wildcard_sig, {}))
    expected_owner = signed_owner_bytes('host.Example.ORG.', 2)
    assert_equal(expected_owner,
      @verifier.send(:canonical_rrset_data, wildcard_set, wildcard_sig, {})
        .byteslice(0, expected_owner.bytesize))

    exact_rr = a_rr('www.example.org.', '192.0.2.9')
    exact_sig = build_rrsig('www.example.org.', labels: 3)
    exact_body = sign([exact_rr], exact_sig)
    exact_set = Dnsruby::RRSet.new([exact_rr])
    exact_set.add(exact_sig)
    assert_equal(exact_body,
      @verifier.send(:canonical_rrset_data, exact_set, exact_sig, {}))
  end

  def test_wildcard_signature_verifies_under_case_ttl_and_rr_order_variations
    rrs = [a_rr('host.example.org.', '192.0.2.1'), a_rr('host.example.org.', '192.0.2.2')]
    sig = build_rrsig('host.example.org.', labels: 2)
    sign(rrs, sig)

    verify_variants(sig, [
      variant('lowercase answer name, RR insertion order as signed',
        rrs.map { |rr| rr.clone }, 'host.example.org.'),
      variant('RRs inserted in reverse canonical order',
        rrs.reverse.map { |rr| rr.clone }, 'host.example.org.'),
      variant('mixed case owner and answer TTL differing from Original TTL',
        [a_rr('HOST.Example.ORG.', 999, '192.0.2.1'),
         a_rr('HOST.Example.ORG.', 999, '192.0.2.2')],
        'HOST.Example.ORG.')
    ])
  end

  def test_one_wildcard_signature_covers_every_name_level_under_the_wildcard
    base_rr = a_rr('host.example.org.', '192.0.2.1')
    base_sig = build_rrsig('host.example.org.', labels: 2)
    sign([base_rr], base_sig)

    ['host.example.org.', 'deep.sub.host.example.org.', 'a.b.c.example.org.'].each do |answer|
      rr = a_rr(answer, '192.0.2.1')
      moved = move_signature(base_sig, answer)
      rrset = Dnsruby::RRSet.new([rr])
      rrset.add(moved)
      assert_equal("*.#{ZONE}",
        owner_reconstructed_by_verifier(rrset, moved).to_s(true),
        "RRSIG labels must reconstruct the wildcard owner for #{answer}")
      assert(@verifier.verify_rrset(rrset, @key),
        "wildcard signature must validate expanded answer #{answer}")
    end
  end

  def test_original_ttl_field_is_what_enters_the_signed_bytes
    rr = a_rr('host.example.org.', ANSWER_TTL, '192.0.2.1')
    sig = build_rrsig('host.example.org.', labels: 2, original_ttl: 7200)
    sign([rr], sig)

    rrset = Dnsruby::RRSet.new([rr])
    rrset.add(sig)
    assert(@verifier.verify_rrset(rrset, @key))

    tampered = build_rrsig('host.example.org.', labels: 2, original_ttl: 1800)
    tampered.signature = sig.signature.b
    bad_set = Dnsruby::RRSet.new([a_rr('host.example.org.', ANSWER_TTL, '192.0.2.1')])
    bad_set.add(tampered)
    assert_crypto_failure(bad_set, 'changing Original TTL changes the signed input')
  end

  def test_signature_order_and_duplicate_signatures_do_not_affect_verification
    rr = a_rr('host.example.org.', '192.0.2.1')
    good = build_rrsig('host.example.org.', labels: 2)
    sign([rr], good)
    bad = good.clone
    bad.signature = good.signature.b.reverse

    [[good, bad], [bad, good]].each do |order|
      rrset = Dnsruby::RRSet.new([a_rr('host.example.org.', '192.0.2.1')])
      order.each { |signature| rrset.add(signature.clone) }
      assert(@verifier.verify_rrset(rrset, @key))
    end
  end

  def test_signature_moved_outside_wildcard_scope_fails_cryptographically
    base_rr = a_rr('host.example.org.', '192.0.2.1')
    base_sig = build_rrsig('host.example.org.', labels: 2)
    sign([base_rr], base_sig)

    outside = [
      ['sibling zone sharing no labels with the wildcard', 'host.example.net.'],
      ['name one label shorter than the wildcard owner', 'example.org.']
    ]
    outside.each do |description, answer|
      rr = a_rr(answer, '192.0.2.1')
      moved = move_signature(base_sig, answer)
      rrset = Dnsruby::RRSet.new([rr])
      rrset.add(moved)
      assert_crypto_failure(rrset, description)
    end

    # A signature for a deeper wildcard (*.host.example.org., labels=3) fails
    # when moved to a branch whose last three labels differ.
    deeper_rr = a_rr('www.host.example.org.', '192.0.2.1')
    deeper_sig = build_rrsig('www.host.example.org.', labels: 3)
    sign([deeper_rr], deeper_sig)
    moved = move_signature(deeper_sig, 'leaf.other.example.org.')
    branch = Dnsruby::RRSet.new([a_rr('leaf.other.example.org.', '192.0.2.1')])
    branch.add(moved)
    assert_equal('*.other.example.org.',
      owner_reconstructed_by_verifier(branch, moved).to_s(true))
    assert_crypto_failure(branch, 'reconstructed suffix no longer matches the signature')
  end

  def test_same_label_count_in_another_branch_still_matches_the_wildcard_owner
    # labels=2 always keeps the last two labels and prepends "*", so any
    # three-label answer under example.org reconstructs the same signed owner.
    base_rr = a_rr('host.example.org.', '192.0.2.1')
    base_sig = build_rrsig('host.example.org.', labels: 2)
    sign([base_rr], base_sig)

    sideways = Dnsruby::RRSet.new([a_rr('other.example.org.', '192.0.2.1')])
    sideways.add(move_signature(base_sig, 'other.example.org.'))
    assert_equal('*.example.org.',
      owner_reconstructed_by_verifier(sideways, sideways.sigs.first).to_s(true))
    assert(@verifier.verify_rrset(sideways, @key))

    # Adding depth does not change the reconstruction: the answer still ends in
    # the same two labels, so this remains a valid expansion of that wildcard.
    deeper = Dnsruby::RRSet.new([a_rr('leaf.other.example.org.', '192.0.2.1')])
    deeper.add(move_signature(base_sig, 'leaf.other.example.org.'))
    assert_equal('*.example.org.',
      owner_reconstructed_by_verifier(deeper, deeper.sigs.first).to_s(true))
    assert(@verifier.verify_rrset(deeper, @key))
  end

  def test_exact_owner_signature_does_not_validate_other_names
    rr = a_rr('host.example.org.', '192.0.2.1')
    sig = build_rrsig('host.example.org.', labels: 3)
    sign([rr], sig)

    signed_set = Dnsruby::RRSet.new([rr])
    signed_set.add(sig)
    assert(@verifier.verify_rrset(signed_set, @key))

    moved = move_signature(sig, 'www.example.org.')
    other = Dnsruby::RRSet.new([a_rr('www.example.org.', '192.0.2.1')])
    other.add(moved)
    assert_equal('www.example.org.',
      owner_reconstructed_by_verifier(other, moved).to_s(true))
    assert_crypto_failure(other, 'labels equal to owner length pins the signed owner')
  end

  def test_failure_samples_keep_structural_and_cryptographic_evidence_distinct
    rr = a_rr('host.example.org.', '192.0.2.1')
    sig = build_rrsig('host.example.org.', labels: 2)
    sign([rr], sig)

    invalid_labels = sig.clone
    invalid_labels.labels = rr.name.labels.length + 7
    structural_error = assert_raises(Dnsruby::VerifyError) do
      bad = Dnsruby::RRSet.new([a_rr('host.example.org.', '192.0.2.1')])
      bad.add(invalid_labels)
      @verifier.verify_rrset(bad, @key)
    end
    assert_match(/Invalid RRSIG label count/, structural_error.message)

    rdata_tampered = Dnsruby::RRSet.new([a_rr('host.example.org.', '192.0.2.2')])
    rdata_tampered.add(sig.clone)
    crypto_error = assert_raises(Dnsruby::VerifyError) do
      @verifier.verify_rrset(rdata_tampered, @key)
    end
    assert_match(/cryptographically verify/, crypto_error.message)
    refute_equal(structural_error.message, crypto_error.message)
  end

  def test_minimal_failure_samples_still_distinguish_normalization_from_crypto_failure
    # Reduced to one RR and one RRSIG each, the two failure classes must remain
    # distinguishable instead of collapsing into a generic verification error.
    rr = a_rr('host.example.org.', '192.0.2.1')
    sig = build_rrsig('host.example.org.', labels: 2)
    sign([rr], sig)

    negative_labels = sig.clone
    negative_labels.labels = -1
    structural = assert_raises(Dnsruby::VerifyError) do
      minimal = Dnsruby::RRSet.new([a_rr('host.example.org.', '192.0.2.1')])
      minimal.add(negative_labels)
      @verifier.verify_rrset(minimal, @key)
    end

    flipped = sig.clone
    last = flipped.signature.bytesize - 1
    flipped.signature = flipped.signature.b.setbyte(last, flipped.signature.getbyte(last) ^ 0x01)
    crypto = assert_raises(Dnsruby::VerifyError) do
      minimal = Dnsruby::RRSet.new([a_rr('host.example.org.', '192.0.2.1')])
      minimal.add(flipped)
      @verifier.verify_rrset(minimal, @key)
    end

    assert_match(/Invalid RRSIG label count/, structural.message)
    assert_match(/cryptographically verify/, crypto.message)
    refute_equal(structural.message, crypto.message)
  end

  private

  def a_rr(name, ttl_or_ip, ip = nil)
    ttl = ip.nil? ? ANSWER_TTL : ttl_or_ip
    address = ip.nil? ? ttl_or_ip : ip
    Dnsruby::RR.create("#{name} #{ttl} IN A #{address}")
  end

  def build_rrsig(owner, labels:, original_ttl: ORIGINAL_TTL)
    now = Time.now.to_i
    Dnsruby::RR.create(
      name: owner, type: 'RRSIG', ttl: ORIGINAL_TTL,
      type_covered: 'A', algorithm: ALGORITHM, labels: labels,
      original_ttl: original_ttl, expiration: now + 3600, inception: now - 60,
      key_tag: @key.key_tag, signers_name: ZONE)
  end

  # RFC 4034 section 3.1.8.1 / section 6.2, built without dnsruby's verifier
  # internals so the test independently specifies the expected wire form.
  def signed_owner(answer_name, labels)
    name = Dnsruby::Name.create(answer_name)
    if labels < name.labels.length
      Dnsruby::Name.new(
        [Dnsruby::Name::Label.new('*')] + name.labels.last(labels), true)
    else
      name
    end
  end

  def signed_owner_bytes(answer_name, labels)
    Dnsruby::MessageEncoder.new { |encoder| encoder.put_name(signed_owner(answer_name, labels), true) }.to_s
  end

  def canonical_rdata(record)
    Dnsruby::MessageEncoder.new { |encoder| record.encode_rdata(encoder, true) }.to_s
  end

  def canonical_rr_wire(record, original_ttl, owner)
    rdata = canonical_rdata(record)
    Dnsruby::MessageEncoder.new do |encoder|
      encoder.put_name(owner, true)
      encoder.put_pack('nnN', record.type.code, record.klass.code, original_ttl)
      encoder.put_pack('n', rdata.bytesize)
      encoder.put_bytes(rdata)
    end.to_s
  end

  # Returns the canonical RRSet body so callers can cross-check byte equality.
  def sign(records, signature)
    owner = signed_owner(records.first.name.to_s, signature.labels)
    body = records.map { |record| canonical_rr_wire(record, signature.original_ttl, owner) }
                  .sort.join
    signature.signature = @rsa.sign(OpenSSL::Digest::SHA256.new, signature.sig_data + body)
    body
  end

  # Reusing signature bytes is only meaningful when the RRSIG RDATA is kept
  # identical, so clone and retarget the record rather than rebuilding it.
  def move_signature(signature, answer_name)
    moved = signature.clone
    moved.name = Dnsruby::Name.create(answer_name)
    moved
  end

  def owner_reconstructed_by_verifier(rrset, signature)
    bytes = @verifier.send(:canonical_rrset_data, rrset, signature, {})
    Dnsruby::MessageDecoder.new(bytes).get_name
  end

  def variant(description, records, owner)
    [description, records, owner]
  end

  def verify_variants(signature, variants)
    variants.each do |description, records, owner|
      moved = move_signature(signature, owner)
      rrset = Dnsruby::RRSet.new(records)
      rrset.add(moved)
      assert(@verifier.verify_rrset(rrset, @key), description)
    end
  end

  def assert_crypto_failure(rrset, description)
    error = assert_raises(Dnsruby::VerifyError, description) do
      @verifier.verify_rrset(rrset, @key)
    end
    assert_match(/cryptographically verify/, error.message, description)
  end
end
