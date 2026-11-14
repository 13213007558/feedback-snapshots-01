require_relative 'spec_helper'
require 'base64'
require 'fileutils'
require 'openssl'
require 'tmpdir'

class Rfc5011Test < Minitest::Test
  DAY = 24 * 60 * 60
  ADD_HOLD_DOWN = 30 * DAY
  REMOVE_HOLD_DOWN = 30 * DAY

  def setup
    Dnsruby::Dnssec.reset
    @clock_time = Time.now.to_i
    @clock = Dnsruby::Rfc5011::Clock.new(Time.at(@clock_time))
    @rsa = OpenSSL::PKey::RSA.generate(2048)
    @new_rsa = OpenSSL::PKey::RSA.generate(2048)
    @evil_rsa = OpenSSL::PKey::RSA.generate(2048)
    @key = dnskey('example.invalid.', @rsa)
    @new_key = dnskey('example.invalid.', @new_rsa)
    @evil_key = dnskey('example.invalid.', @evil_rsa)
    @verifier = Dnsruby::SingleVerifier.new(Dnsruby::SingleVerifier::VerifierType::ANCHOR)
    @verifier.add_trust_anchor(@key)
    @manager = new_manager
  end

  def teardown
    @manager.save if @manager
    FileUtils.rm_rf(@directory) if @directory
    Dnsruby::Dnssec.reset
  end

  def test_new_sep_key_waits_for_add_hold_down_before_becoming_an_anchor
    assert(@manager.observe(signed_rrset([@key, @new_key], @key, @rsa)))
    assert_equal('AddPend', @manager.state(@new_key))
    refute_includes(@manager.trust_anchors.map(&:key_tag), @new_key.key_tag)
    refute_includes(@verifier.managed_trust_anchors.map(&:key_tag), @new_key.key_tag)
    # The seed anchor remains manually configured on the verifier and is not
    # copied into the RFC 5011 manager's own trust-anchor list.
    assert_empty(@manager.trust_anchors)
    assert_includes(@verifier.trust_anchors.map(&:key_tag), @key.key_tag)

    @clock.advance(ADD_HOLD_DOWN - 1)
    assert(@manager.observe(signed_rrset([@key, @new_key], @key, @rsa, at: @clock.now.to_i)))
    assert_equal('AddPend', @manager.state(@new_key))

    @clock.advance(1)
    assert(@manager.observe(signed_rrset([@key, @new_key], @key, @rsa, at: @clock.now.to_i)))
    assert_equal('Valid', @manager.state(@new_key))
    assert_includes(@manager.trust_anchors.map(&:key_tag), @new_key.key_tag)
    assert_includes(@verifier.managed_trust_anchors.map(&:key_tag), @new_key.key_tag)
  end

  def test_pending_key_disappearing_resets_add_hold_down
    assert(@manager.observe(signed_rrset([@key, @new_key], @key, @rsa)))
    assert_equal('AddPend', @manager.state(@new_key))

    @clock.advance(10 * DAY)
    assert(@manager.observe(signed_rrset([@key], @key, @rsa, at: @clock.now.to_i)))
    assert_nil(@manager.state(@new_key))
    assert_empty(@manager.pending_keys)

    assert(@manager.observe(signed_rrset([@key, @new_key], @key, @rsa, at: @clock.now.to_i)))
    assert_equal('AddPend', @manager.state(@new_key))
    @clock.advance(20 * DAY)
    assert(@manager.observe(signed_rrset([@key, @new_key], @key, @rsa, at: @clock.now.to_i)))
    assert_equal('AddPend', @manager.state(@new_key), 'the restarted timer must not be inherited from the first observation')
  end

  def test_valid_anchor_goes_missing_but_remains_trusted_until_revoked
    @manager.add_trust_anchor(@new_key, at: @clock.now.to_i)
    assert(@manager.observe(signed_rrset([@key], @key, @rsa)))
    assert_equal('Missing', @manager.state(@new_key))
    assert_includes(@manager.trust_anchors.map(&:key_tag), @new_key.key_tag)
    assert_includes(@verifier.managed_trust_anchors.map(&:key_tag), @new_key.key_tag)
    assert(@verifier.verify_rrset(signed_rrset([@key], @key, @rsa)))

    assert(@manager.observe(signed_rrset([@key, @new_key], @key, @rsa)))
    assert_equal('Valid', @manager.state(@new_key))
  end

  def test_revocation_is_immediate_and_requires_the_revoked_keys_own_signature
    @manager.add_trust_anchor(@new_key, at: @clock.now.to_i)
    @clock.advance(DAY)
    revoked = revoke(@new_key)
    assert(@manager.observe(signed_rrset([@key, revoked], [@key, revoked], [@rsa, @new_rsa])))
    assert_equal('Revoked', @manager.state(@new_key))
    refute_includes(@manager.trust_anchors.map(&:key_tag), @new_key.key_tag)
    refute_includes(@verifier.managed_trust_anchors.map(&:key_tag), @new_key.key_tag)
  end

  def test_revocation_without_a_self_signature_is_rejected
    @manager.add_trust_anchor(@key, at: @clock.now.to_i)
    @manager.add_trust_anchor(@new_key, at: @clock.now.to_i)
    revoked = revoke(@new_key)

    # The RRSet is validly signed by the existing anchor, but the revoked key
    # did not sign its own revocation. It must not enter Revoked; because it is
    # absent from this authenticated RRSet RFC 5011 moves it to Missing.
    assert(@manager.observe(signed_rrset([@key, revoked], @key, @rsa)))
    assert_equal('Missing', @manager.state(@new_key))
    assert_includes(@manager.trust_anchors.map(&:key_tag), @new_key.key_tag)
    refute_equal('Revoked', @manager.state(@new_key))
  end

  def test_revoked_record_is_removed_after_remove_hold_down_and_absence
    @manager.add_trust_anchor(@key, at: @clock.now.to_i)
    @manager.add_trust_anchor(@new_key, at: @clock.now.to_i)
    revoked = revoke(@new_key)
    assert(@manager.observe(signed_rrset([@key, revoked], [@key, revoked], [@rsa, @new_rsa])))
    assert_equal('Revoked', @manager.state(@new_key))

    assert(@manager.observe(signed_rrset([@key], @key, @rsa, at: @clock.now.to_i)))
    assert_equal('Revoked', @manager.state(@new_key))
    @clock.advance(REMOVE_HOLD_DOWN - 1)
    assert(@manager.observe(signed_rrset([@key], @key, @rsa, at: @clock.now.to_i)))
    refute_nil(@manager.state(@new_key))
    @clock.advance(1)
    assert(@manager.observe(signed_rrset([@key], @key, @rsa, at: @clock.now.to_i)))
    assert_equal('Removed', @manager.state(@new_key))
    refute_includes(@manager.trust_anchors.map(&:key_tag), @new_key.key_tag)
  end

  def test_unauthenticated_observation_cannot_change_persisted_state
    signed = signed_rrset([@key, @new_key], @key, @rsa)
    assert(@manager.observe(signed))
    before = File.read(@manager.store_path)
    before_records = @manager.records
    evil_rrset = signed_rrset([@evil_key], @evil_key, @evil_rsa)
    refute(@manager.observe(evil_rrset))
    assert_nil(@manager.state(@evil_key))
    assert_equal(before, File.read(@manager.store_path))
    assert_equal(before_records, @manager.records)

    # A correctly signed RRSet that omits an existing anchor is ignored too if
    # its signatures do not chain to an existing trusted key.
    refute(@manager.observe(signed_rrset([@evil_key, @key], @evil_key, @evil_rsa)))
    assert_equal(before, File.read(@manager.store_path))
  end

  def test_state_and_hold_down_survive_process_restart
    assert(@manager.observe(signed_rrset([@key, @new_key], @key, @rsa)))
    @clock.advance(29 * DAY)
    assert(@manager.observe(signed_rrset([@key, @new_key], @key, @rsa, at: @clock.now.to_i)))
    assert_equal('AddPend', @manager.state(@new_key))

    restarted_clock = Dnsruby::Rfc5011::Clock.new(Time.at(@clock_time + 30 * DAY))
    restarted_verifier = Dnsruby::SingleVerifier.new(Dnsruby::SingleVerifier::VerifierType::ANCHOR)
    restarted_verifier.add_trust_anchor(@key)
    restarted = Dnsruby::Rfc5011.new(store_path: @manager.store_path,
      verifier: restarted_verifier, clock: restarted_clock,
      add_hold_down: ADD_HOLD_DOWN, remove_hold_down: REMOVE_HOLD_DOWN)
    assert_equal('AddPend', restarted.state(@new_key))
    refute_includes(restarted.trust_anchors.map(&:key_tag), @new_key.key_tag)

    # Crossing the deadline while down is not itself enough: a fresh
    # authenticated observation is required.
    assert(restarted.observe(signed_rrset([@key, @new_key], @key, @rsa, at: restarted_clock.now.to_i)))
    assert_equal('Valid', restarted.state(@new_key))
    assert_includes(restarted.trust_anchors.map(&:key_tag), @new_key.key_tag)
  end

  def test_manual_anchor_remains_separate_from_managed_anchor
    manual_key = dnskey('manual.invalid.', OpenSSL::PKey::RSA.generate(2048))
    @verifier.add_trust_anchor(manual_key)
    @manager.add_trust_anchor(@new_key, at: @clock.now.to_i)
    assert_includes(@verifier.trust_anchors.map(&:key_tag), manual_key.key_tag)
    assert_equal([@new_key.key_tag], @verifier.managed_trust_anchors.map(&:key_tag))
    assert_includes(@manager.configured_anchors.map(&:key_tag), manual_key.key_tag)
    refute_includes(@manager.configured_anchors.map(&:key_tag), @new_key.key_tag)

    @manager.remove_managed_anchor(@new_key)
    assert_empty(@verifier.managed_trust_anchors)
    assert_includes(@verifier.trust_anchors.map(&:key_tag), manual_key.key_tag)
  end

  def test_revoked_state_is_permanent_and_removal_clock_is_not_reset_by_an_unrevoked_copy
    @manager.add_trust_anchor(@key, at: @clock.now.to_i)
    @manager.add_trust_anchor(@new_key, at: @clock.now.to_i)
    revoked = revoke(@new_key)
    assert(@manager.observe(signed_rrset([@key, revoked], [@key, revoked], [@rsa, @new_rsa])))
    assert_equal('Revoked', @manager.state(@new_key))

    @clock.advance(DAY)
    # A stale unrevoked copy must not make the revoked key usable again.
    assert(@manager.observe(signed_rrset([@key, @new_key], @key, @rsa, at: @clock.now.to_i)))
    assert_equal('Revoked', @manager.state(@new_key))
    refute_includes(@manager.trust_anchors.map(&:key_tag), @new_key.key_tag)

    @clock.advance(REMOVE_HOLD_DOWN)
    assert(@manager.observe(signed_rrset([@key], @key, @rsa, at: @clock.now.to_i)))
    # The first authenticated observation without the revoked key starts the
    # remove hold-down clock.
    assert_equal('Revoked', @manager.state(@new_key))
    @clock.advance(REMOVE_HOLD_DOWN)
    assert(@manager.observe(signed_rrset([@key], @key, @rsa, at: @clock.now.to_i)))
    assert_equal('Removed', @manager.state(@new_key))
  end

  def test_a_dnskey_rrset_matching_a_configured_ds_can_authenticate_observations
    ds_verifier = Dnsruby::SingleVerifier.new(Dnsruby::SingleVerifier::VerifierType::ANCHOR)
    ds_verifier.add_trust_anchor(Dnsruby::RR::DS.from_key(@key, 2))
    manager = Dnsruby::Rfc5011.new(verifier: ds_verifier, clock: @clock,
      add_hold_down: ADD_HOLD_DOWN, remove_hold_down: REMOVE_HOLD_DOWN)
    old_verifier = @verifier
    @verifier = ds_verifier
    begin
      assert(manager.observe(signed_rrset([@key, @new_key], @key, @rsa)))
      assert_equal('AddPend', manager.state(@new_key))
      refute_includes(manager.trust_anchors.map(&:key_tag), @new_key.key_tag)
    ensure
      @verifier = old_verifier
    end
  end

  def test_corrupt_persisted_record_is_rejected
    @manager.add_trust_anchor(@key, at: @clock.now.to_i)
    data = JSON.parse(File.read(@manager.store_path))
    data['trust_points'][0]['keys'][0]['flags'] = 256 # no longer matches identity
    File.write(@manager.store_path, JSON.pretty_generate(data))
    assert_raises(Dnsruby::Rfc5011::StateError) do
      Dnsruby::Rfc5011.new(store_path: @manager.store_path, verifier: @verifier, clock: @clock)
    end
  end

  def test_dnssec_exposes_managed_anchors_separately_from_manual_anchors
    manual_key = dnskey('manual.invalid.', OpenSSL::PKey::RSA.generate(2048))
    managed_key = dnskey('managed.invalid.', OpenSSL::PKey::RSA.generate(2048))
    Dnsruby::Dnssec.add_trust_anchor(manual_key)
    Dnsruby::Dnssec.add_managed_trust_anchor(managed_key)
    assert_equal([manual_key.key_tag], Dnsruby::Dnssec.trust_anchors.map(&:key_tag))
    assert_equal([managed_key.key_tag], Dnsruby::Dnssec.managed_trust_anchors.map(&:key_tag))
    refute(Dnsruby::Dnssec.no_keys?)
    Dnsruby::Dnssec.clear_managed_trust_anchors
    assert_empty(Dnsruby::Dnssec.managed_trust_anchors)
    assert_equal([manual_key.key_tag], Dnsruby::Dnssec.trust_anchors.map(&:key_tag))
  end

  def test_dnssec_reset_detaches_root_manager_and_restores_only_builtin_trust
    key = dnskey('.', OpenSSL::PKey::RSA.generate(2048))
    Dnsruby::Dnssec.reset
    manager = Dnsruby::Dnssec.root_anchor_manager
    manager.add_trust_anchor(key)
    assert_equal([key.key_tag], Dnsruby::Dnssec.root_verifier.managed_trust_anchors.map(&:key_tag))

    Dnsruby::Dnssec.reset
    refute_same(manager, Dnsruby::Dnssec.root_anchor_manager)
    assert_empty(Dnsruby::Dnssec.managed_trust_anchors)
    assert_equal([20326, 38696], Dnsruby::Dnssec.root_verifier.trust_anchors.map(&:key_tag))
  end

  private

  def new_manager
    @directory = Dir.mktmpdir('dnsruby-rfc5011')
    Dnsruby::Rfc5011.new(store_path: File.join(@directory, 'state.json'),
      verifier: @verifier, clock: @clock,
      add_hold_down: ADD_HOLD_DOWN, remove_hold_down: REMOVE_HOLD_DOWN)
  end

  def dnskey(name, rsa)
    exponent = rsa.e.to_s(2)
    key_data = Base64.strict_encode64([exponent.bytesize].pack('C') + exponent + rsa.n.to_s(2))
    Dnsruby::RR.create("#{name} 300 IN DNSKEY 257 3 8 #{key_data}")
  end

  def revoke(key)
    revoked = key.clone
    revoked.revoked = true
    revoked
  end

  def signed_rrset(keys, signers, rsas, at: nil)
    time = at || @clock.now.to_i
    signatures = Array(signers).zip(Array(rsas)).map do |signer, rsa|
      signature = Dnsruby::RR.create(name: keys.first.name, type: 'RRSIG', ttl: 300,
        type_covered: 'DNSKEY', algorithm: 8, labels: keys.first.name.labels.length,
        original_ttl: 300, expiration: time + 90 * DAY, inception: time - 600,
        key_tag: signer.key_tag, signers_name: signer.name)
      data = @verifier.send(:canonical_rrset_data, Dnsruby::RRSet.new(keys), signature, {})
      signature.signature = rsa.sign(OpenSSL::Digest::SHA256.new, signature.sig_data + data)
      signature
    end
    Dnsruby::RRSet.new(keys + signatures)
  end
end
