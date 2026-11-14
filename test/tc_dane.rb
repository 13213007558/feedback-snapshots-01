require_relative 'spec_helper'

require 'openssl'
require 'securerandom'
require 'digest'

class DANETest < Minitest::Test
  include Dnsruby

  WWW = 'www.example.com'
  MAIL = 'mail.example.org'
  PORT = 443

  def setup
    @ca_key = OpenSSL::PKey::RSA.new(2048)
    @ca = make_ca(@ca_key, 'Example CA')
    @leaf_key = OpenSSL::PKey::RSA.new(2048)
    @leaf = make_leaf(@leaf_key, @ca, @ca_key, WWW)
    @chain = [@leaf, @ca]
    @store = OpenSSL::X509::Store.new
    @store.add_cert(@ca)
  end

  def test_tlsa_name_construction
    assert_equal('_443._tcp.www.example.com',
                 DANE.tlsa_name(WWW, 443).to_s)
    assert_equal('_25._tcp.mail.example.org',
                 DANE.tlsa_name(MAIL, 25).to_s)
    assert_equal('_853._udp.dns.example.net',
                 DANE.tlsa_name('dns.example.net', 853, 'udp').to_s)
  end

  def test_tlsa_name_rejects_bad_arguments
    assert_raises(DANE::ArgumentError) { DANE.tlsa_name('', 443) }
    assert_raises(DANE::ArgumentError) { DANE.tlsa_name(WWW, 0) }
    assert_raises(DANE::ArgumentError) { DANE.tlsa_name(WWW, 70_000) }
    assert_raises(DANE::ArgumentError) { DANE.tlsa_name(WWW, 'https') }
    assert_raises(DANE::ArgumentError) { DANE.tlsa_name(WWW, 443, 'icmp') }
  end

  def test_dane_ee_spki_sha256_authenticates_leaf
    result = verify(records: [tlsa(3, 1, 1, @leaf)])
    assert result.authenticated?
    assert_equal(3, result.matched.usage)
    assert_equal([result.matched], result.associations)
    assert_empty result.unusable_associations
  end

  def test_dane_ee_cert_full_exact_match
    result = verify(records: [tlsa(3, 0, 0, @leaf)])
    assert result.authenticated?
    assert_equal(0, result.matched.selector)
    assert_equal(0, result.matched.matching_type)
  end

  def test_dane_ee_cert_sha512
    result = verify(records: [tlsa(3, 0, 2, @leaf)])
    assert result.authenticated?
  end

  def test_dane_ee_spki_full_match
    result = verify(records: [tlsa(3, 1, 0, @leaf)])
    assert result.authenticated?
  end

  def test_dane_ee_ignores_name_expiry_and_chain
    # A leaf issued for a different name, by an unrelated CA, with no chain
    # validation possible: DANE-EE still authenticates on the binding alone.
    foreign_ca_key = OpenSSL::PKey::RSA.new(2048)
    foreign_ca = make_ca(foreign_ca_key, 'Foreign CA')
    foreign_leaf = make_leaf(@leaf_key, foreign_ca, foreign_ca_key, MAIL)
    result = verify(service: WWW, chain: [foreign_leaf],
                    records: [tlsa(3, 1, 1, foreign_leaf)])
    assert result.authenticated?
  end

  def test_dane_ee_tolerates_expired_certificate
    expired = make_leaf(@leaf_key, @ca, @ca_key, WWW,
                        not_before: Time.now - 7200, not_after: Time.now - 3600)
    result = verify(chain: [expired], records: [tlsa(3, 1, 1, expired)])
    assert result.authenticated?
  end

  def test_dane_ee_requires_leaf_match
    other = make_leaf(OpenSSL::PKey::RSA.new(2048), @ca, @ca_key, WWW)
    error = assert_raises(DANE::VerificationError) do
      verify(records: [tlsa(3, 1, 1, other)])
    end
    refute error.result.authenticated?
    assert_nil error.result.matched
  end

  def test_dane_ta_anchor_cert_digest
    result = verify(records: [tlsa(2, 0, 1, @ca)])
    assert result.authenticated?
    assert_equal(2, result.matched.usage)
  end

  def test_dane_ta_anchor_spki
    result = verify(records: [tlsa(2, 1, 1, @ca)])
    assert result.authenticated?
  end

  def test_dane_ta_full_cert
    result = verify(records: [tlsa(2, 0, 0, @ca)])
    assert result.authenticated?
  end

  def test_dane_ta_self_anchored_single_certificate_chain
    # A self-signed leaf presented on its own can act as its own anchor.
    self_signed_key = OpenSSL::PKey::RSA.new(2048)
    self_signed = make_leaf(self_signed_key, @ca, self_signed_key, WWW)
    result = verify(chain: [self_signed], records: [tlsa(2, 1, 1, self_signed)])
    assert result.authenticated?
  end

  def test_dane_ta_rejects_expired_leaf
    expired = make_leaf(@leaf_key, @ca, @ca_key, WWW,
                        not_before: Time.now - 7200, not_after: Time.now - 3600)
    error = assert_raises(DANE::VerificationError) do
      verify(chain: [expired, @ca], records: [tlsa(2, 0, 1, @ca)])
    end
    refute error.result.authenticated?
  end

  def test_dane_ta_rejects_broken_chain
    other_ca = make_ca(OpenSSL::PKey::RSA.new(2048), 'Other CA')
    # Association pins the other CA but the presented chain is signed by @ca.
    error = assert_raises(DANE::VerificationError) do
      verify(records: [tlsa(2, 0, 1, other_ca)])
    end
    refute error.result.authenticated?
  end

  def test_dane_ta_enforces_service_name
    misnamed = make_leaf(@leaf_key, @ca, @ca_key, MAIL)
    error = assert_raises(DANE::VerificationError) do
      verify(chain: [misnamed, @ca], records: [tlsa(2, 0, 1, @ca)])
    end
    assert_match(/service name/, error.result.failure_reason)
  end

  def test_dane_ta_name_check_can_be_disabled
    misnamed = make_leaf(@leaf_key, @ca, @ca_key, MAIL)
    result = verify(chain: [misnamed, @ca],
                    records: [tlsa(2, 0, 1, @ca)],
                    trust: DANE::TrustConfig.new(check_name: false))
    assert result.authenticated?
  end

  def test_pkix_ee_requires_path_validation_and_leaf_match
    result = verify(records: [tlsa(1, 1, 1, @leaf)],
                    trust: DANE::TrustConfig.new(trust_store: @store))
    assert result.authenticated?
  end

  def test_pkix_ee_fails_without_trust_anchor
    error = assert_raises(DANE::VerificationError) do
      verify(records: [tlsa(1, 1, 1, @leaf)],
             trust: DANE::TrustConfig.new)
    end
    refute error.result.authenticated?
    assert_match(/PKIX path validation failed/, error.result.failure_reason)
  end

  def test_pkix_ee_enforces_name
    misnamed = make_leaf(@leaf_key, @ca, @ca_key, MAIL)
    error = assert_raises(DANE::VerificationError) do
      verify(chain: [misnamed, @ca], records: [tlsa(1, 1, 1, misnamed)],
             trust: DANE::TrustConfig.new(trust_store: @store))
    end
    assert_match(/service name/, error.result.failure_reason)
  end

  def test_pkix_ta_matches_issuer_in_valid_path
    result = verify(records: [tlsa(0, 0, 1, @ca)],
                    trust: DANE::TrustConfig.new(trust_store: @store))
    assert result.authenticated?
  end

  def test_pkix_ta_fails_when_anchor_untrusted
    error = assert_raises(DANE::VerificationError) do
      verify(records: [tlsa(0, 0, 1, @ca)],
             trust: DANE::TrustConfig.new)
    end
    refute error.result.authenticated?
  end

  def test_pkix_ta_leaf_association_does_not_match_anchor_record
    # Usage 0 pins a CA on the path, so a leaf SPKI association cannot match.
    error = assert_raises(DANE::VerificationError) do
      verify(records: [tlsa(0, 1, 1, @leaf)],
             trust: DANE::TrustConfig.new(trust_store: @store))
    end
    refute error.result.authenticated?
  end

  def test_first_matching_record_is_returned
    wrong = tlsa(3, 1, 1, make_leaf(OpenSSL::PKey::RSA.new(2048), @ca, @ca_key, WWW))
    right = tlsa(3, 1, 1, @leaf)
    result = verify(records: [wrong, right])
    assert result.authenticated?
    assert_equal right.databin, result.matched.databin
  end

  def test_unusable_and_usable_records_are_both_reported
    result = verify(records: [tlsa(255, 1, 1, @leaf), tlsa(3, 1, 1, @leaf)])
    assert result.authenticated?
    assert_equal 1, result.unusable_associations.length
    assert_equal 1, result.associations.length
    assert_equal result.matched, result.associations.first
  end

  def test_unknown_usage_is_unusable_not_trusted
    error = assert_raises(DANE::VerificationError) do
      verify(records: [tlsa(255, 1, 1, @leaf)])
    end
    assert_equal 1, error.result.unusable_associations.length
    assert_match(/unsupported certificate usage 255/, error.result.unusable_associations.first.last)
  end

  def test_unknown_selector_is_unusable
    error = assert_raises(DANE::VerificationError) do
      verify(records: [tlsa(3, 2, 1, @leaf)])
    end
    assert_match(/unsupported selector 2/, error.result.unusable_associations.first.last)
  end

  def test_unknown_matching_type_is_unusable
    error = assert_raises(DANE::VerificationError) do
      verify(records: [tlsa(3, 1, 3, @leaf)])
    end
    assert_match(/unsupported matching type 3/, error.result.unusable_associations.first.last)
  end

  def test_malformed_digest_length_is_unusable
    # A 16-byte value cannot be a SHA-256 (32-byte) association digest.
    record = { usage: 3, selector: 1, matching_type: 1,
               data: OpenSSL::Digest::SHA256.hexdigest('x')[0, 32] }
    error = assert_raises(DANE::VerificationError) do
      verify(records: [record])
    end
    assert_match(/malformed digest length/, error.result.unusable_associations.first.last)
  end

  def test_unverified_records_are_refused
    assert_raises(DANE::ArgumentError) do
      verify(records: [tlsa(3, 1, 1, @leaf)], verified: false)
    end
  end

  def test_per_record_verified_flags
    records = [tlsa(3, 1, 1, @leaf)]
    assert_raises(DANE::ArgumentError) do
      verify(records: records, verified: [false])
    end
    result = verify(records: records, verified: [true])
    assert result.authenticated?
  end

  def test_security_level_secure_accepted_others_refused
    result = verify(records: [tlsa(3, 1, 1, @leaf)],
                    verified: Message::SecurityLevel::SECURE)
    assert result.authenticated?

    [Message::SecurityLevel::INSECURE, Message::SecurityLevel::BOGUS,
     Message::SecurityLevel::INDETERMINATE].each do |level|
      assert_raises(DANE::ArgumentError) do
        verify(records: [tlsa(3, 1, 1, @leaf)], verified: level)
      end
    end
  end

  def test_owner_name_mismatch_is_unusable
    record = tlsa(3, 1, 1, @leaf)
    record.name = Dnsruby::Name.create("_443._tcp.other.example.net")
    error = assert_raises(DANE::VerificationError) do
      verify(records: [record])
    end
    assert_match(/TLSA query name/, error.result.unusable_associations.first.last)
  end

  def test_owner_name_match_succeeds
    record = tlsa(3, 1, 1, @leaf)
    record.name = Dnsruby::Name.create("_443._tcp.#{WWW}")
    result = verify(records: [record])
    assert result.authenticated?
  end

  def test_hash_records_are_supported
    hash_record = {
      usage: 3,
      selector: 1,
      matching_type: 1,
      data: OpenSSL::Digest::SHA256.hexdigest(@leaf.public_key.to_der)
    }
    result = verify(records: [hash_record])
    assert result.authenticated?
  end

  def test_hash_records_accept_raw_databin
    hash_record = {
      usage: 3,
      selector: 0,
      matching_type: 1,
      databin: OpenSSL::Digest::SHA256.digest(@leaf.to_der)
    }
    result = verify(records: [hash_record])
    assert result.authenticated?
  end

  def test_empty_association_data_is_unusable
    record = { usage: 3, selector: 1, matching_type: 0, data: '' }
    error = assert_raises(DANE::VerificationError) do
      verify(records: [record])
    end
    assert_match(/empty certificate association data/, error.result.unusable_associations.first.last)
  end

  def test_pem_chain_entries_are_supported
    result = verify(chain: [@leaf.to_pem, @ca.to_pem],
                    records: [tlsa(3, 0, 1, @leaf)])
    assert result.authenticated?
  end

  def test_empty_chain_and_records_rejected
    assert_raises(DANE::ArgumentError) do
      DANE.verify(service: WWW, port: PORT, tlsa_records: [tlsa(3, 1, 1, @leaf)],
                  chain: [], verified: true)
    end
    assert_raises(DANE::ArgumentError) do
      DANE.verify(service: WWW, port: PORT, tlsa_records: [], chain: @chain,
                  verified: true)
    end
  end

  def test_bad_trust_config_rejected
    assert_raises(DANE::ArgumentError) do
      DANE.verify(service: WWW, port: PORT, tlsa_records: [tlsa(3, 1, 1, @leaf)],
                  chain: @chain, trust_config: Object.new, verified: true)
    end
  end

  private

  def verify(service: WWW, port: PORT, records:, chain: @chain, trust: nil, verified: true)
    DANE.verify(service: service, port: port, tlsa_records: records,
                chain: chain, trust_config: trust, verified: verified)
  end

  def tlsa(usage, selector, matching_type, certificate)
    content = selector == DANE::SELECTOR_CERT ? certificate.to_der : certificate.public_key.to_der
    data = case matching_type
           when DANE::MATCHING_FULL then content
           when DANE::MATCHING_SHA2_256 then OpenSSL::Digest::SHA256.digest(content)
           when DANE::MATCHING_SHA2_512 then OpenSSL::Digest::SHA512.digest(content)
           else OpenSSL::Digest::SHA256.digest(content)
           end
    Dnsruby::RR::IN::TLSA.new([usage, selector, matching_type, data])
  end

  def make_ca(key, common_name)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = random_serial
    cert.subject = cert.issuer = OpenSSL::X509::Name.new([['CN', common_name]])
    cert.public_key = key.public_key
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + 3600
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = cert
    cert.add_extension(factory.create_extension('basicConstraints', 'CA:TRUE', true))
    cert.add_extension(factory.create_extension('keyUsage', 'keyCertSign,cRLSign', true))
    cert.sign(key, OpenSSL::Digest::SHA256.new)
    cert
  end

  def make_leaf(key, issuer_cert, issuer_key, common_name, not_before: Time.now - 60,
                not_after: Time.now + 3600)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = random_serial
    cert.subject = OpenSSL::X509::Name.new([['CN', common_name]])
    cert.issuer = issuer_cert.subject
    cert.public_key = key.public_key
    cert.not_before = not_before
    cert.not_after = not_after
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = cert
    factory.issuer_certificate = issuer_cert
    cert.add_extension(factory.create_extension('subjectAltName', "DNS:#{common_name}", false))
    cert.add_extension(factory.create_extension('basicConstraints', 'CA:FALSE', true))
    cert.sign(issuer_key, OpenSSL::Digest::SHA256.new)
    cert
  end

  def random_serial
    OpenSSL::BN.new(SecureRandom.random_bytes(8).unpack1('H*').hex)
  end
end
