require "common"
require "net/ssh"
require "net/ssh/verifiers/always"
require "net/ssh/verifiers/accept_new"
require "net/ssh/verifiers/accept_new_or_local_tunnel"
require "net/ssh/verifiers/trust_evidence"
require "net/ssh/authentication/certificate"
require "tempfile"
require_relative "test_cert_authority_checks"

# Tests for the optional :verify_host_key_evidence trust-decision evidence.
# The evidence must explain *which* known_hosts rule drove a refusal (file,
# line, host pattern, entry/key type), keep @revoked decisive over a same-key
# pin, redact hashed host entries, and report each certificate check as
# not_run/pass/fail — all without changing the accept/reject outcome.
class TestTrustEvidence < NetSSHTest
  HOST = "victim.test"
  Session = Struct.new(:host_keys, :port, :peer, :options)

  def test_evidence_is_not_collected_by_default
    with_known_hosts("#{HOST} #{line(pinned_key)}") do |path|
      error = assert_raises(Net::SSH::HostKeyMismatch) { verify(path, other_key) }
      assert_nil error.trust_evidence
    end
  end

  def test_evidence_records_file_line_pattern_and_key_type
    with_known_hosts("#{HOST} #{line(pinned_key)}") do |path|
      error = assert_raises(Net::SSH::HostKeyMismatch) { verify(path, other_key, evidence: true) }
      evidence = error.trust_evidence
      assert_equal :rejected, evidence.decision
      assert_equal :mismatch, evidence.reason
      assert_equal HOST, evidence.host
      assert_equal other_key.ssh_type, evidence.presented_key_type
      assert_equal 1, evidence.entries.size

      location = evidence.entries.first[:location]
      assert_equal File.expand_path(path), location[:source]
      assert_equal 1, location[:line]
      assert_equal HOST, location[:host_pattern]
      assert_equal false, location[:hashed]
      assert_equal :key, evidence.entries.first[:entry_kind]
      assert_equal pinned_key.ssh_type, evidence.entries.first[:key_type]
      assert_equal false, evidence.entries.first[:key_match]
    end
  end

  def test_cert_authority_entry_is_typed_separately_from_plain_keys
    with_known_hosts("@cert-authority #{HOST} #{line(ca_public)}") do |path|
      error = assert_raises(Net::SSH::HostKeyMismatch) { verify(path, other_key, evidence: true) }
      assert_equal :cert_authority, error.trust_evidence.entries.first[:entry_kind]
      assert_equal ca_public.ssh_type, error.trust_evidence.entries.first[:key_type]
    end
  end

  # Scenario 1 from the task: the same key is pinned as trusted in one file and
  # marked @revoked in a second one. Both entries must be reported, the refusal
  # must still happen and @revoked must be the documented reason.
  def test_allow_and_revocation_conflict_across_two_files_prefers_revocation
    allow_file = write_known_hosts("#{HOST} #{line(conflict_key)}")
    revoke_file = write_known_hosts("@revoked #{HOST} #{line(conflict_key)}")

    options = known_hosts_options([allow_file, revoke_file]).merge(verify_host_key_evidence: true)
    host_keys = Net::SSH::KnownHosts.search_for(HOST, options)
    session = Session.new(host_keys, 22, { ip: "127.0.0.1" }, options)

    error = assert_raises(Net::SSH::HostKeyRevoked) do
      Net::SSH::Verifiers::Always.new.verify(session: session, key: conflict_key, fingerprint: "fp")
    end

    evidence = error.trust_evidence
    assert_equal :rejected, evidence.decision
    assert_equal :revoked, evidence.reason
    assert_equal 2, evidence.entries.size
    assert(evidence.entries.all? { |entry| entry[:key_match] })
    assert_equal :key, evidence.entries.first[:entry_kind]
    assert_equal File.expand_path(allow_file), evidence.entries.first[:location][:source]
    assert_equal :revoked, evidence.entries.last[:entry_kind]
    assert_equal File.expand_path(revoke_file), evidence.entries.last[:location][:source]
    assert_equal 1, evidence.matching_revocations.size
    assert_equal File.expand_path(revoke_file), evidence.matching_revocations.first[:location][:source]
  ensure
    File.unlink(allow_file, revoke_file)
  end

  # The evidence must not change the actual decision: without it the same setup
  # raises the same HostKeyRevoked.
  def test_revocation_conflict_refuses_identically_without_evidence
    allow_file = write_known_hosts("#{HOST} #{line(conflict_key)}")
    revoke_file = write_known_hosts("@revoked #{HOST} #{line(conflict_key)}")
    begin
      options = known_hosts_options([allow_file, revoke_file])
      host_keys = Net::SSH::KnownHosts.search_for(HOST, options)
      session = Session.new(host_keys, 22, { ip: "127.0.0.1" }, options)
      assert_raises(Net::SSH::HostKeyRevoked) do
        Net::SSH::Verifiers::Always.new.verify(session: session, key: conflict_key, fingerprint: "fp")
      end
    ensure
      File.unlink(allow_file, revoke_file)
    end
  end

  # A hashed known_hosts line must not reveal the raw |1|salt|hash token, or the
  # evidence would let an attacker brute-force the full host list offline.
  def test_hashed_host_pattern_is_redacted
    salt = "0123456789abcdefghij"
    hash = OpenSSL::HMAC.digest(OpenSSL::Digest.new("sha1"), salt, HOST)
    hashed = "|1|#{[salt].pack('m0')}|#{[hash].pack('m0')}"
    with_known_hosts("#{hashed} #{line(pinned_key)}") do |path|
      error = assert_raises(Net::SSH::HostKeyMismatch) { verify(path, other_key, evidence: true) }
      location = error.trust_evidence.entries.first[:location]
      assert_equal true, location[:hashed]
      assert_equal Net::SSH::HostKeyEntryLocation::HASHED_PATTERN, location[:host_pattern]
      refute_match(/\|1\|/, error.trust_evidence.inspect)
      refute_includes error.trust_evidence.inspect, salt
    end
  end

  def test_hashed_revocation_line_is_redacted_and_still_refuses
    salt = "0123456789abcdefghij"
    hash = OpenSSL::HMAC.digest(OpenSSL::Digest.new("sha1"), salt, HOST)
    hashed = "|1|#{[salt].pack('m0')}|#{[hash].pack('m0')}"
    with_known_hosts("@revoked #{hashed} #{line(conflict_key)}") do |path|
      error = assert_raises(Net::SSH::HostKeyRevoked) { verify(path, conflict_key, evidence: true) }
      location = error.trust_evidence.matching_revocations.first[:location]
      assert_equal true, location[:hashed]
      assert_equal Net::SSH::HostKeyEntryLocation::HASHED_PATTERN, location[:host_pattern]
      refute_includes error.trust_evidence.inspect, salt
    end
  end

  # Scenario 2: a certificate signed by a trusted CA whose principal does not
  # cover the connected host. The CA entry is located and the hostname check is
  # the single failed one; validity passes; the remaining checks never ran.
  def test_trusted_ca_with_wrong_hostname_locates_ca_entry_and_failing_check
    with_known_hosts("@cert-authority #{target_host} #{line(ca_public)}") do |path|
      cert = build_cert(principals: ["evil.example"])
      error = assert_raises(Net::SSH::HostKeyMismatch) { verify(path, cert, host: target_host, evidence: true) }
      evidence = error.trust_evidence

      assert_equal :certificate_hostname, evidence.reason
      assert_match(/not a listed principal/, evidence.detail)
      assert_equal :fail, evidence.checks[:certificate_hostname]
      assert_equal :pass, evidence.checks[:certificate_validity]
      assert_equal :not_run, evidence.checks[:certificate_type]
      assert_equal :not_run, evidence.checks[:critical_options]

      entry = evidence.entries.first
      assert_equal :cert_authority, entry[:entry_kind]
      assert_equal true, entry[:key_match]
      assert_equal 1, entry[:location][:line]
      assert_equal target_host, entry[:location][:host_pattern]
    end
  end

  def test_unexecuted_certificate_checks_are_never_marked_as_passing
    with_known_hosts("@cert-authority #{target_host} #{line(ca_public)}") do |path|
      cert = build_cert(valid_after: Time.now - 7200, valid_before: Time.now - 3600)
      error = assert_raises(Net::SSH::HostKeyMismatch) { verify(path, cert, host: target_host, evidence: true) }
      checks = error.trust_evidence.checks
      assert_equal :fail, checks[:certificate_validity]
      assert_equal :not_run, checks[:certificate_hostname]
      assert_equal :not_run, checks[:certificate_type]
      assert_equal :not_run, checks[:critical_options]
      assert_equal :certificate_validity, error.trust_evidence.reason
    end
  end

  def test_all_certificate_checks_pass_for_a_valid_certificate
    with_known_hosts("@cert-authority #{target_host} #{line(ca_public)}") do |path|
      cert = build_cert
      assert verify(path, cert, host: target_host, evidence: true)
    end
  end

  def test_unknown_host_evidence_has_no_entries
    with_known_hosts("other.test #{line(pinned_key)}") do |path|
      error = assert_raises(Net::SSH::HostKeyUnknown) { verify(path, other_key, host: HOST, evidence: true) }
      assert_equal :unknown, error.trust_evidence.reason
      assert_empty error.trust_evidence.entries
      assert_equal :not_run, error.trust_evidence.checks[:certificate_hostname]
    end
  end

  # Observing entries for the evidence must not change key selection order: the
  # accepted key is still the first matching pinned key.
  def test_evidence_does_not_change_key_selection_order
    with_known_hosts("#{HOST} #{line(other_key)}", "#{HOST} #{line(pinned_key)}") do |path|
      assert verify(path, other_key, evidence: true)

      options = known_hosts_options(path).merge(verify_host_key_evidence: true)
      host_keys = Net::SSH::KnownHosts.search_for(HOST, options)
      assert_equal [other_key.ssh_type, pinned_key.ssh_type], host_keys.map(&:ssh_type)
    end
  end

  def test_evidence_is_attached_through_accept_new_and_tunnel_verifiers
    with_known_hosts("@revoked #{HOST} #{line(conflict_key)}") do |path|
      [Net::SSH::Verifiers::AcceptNew, Net::SSH::Verifiers::AcceptNewOrLocalTunnel].each do |verifier|
        error = assert_raises(Net::SSH::HostKeyRevoked) { verify(path, conflict_key, verifier: verifier, evidence: true) }
        assert_equal :revoked, error.trust_evidence.reason
      end
    end
  end

  def test_to_h_is_loggable_and_carries_every_field
    with_known_hosts("#{HOST} #{line(pinned_key)}") do |path|
      error = assert_raises(Net::SSH::HostKeyMismatch) { verify(path, other_key, evidence: true) }
      hash = error.trust_evidence.to_h
      assert_equal %i[host presented_key_type presented_fingerprint decision reason detail checks entries],
                   hash.keys
      assert_kind_of Hash, hash[:checks]
      assert_kind_of Array, hash[:entries]
      assert_equal "fp", hash[:presented_fingerprint]
    end
  end

  private

  def pinned_key
    @pinned_key ||= OpenSSL::PKey::RSA.new(2048).public_key
  end

  def other_key
    @other_key ||= OpenSSL::PKey::RSA.new(2048).public_key
  end

  def conflict_key
    @conflict_key ||= OpenSSL::PKey::RSA.new(2048).public_key
  end

  def ca_private
    @ca_private ||= OpenSSL::PKey::RSA.new(CertAuthorityCheckFixtures::CA_KEY)
  end

  def ca_public
    ca_private.public_key
  end

  def host_private
    @host_private ||= OpenSSL::PKey::RSA.new(CertAuthorityCheckFixtures::KEY)
  end

  def target_host
    "prod-db.example.com"
  end

  def build_cert(principals: [target_host], valid_after: Time.now - 3600,
                 valid_before: Time.now + 3600, critical_options: {}, type: :host)
    cert = Net::SSH::Buffer.new(CertAuthorityCheckFixtures::SIGNED_CERT).read_key
    cert.key = host_private
    cert.type = type
    cert.valid_principals = principals
    cert.valid_after = valid_after
    cert.valid_before = valid_before
    cert.critical_options = critical_options
    cert.sign!(ca_private)
    cert
  end

  def line(key)
    "#{key.ssh_type} #{[key.to_blob].pack('m0')}"
  end

  def known_hosts_options(path, **options)
    files = Array(path)
    { user_known_hosts_file: files, global_known_hosts_file: [] }.merge(options)
  end

  def with_known_hosts(*lines)
    file = Tempfile.create("known_hosts")
    file.puts(lines)
    file.close
    yield file.path
  ensure
    File.unlink(file.path) if file && File.exist?(file.path)
  end

  def write_known_hosts(*lines)
    file = Tempfile.create("known_hosts")
    file.puts(lines)
    file.close
    file.path
  end

  def verify(path, key, verifier: Net::SSH::Verifiers::Always, host: HOST, port: 22, evidence: false)
    options = known_hosts_options(path)
    options[:verify_host_key_evidence] = true if evidence
    host_keys = Net::SSH::KnownHosts.search_for(host, options)
    session = Session.new(host_keys, port, { ip: "127.0.0.1" }, options)
    verifier.new.verify(session: session, key: key, fingerprint: "fp")
  end
end
