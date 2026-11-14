require "common"
require "net/ssh"
require "net/ssh/verifiers/accept_new"
require "tmpdir"

# First-registration races: two connections to a new host must not both
# register a key. The file is the source of truth: after both connections
# settle, the key read back from it must match what each connection was told.
class TestAcceptNewAtomicRegistration < NetSSHTest
  HOST = "new-host.test"
  Session = Struct.new(:host_keys, :port, :peer)

  def test_concurrent_connections_with_the_same_key_register_it_once
    Dir.mktmpdir do |dir|
      path = File.join(dir, "known_hosts")
      File.write(path, "# header comment\nother.test #{line(other_key)}\n")

      results = run_concurrently(path, [key, key])

      assert_equal %i[accepted accepted], results.map { |r| r[:outcome] }
      assert_equal 1, registered_keys(path, HOST).size
      assert results.all? { |r| same_keys?(r[:registered], registered_keys(path, HOST)) }
      assert_equal "# header comment", File.readlines(path).first.chomp
      assert_includes File.read(path), "other.test "
    end
  end

  def test_concurrent_connections_with_different_keys_leave_one_winner
    Dir.mktmpdir do |dir|
      path = File.join(dir, "known_hosts")
      File.write(path, "")

      results = run_concurrently(path, [key, other_key()])

      outcome = results.map { |r| r[:outcome] }
      assert_includes outcome, :accepted
      assert_includes outcome, :mismatch
      registered = registered_keys(path, HOST)
      assert_equal 1, registered.size

      # The connection that lost must not have added a key of its own,
      # and the winner's key must be the one on disk for the next connection.
      results.each do |result|
        next unless result[:outcome] == :mismatch

        refute result[:registered].any? { |blob| blob == result[:key].to_blob }
        assert_raises(Net::SSH::HostKeyMismatch) { verify(path, result[:key]) }
      end

      winner = results.find { |r| r[:outcome] == :accepted }
      assert_equal winner[:key].to_blob, registered.first
      assert verify(path, winner[:key])
    end
  end

  def test_registration_failure_is_refused_and_not_remembered
    Dir.mktmpdir do |dir|
      path = File.join(dir, "known_hosts")
      File.write(path, "")

      results = run_concurrently(path, [key, key], read_path: path, readonly_after: :status)

      assert_equal %i[write_failed write_failed], results.map { |r| r[:outcome] }
      assert results.all? { |r| r[:registered].nil? }
      assert_empty File.read(path)

      # The next connection reads the same fact: the host is still unknown,
      # and registering again fails the same way instead of trusting the key.
      assert_empty Net::SSH::KnownHosts.new(path).keys_for(HOST)
      assert_raises(Net::SSH::HostKeyWriteFailed) { verify_with_accept_new(path, key) }
    end
  end

  def test_write_failure_is_not_overridable_by_remember_host
    Dir.mktmpdir do |dir|
      path = File.join(dir, "known_hosts")
      File.write(path, "")
      File.chmod(0o400, path)

      options = { user_known_hosts_file: path, global_known_hosts_file: [] }
      host_keys = Net::SSH::KnownHosts.search_for(HOST, options)
      session = Session.new(host_keys, 22, { ip: "192.0.2.10" })

      error = assert_raises(Net::SSH::HostKeyWriteFailed) do
        Net::SSH::Verifiers::AcceptNew.new.verify(session: session, key: key, fingerprint: "fp")
      end
      assert host_keys.empty?
      assert_raises(Net::SSH::HostKeyWriteFailed) { error.remember_host! }
      assert_empty Net::SSH::KnownHosts.new(path).keys_for(HOST)
    end
  end

  def test_concurrent_registrations_of_the_same_key_in_two_files_never_split_the_trust
    Dir.mktmpdir do |dir|
      first = File.join(dir, "known_hosts")
      second = File.join(dir, "known_hosts2")
      File.write(first, "")
      File.write(second, "")

      options = { user_known_hosts_file: [first, second], global_known_hosts_file: [] }
      results = run_concurrently_files(options, [key, other_key])

      accepted = results.select { |r| r[:outcome] == :accepted }
      assert_equal 1, accepted.size, "only one key may be registered, got #{results.inspect}"

      registered = (registered_keys(first, HOST) + registered_keys(second, HOST)).uniq
      assert_equal 1, registered.size
      assert_equal accepted.first[:key].to_blob, registered.first
    end
  end

  private

  def run_concurrently_files(options, keys)
    start = Queue.new
    threads = keys.map do |candidate|
      Thread.new do
        start.pop
        begin
          host_keys = Net::SSH::KnownHosts.search_for(HOST, options)
          session = Session.new(host_keys, 22, { ip: "192.0.2.10" })
          Net::SSH::Verifiers::AcceptNew.new.verify(session: session, key: candidate, fingerprint: "fp")
          { outcome: :accepted, key: candidate }
        rescue Net::SSH::HostKeyMismatch
          { outcome: :mismatch, key: candidate }
        rescue Net::SSH::HostKeyWriteFailed
          { outcome: :write_failed, key: candidate }
        end
      end
    end

    keys.each { start << true }
    threads.map(&:value)
  end

  def verify_with_accept_new(path, candidate)
    options = { user_known_hosts_file: path, global_known_hosts_file: [] }
    host_keys = Net::SSH::KnownHosts.search_for(HOST, options)
    session = Session.new(host_keys, 22, { ip: "192.0.2.10" })
    Net::SSH::Verifiers::AcceptNew.new.verify(session: session, key: candidate, fingerprint: "fp")
  end

  def run_concurrently(path, keys, read_path: nil, readonly_after: nil)
    options = { user_known_hosts_file: read_path || path, global_known_hosts_file: [] }

    if readonly_after == :status
      File.chmod(0o400, read_path)
    end
    start = Queue.new
    threads = keys.map do |candidate|
      Thread.new do
        start.pop
        begin
          host_keys = Net::SSH::KnownHosts.search_for(HOST, options)
          session = Session.new(host_keys, 22, { ip: "192.0.2.10" })
          verifier = Net::SSH::Verifiers::AcceptNew.new
          verifier.verify(session: session, key: candidate, fingerprint: "fp")
          { outcome: :accepted, key: candidate,
            registered: Net::SSH::KnownHosts.new(read_path || path).keys_for(HOST).map(&:to_blob) }
        rescue Net::SSH::HostKeyMismatch
          { outcome: :mismatch, key: candidate,
            registered: Net::SSH::KnownHosts.new(read_path || path).keys_for(HOST).map(&:to_blob) }
        rescue Net::SSH::HostKeyWriteFailed
          { outcome: :write_failed, key: candidate, registered: nil }
        end
      end
    end

    keys.each { start << true }
    threads.map(&:value)
  end

  def verify(path, candidate)
    options = { user_known_hosts_file: path, global_known_hosts_file: [] }
    host_keys = Net::SSH::KnownHosts.search_for(HOST, options)
    session = Session.new(host_keys, 22, { ip: "192.0.2.10" })
    Net::SSH::Verifiers::Always.new.verify(session: session, key: candidate, fingerprint: "fp")
  end

  def registered_keys(path, host)
    Net::SSH::KnownHosts.new(path).keys_for(host).map(&:to_blob)
  end

  def same_keys?(left, right)
    left.sort == right.sort
  end

  def key
    @key ||= OpenSSL::PKey::RSA.new(2048).public_key
  end

  def other_key
    @other_key ||= OpenSSL::PKey::RSA.new(2048).public_key
  end

  def line(candidate)
    "#{candidate.ssh_type} #{[candidate.to_blob].pack('m0')}"
  end
end
