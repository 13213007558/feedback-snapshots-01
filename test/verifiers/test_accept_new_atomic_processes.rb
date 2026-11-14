require "common"
require "net/ssh"
require "net/ssh/verifiers/accept_new"
require "tmpdir"

# The same race across OS processes, which is what a deployment system with
# concurrent workers does. File locks are per open file description, so this
# exercises flock across processes rather than only across threads.
class TestAcceptNewAtomicRegistrationProcesses < NetSSHTest
  HOST = "new-host.test"

  def test_two_processes_with_different_keys_cannot_both_register
    skip "fork is not available on this platform" unless Process.respond_to?(:fork)

    Dir.mktmpdir do |dir|
      path = File.join(dir, "known_hosts")
      File.write(path, "")
      keys = [write_key(dir, "one"), write_key(dir, "two")]

      results = run_in_processes(path, keys)

      accepted = results.select { |r| r[:outcome] == :accepted }
      mismatched = results.select { |r| r[:outcome] == :mismatch }
      assert_equal 1, accepted.size, results.inspect
      assert_equal 1, mismatched.size, results.inspect

      registered = Net::SSH::KnownHosts.new(path).keys_for(HOST).map(&:to_blob)
      assert_equal 1, registered.size
      assert_equal accepted.first[:blob], registered.first
    end
  end

  def test_two_processes_with_the_same_key_both_accept_it_once
    skip "fork is not available on this platform" unless Process.respond_to?(:fork)

    Dir.mktmpdir do |dir|
      path = File.join(dir, "known_hosts")
      File.write(path, "")
      file = write_key(dir, "one")

      results = run_in_processes(path, [file, file])

      assert_equal %i[accepted accepted], results.map { |r| r[:outcome] }
      assert_equal 1, File.readlines(path).reject { |line| line.strip.empty? }.size
    end
  end

  private

  def write_key(dir, name)
    key = OpenSSL::PKey::RSA.new(2048).public_key
    path = File.join(dir, "#{name}.pub")
    File.binwrite(path, key.to_blob)
    path
  end

  def run_in_processes(known_hosts, key_files)
    results = key_files.map do |key_file|
      reader, writer = IO.pipe

      pid = fork do
        reader.close
        writer.write(Marshal.dump(child_registration(known_hosts, key_file)))
        writer.close
        exit!(0)
      end

      writer.close
      [pid, reader]
    end

    results.map do |pid, reader|
      Process.wait(pid)
      data = reader.read
      reader.close
      Marshal.load(data)
    end
  end

  def child_registration(known_hosts, key_file)
    require "net/ssh/known_hosts"
    require "net/ssh/verifiers/accept_new"

    key = Net::SSH::Buffer.new(File.binread(key_file)).read_key
    options = { user_known_hosts_file: known_hosts, global_known_hosts_file: [] }
    host_keys = Net::SSH::KnownHosts.search_for(HOST, options)
    session = Struct.new(:host_keys, :port, :peer).new(host_keys, 22, { ip: "192.0.2.10" })
    Net::SSH::Verifiers::AcceptNew.new.verify(session: session, key: key, fingerprint: "fp")
    { outcome: :accepted, blob: key.to_blob }
  rescue Net::SSH::HostKeyMismatch
    { outcome: :mismatch, blob: key.to_blob }
  rescue Net::SSH::HostKeyWriteFailed
    { outcome: :write_failed, blob: key.to_blob }
  end
end
