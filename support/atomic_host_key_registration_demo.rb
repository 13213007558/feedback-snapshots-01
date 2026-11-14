# Demonstrates first-time host key registration with verify_host_key: :accept_new:
# two concurrent connections to the same new host using a temporary known_hosts
# file, for the same key, two different keys, and a write failure. It also
# checks that the decision each connection got matches what the next connection
# reads back from the file.
#
#   bundle exec ruby -Ilib support/atomic_host_key_registration_demo.rb

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "net/ssh"
require "net/ssh/verifiers/accept_new"
require "openssl"
require "tmpdir"

HOST = "demo-host.test"
Session = Struct.new(:host_keys, :port, :peer)

def new_key
  OpenSSL::PKey::RSA.new(2048).public_key
end

def line_for(key)
  "#{key.ssh_type} #{[key.to_blob].pack('m0')}"
end

def keys_in(path)
  Net::SSH::KnownHosts.new(path).keys_for(HOST).map(&:to_blob)
end

def attempt(path, key)
  options = { user_known_hosts_file: path, global_known_hosts_file: [] }
  session = Session.new(Net::SSH::KnownHosts.search_for(HOST, options), 22, { ip: "192.0.2.10" })
  Net::SSH::Verifiers::AcceptNew.new.verify(session: session, key: key, fingerprint: "fp")
  [:accepted, keys_in(path)]
rescue Net::SSH::HostKeyMismatch
  [:mismatch, keys_in(path)]
rescue Net::SSH::HostKeyWriteFailed
  [:write_failed, keys_in(path)]
end

# Start both connections as simultaneously as Ruby threads allow.
def race(path, keys)
  start = Queue.new
  threads = keys.map { |key| Thread.new { start.pop; attempt(path, key) } }
  keys.size.times { start << true }
  threads.map(&:value)
end

def report(results, path)
  live = keys_in(path)
  results.each do |outcome, seen|
    consistent = outcome == :write_failed ? live.empty? : seen == live
    puts "  connection #{outcome}, next connection reads the same: #{consistent}"
  end
end

Dir.mktmpdir do |dir|
  puts "same key:"
  path = File.join(dir, "same")
  File.write(path, "# comment for another host\nother.test #{line_for(new_key)}\n")
  same = new_key
  report(race(path, [same, same]), path)
  puts "  registered keys: #{keys_in(path).size}, comments and other hosts kept: #{File.read(path).include?('# comment')}"

  puts "different keys:"
  path = File.join(dir, "different")
  File.write(path, "")
  report(race(path, [new_key, new_key]), path)
  puts "  registered keys: #{keys_in(path).size}"

  puts "write failure (read-only known_hosts):"
  path = File.join(dir, "readonly")
  File.write(path, "")
  File.chmod(0o400, path)
  report(race(path, [same, same]), path)
  puts "  registered keys: #{keys_in(path).size}"
end
