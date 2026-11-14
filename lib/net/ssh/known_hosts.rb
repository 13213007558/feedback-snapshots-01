require 'strscan'
require 'openssl'
require 'net/ssh/buffer'
require 'net/ssh/errors'
require 'net/ssh/authentication/ed25519_loader'

module Net
  module SSH
    module HostKeyEntries
      # regular public key entry
      class PubKey
        # The public key itself, e.g. an OpenSSL::PKey::PKey.
        attr_reader :key

        def initialize(key, comment: nil)
          @key = key
          @comment = comment
        end

        def ssh_type
          @key.ssh_type
        end

        def ssh_types
          [ssh_type]
        end

        def to_blob
          @key.to_blob
        end

        def matches_key?(server_key)
          @key.ssh_type == server_key.ssh_type && @key.to_blob == server_key.to_blob
        end

        def method_missing(name, *args, &block)
          return super unless @key.respond_to?(name)

          raise NoMethodError.new(
            "undefined method `#{name}' for #{self.class}; call it on #key, the wrapped public key",
            name
          )
        end

        def respond_to_missing?(_name, _include_private = false)
          false
        end
      end

      # @cert-authority entry
      class CertAuthority
        def ssh_types
          %w[
            ecdsa-sha2-nistp256-cert-v01@openssh.com
            ecdsa-sha2-nistp384-cert-v01@openssh.com
            ecdsa-sha2-nistp521-cert-v01@openssh.com
            ssh-ed25519-cert-v01@openssh.com
            ssh-rsa-cert-v01@openssh.com
            ssh-rsa-cert-v00@openssh.com
          ]
        end

        def initialize(key, comment: nil)
          @key = key
          @comment = comment
        end

        def matches_key?(server_key)
          if ssh_types.include?(server_key.ssh_type)
            server_key.signature_valid? && (server_key.signature_key.to_blob == @key.to_blob)
          else
            false
          end
        end

        # Returns true if the certificate lists no principals (unrestricted) or
        # if the given hostname matches a listed principal. Host-certificate
        # principals are shell-glob patterns, matching OpenSSH, whose
        # sshkey_cert_check_host passes wildcard_pattern=1 so principals like
        # "*.example.com" are matched with match_pattern rather than strcmp.
        def matches_principal?(server_key, hostname)
          server_key.valid_principals.empty? ||
            server_key.valid_principals.any? { |principal| File.fnmatch(principal, hostname) }
        end

        # Returns true if the certificate's validity window covers the current time.
        def matches_validity?(server_key)
          return false if server_key.valid_after && server_key.valid_after > Time.now
          return false if server_key.valid_before && server_key.valid_before < Time.now

          true
        end

        # Returns true if the certificate is a host certificate. A user
        # certificate (type :user) must never authenticate a host.
        def matches_type?(server_key)
          server_key.type == :host
        end

        # Returns true if every critical option in the certificate is one we can
        # enforce. net-ssh enforces none, so any critical option is unsupported
        # and, as OpenSSH does, must cause the certificate to be rejected.
        def critical_options_supported?(server_key)
          server_key.critical_options.empty?
        end
      end

      # @revoked entry
      class Revoked
        def initialize(key, comment: nil)
          @key = key
          @comment = comment
        end

        # Returns true for the revoked key itself and for any certificate that
        # wraps it or is signed by it, matching OpenSSH's check_key_not_revoked.
        def matches_key?(server_key)
          keys = [server_key]
          keys += [server_key.key, server_key.signature_key] if server_key.respond_to?(:signature_key)
          keys.any? { |key| key.ssh_type == @key.ssh_type && key.to_blob == @key.to_blob }
        end
      end
    end

    # Represents the result of a search in known hosts
    # see search_for
    class HostKeys
      include Enumerable
      attr_reader :host

      def initialize(host_keys, host, known_hosts, options = {}, revoked_keys = [])
        @host_keys = host_keys
        @host = host
        @known_hosts = known_hosts
        @options = options
        @revoked_keys = revoked_keys
      end

      # Returns true if a @revoked known-hosts entry for this host matches +key+.
      def revoked?(key)
        @revoked_keys.any? { |entry| entry.matches_key?(key) }
      end

      # Adds the key to the known hosts and returns true only if it was
      # persisted, or if it already matches an entry for this host. A custom
      # known_hosts object must return true, :added or :matched to confirm
      # that; false, nil or any other value is treated as a failed
      # registration, so a key is never trusted only in memory. Registration
      # errors are not hidden either: they propagate, and the in-memory
      # collection is only updated after a successful registration.
      def add_host_key(key)
        result = @known_hosts.add(@host, key, @options)

        unless [true, :added, :matched].include?(result)
          raise HostKeyWriteFailed, "could not add the host key for #{@host.inspect} to known_hosts"
        end

        @host_keys.push(key) unless @host_keys.any? do |known|
          if known.respond_to?(:matches_key?)
            known.matches_key?(key)
          else
            known.ssh_type == key.ssh_type && known.to_blob == key.to_blob
          end
        end

        true
      end

      def each(&block)
        @host_keys.each(&block)
      end

      def empty?
        @host_keys.empty?
      end

      # Returns the bare hostname, stripping port and IP portions from the
      # comma-separated host string used internally.
      #
      # Examples:
      #   "server.example.com"            => "server.example.com"
      #   "server.example.com,1.2.3.4"    => "server.example.com"
      #   "[server.example.com]:2222"      => "server.example.com"
      def hostname
        @host.split(",").first.gsub(/\[|\]:\d+/, "")
      end
    end

    # Searches an OpenSSH-style known-host file for a given host, and returns all
    # matching keys. This is used to implement host-key verification, as well as
    # to determine what key a user prefers to use for a given host.
    #
    # This is used internally by Net::SSH, and will never need to be used directly
    # by consumers of the library.
    class KnownHosts
      SUPPORTED_TYPE = %w[ssh-rsa ssh-dss
                          ecdsa-sha2-nistp256
                          ecdsa-sha2-nistp384
                          ecdsa-sha2-nistp521]

      SUPPORTED_TYPE.push('ssh-ed25519') if Net::SSH::Authentication::ED25519Loader::LOADED

      class << self
        # Searches all known host files (see KnownHosts.hostfiles) for all keys
        # of the given host. Returns an enumerable of keys found.
        def search_for(host, options = {})
          files = hostfiles(options)
          revoked_keys = files.flat_map { |file| KnownHosts.new(file).revoked_keys_for(host) }
          HostKeys.new(search_in(files, host, options), host, self, options, revoked_keys)
        end

        # Search for all known keys for the given host, in every file given in
        # the +files+ array. Returns the list of keys. @revoked entries are not
        # included.
        def search_in(files, host, options = {})
          files.flat_map { |file| KnownHosts.new(file).keys_for(host, options) }
        end

        # Looks in the given +options+ hash for the :user_known_hosts_file and
        # :global_known_hosts_file keys, and returns an array of all known
        # hosts files. If the :user_known_hosts_file key is not set, the
        # default is returned (~/.ssh/known_hosts and ~/.ssh/known_hosts2). If
        # :global_known_hosts_file is not set, the default is used
        # (/etc/ssh/ssh_known_hosts and /etc/ssh/ssh_known_hosts2).
        #
        # If you only want the user known host files, you can pass :user as
        # the second option.
        def hostfiles(options, which = :all)
          files = []

          files += Array(options[:user_known_hosts_file] || %w[~/.ssh/known_hosts ~/.ssh/known_hosts2]) if which == :all || which == :user

          if which == :all || which == :global
            files += Array(options[:global_known_hosts_file] || %w[/etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2])
          end

          return files
        end

        # Registers +key+ for +host+ in the user known-hosts files (see
        # KnownHosts.hostfiles), first time only, and returns how it was
        # trusted:
        #
        #   :added   the key was appended and read back from the file
        #   :matched the host already had exactly this key in a configured file
        #
        # The comparison and the append happen while holding exclusive locks on
        # the files involved, so two connections racing to register the same
        # new host cannot both write a key. If a configured file already has a
        # different key for the host, HostKeyMismatch is raised and no file is
        # modified; a key marked @revoked raises HostKeyRevoked. Failures to
        # write, flush or read the key back raise too, so the caller must only
        # treat the key as trusted after :added or :matched.
        #
        # When several known-hosts files are configured, an entry for the host
        # in any of them counts, as during verification: a file with this key
        # makes the result :matched, and a different key in any file is a
        # conflict and raises HostKeyMismatch. A host with no entry anywhere is
        # registered in the first configured user file that can be written, as
        # OpenSSH does; if that file can't be written, the next one is tried.
        # Global files are read but never written. Files are appended to, never
        # rewritten, so comments and entries for other hosts are preserved.
        #
        # Returns false when the caller passed no files at all, e.g. a custom
        # :known_hosts object that can't persist anything. When none of the
        # configured files can be written, HostKeyWriteFailed is raised.
        def add(host, key, options = {})
          read_paths = hostfiles(options, :all).map { |path| File.expand_path(path) }.uniq
          write_paths = hostfiles(options, :user).map { |path| File.expand_path(path) }.uniq
          return false if read_paths.empty?

          attempts = 0

          loop do
            attempts += 1
            locks = {}
            retry_needed = false
            last_error = nil

            begin
              # Lock existing user files in a stable (absolute path) order, so
              # processes with overlapping lists can't deadlock.
              write_paths.sort.each do |path|
                next unless File.file?(path)

                locks[path] = lock_file(path)
              end

              # A file may have appeared between our checks; if it did, its
              # entries aren't covered by the comparison below, so start over.
              retry_needed = pending_paths(write_paths, locks).any? { |path| File.file?(path) }

              unless retry_needed
                # Configured global files are read but never written; a key
                # registered there is as good as one registered in a user file.
                state = registration_state(read_paths, locks, host, key, options)
                return :matched if state == :matched

                write_paths.each do |path|
                  lock = locks[path]

                  unless lock
                    begin
                      # Non-blocking: if another process is creating or locking
                      # this path, retry with it included rather than risk a
                      # lock-order inversion.
                      lock = lock_file(path, create: true, nonblock: true)
                    rescue Errno::EWOULDBLOCK
                      retry_needed = true
                      break
                    rescue SystemCallError => error
                      last_error = error
                      next
                    end

                    locks[path] = lock
                  end

                  next unless lock[:writable]

                  # Another connection may have registered a key for this host
                  # while we waited for a lock, so compare again under them.
                  return :matched if registration_state(read_paths, locks, host, key, options) == :matched

                  begin
                    append_key(lock[:io], host, key, options)
                    return :added
                  rescue SystemCallError, IOError => error
                    last_error = error
                  end
                end
              end
            ensure
              locks.each_value { |lock| unlock_file(lock) }
            end

            if retry_needed
              if attempts >= 10
                raise HostKeyWriteFailed, "unable to lock a known hosts file to register the key for #{host.inspect}"
              end

              sleep(0.002 * attempts)
              next
            end

            if last_error
              raise HostKeyWriteFailed, "unable to write the host key for #{host.inspect} to a known hosts file: #{last_error.message}"
            end

            raise HostKeyWriteFailed,
                  "no writable known hosts file to register the host key for #{host.inspect}"
          end
        end

        private

        def pending_paths(paths, locks)
          paths.reject { |path| locks.key?(path) }
        end

        # Opens and exclusively locks a known-hosts file, creating it when
        # +create+ is set. A file that exists but can't be opened read-write is
        # still locked read-only, so its entries take part in the comparison,
        # but it is never chosen for the append.
        def lock_file(path, create: false, nonblock: false)
          writable = true
          io =
            if create
              File.open(path, File::RDWR | File::CREAT | File::APPEND)
            else
              begin
                File.open(path, File::RDWR)
              rescue Errno::EACCES, Errno::EPERM, Errno::EROFS
                writable = false
                File.open(path, File::RDONLY)
              end
            end

          locked = io.flock(File::LOCK_EX | (nonblock ? File::LOCK_NB : 0))
          raise Errno::EWOULDBLOCK, path if locked == false

          io.binmode
          { io: io, writable: writable }
        rescue SystemCallError
          io&.close
          raise
        end

        def unlock_file(lock)
          lock[:io].flock(File::LOCK_UN)
        rescue SystemCallError
          # Closing the file releases the lock anyway.
        ensure
          lock[:io].close
        end

        # Compares the key with the host's entries in the configured files.
        # Returns :matched, :none, or raises HostKeyRevoked / HostKeyMismatch.
        # A matching entry wins over a conflicting one in another file, as it
        # does during verification.
        def registration_state(paths, locks, host, key, options)
          entries = host.split(',')
          same_key = false
          other_key = false

          paths.each do |path|
            content =
              if locks.key?(path)
                read_locked(locks[path][:io])
              elsif File.file?(path) && File.readable?(path)
                File.binread(path)
              else
                ''
              end

            each_known_host_entry(content) do |marker, hostlist, key_content, _comment|
              known = parse_entry_key(key_content)
              # Match keys_for and revoked_keys_for: an entry of a key type
              # verification can't use, such as a host certificate, is neither
              # a pin nor a revocation here.
              next unless known && SUPPORTED_TYPE.include?(known.ssh_type)

              if marker == '@revoked'
                next unless revoked_entry_matches?(hostlist, entries)
                raise HostKeyRevoked, "host key for #{host.inspect} is revoked" if HostKeyEntries::Revoked.new(known).matches_key?(key)

                next
              end

              # @cert-authority entries trust a CA, so they neither pin this
              # host to one concrete key nor conflict with an issued
              # certificate or a plain key.
              next if marker == '@cert-authority'
              next unless key_entry_matches?(hostlist, entries, options)

              if same_key_as?(known, key)
                same_key = true
              else
                other_key = true
              end
            end
          end

          return :matched if same_key

          raise HostKeyMismatch, "host key for #{host.inspect} does not match the key already registered" if other_key

          :none
        end

        def read_locked(io)
          io.rewind
          io.read || ''
        end

        # Yields the marker, host patterns, key content and comment of every
        # usable line of the given known-hosts content. Unlike each_entry, key
        # types outside SUPPORTED_TYPE are yielded too, so registration can
        # compare and read back a key type that verification can't use yet.
        def each_known_host_entry(content)
          content.each_line do |line|
            fields = line.split(' ')
            marker = fields.shift if fields.first&.start_with?('@')
            hosts, type, key_content, comment = fields

            # Skip empty line or one that is commented
            next if hosts.nil? || hosts.start_with?('#')
            next if type.nil? || key_content.nil?

            yield marker, hosts.split(','), key_content, comment
          end
        end

        def parse_entry_key(key_content)
          entry_key(key_content)
        rescue Net::SSH::UnsupportedKeyType, ArgumentError, TypeError
          nil
        end

        def entry_key(key_content)
          Net::SSH::Buffer.new(key_content.unpack('m*').first).read_key
        end

        def same_key_as?(known, key)
          known.ssh_type == key.ssh_type && known.to_blob == key.to_blob
        end

        def key_entry_matches?(hostlist, entries, options)
          found = hostlist.any? { |pattern| blank.match(entries.first, pattern) } ||
                  blank.known_host_hash?(hostlist, entries)
          return false unless found

          if options[:check_host_ip] && entries.size > 1 && hostlist.size > 1
            found = hostlist.include?(entries[1])
          end

          found
        end

        def revoked_entry_matches?(hostlist, entries)
          entries.any? { |entry| hostlist.any? { |pattern| blank.match(entry, pattern) } } ||
            blank.known_host_hash?(hostlist, entries)
        end

        # A host-less instance used for its matching helpers.
        def blank
          @blank ||= new('')
        end

        # Appends one entry and reads it back from the file before reporting
        # success. On failure only the bytes of this attempt are rolled back,
        # so a line another process appended after our offset is not lost.
        def append_key(io, host, key, options)
          io.seek(0, IO::SEEK_END)
          offset = io.pos
          separator = ''
          if offset.positive?
            io.seek(-1, IO::SEEK_END)
            separator = "\n" unless io.read(1) == "\n"
          end

          line = "#{separator}#{host} #{key.ssh_type} #{[Net::SSH::Buffer.from(:key, key).to_s].pack('m*').gsub(/\s/, '')}\n"

          begin
            written = io.write(line)
            raise IOError, "short write to #{io.path}" unless written == line.bytesize

            io.flush
            sync_file(io)

            # What matters is that the exact line was read back, even for a key
            # type keys_for does not consume yet, such as a host certificate.
            if io.stat.file? && !written_line_present?(File.binread(io.path), host, key)
              raise IOError, "could not read back the key written to #{io.path}"
            end
          rescue StandardError
            roll_back(io, offset, line)
            raise
          end
        end

        # Removes only the bytes this attempt appended. If another writer added
        # anything beyond them (i.e. the tail is not our line), the file is left
        # alone: it holds evidence this connection can't claim.
        def roll_back(io, offset, line)
          begin
            io.flush
            io.rewind
            tail = io.read.to_s
            appended = tail.byteslice(offset..)
            if appended && line.start_with?(appended)
              io.truncate(offset)
              io.flush
            end
          rescue SystemCallError, IOError
            # The original failure is more useful than a failed cleanup.
          end
        end

        def sync_file(io)
          io.fsync
        rescue Errno::EINVAL, NotImplementedError
          # Some filesystems and special files don't support fsync; the
          # read-back still verifies what was written.
        end

        # Reads the file back to confirm the exact entry that was written is
        # there for this host. The host part is compared exactly, not as a
        # pattern, so a wildcard entry that merely matches is not mistaken for
        # this registration.
        def written_line_present?(content, host, key)
          entries = host.split(',')

          each_known_host_entry(content) do |marker, hostlist, key_content, _comment|
            next unless marker.nil?
            next unless hostlist == entries

            known = parse_entry_key(key_content)
            return true if known && same_key_as?(known, key)
          end

          false
        end
      end

      # The host-key file name that this KnownHosts instance will use to search
      # for keys.
      attr_reader :source

      # Instantiate a new KnownHosts instance that will search the given known-hosts
      # file. The path is expanded file File.expand_path.
      def initialize(source)
        @source = File.expand_path(source)
      rescue ArgumentError
        @source = source
      end

      # Returns an array of all keys that are known to be associatd with the
      # given host. The +host+ parameter is either the domain name or ip address
      # of the host, or both (comma-separated). Additionally, if a non-standard
      # port is being used, it may be specified by putting the host (or ip, or
      # both) in square brackets, and appending the port outside the brackets
      # after a colon. Possible formats for +host+, then, are;
      #
      #   "net.ssh.test"
      #   "1.2.3.4"
      #   "net.ssh.test,1.2.3.4"
      #   "[net.ssh.test]:5555"
      #   "[1,2,3,4]:5555"
      #   "[net.ssh.test]:5555,[1.2.3.4]:5555
      #
      # @revoked entries are not included, see revoked_keys_for.
      def keys_for(host, options = {})
        keys = []
        entries = host.split(/,/)
        host_name = entries[0]
        host_ip = entries[1]

        each_entry do |marker, hostlist, key_content, comment|
          next if marker == "@revoked"

          found = hostlist.any? { |pattern| match(host_name, pattern) } || known_host_hash?(hostlist, entries)
          next unless found

          found = hostlist.include?(host_ip) if options[:check_host_ip] && entries.size > 1 && hostlist.size > 1
          next unless found

          raw_key = read_key(key_content)

          keys <<
            if marker == "@cert-authority"
              HostKeyEntries::CertAuthority.new(raw_key, comment: comment)
            else
              HostKeyEntries::PubKey.new(raw_key, comment: comment)
            end
        end

        keys
      end

      # Returns the @revoked entries for the given host, which takes the same
      # formats as keys_for. An entry matching any of the comma-separated names
      # counts, so :check_host_ip can't narrow a revocation.
      def revoked_keys_for(host)
        keys = []
        entries = host.split(/,/)

        each_entry do |marker, hostlist, key_content, comment|
          next unless marker == "@revoked"

          found = entries.any? { |entry| hostlist.any? { |pattern| match(entry, pattern) } }
          next unless found || known_host_hash?(hostlist, entries)

          keys << HostKeyEntries::Revoked.new(read_key(key_content), comment: comment)
        end

        keys
      end

      def match(host, pattern)
        if pattern.include?('*') || pattern.include?('?')
          # see man 8 sshd for pattern details
          pattern_regexp = pattern.split('*', -1).map do |x|
            x.split('?', -1).map do |y|
              Regexp.escape(y)
            end.join('.')
          end.join('.*')

          host =~ Regexp.new("\\A#{pattern_regexp}\\z")
        else
          host == pattern
        end
      end

      # Indicates whether one of the entries matches an hostname that has been
      # stored as a HMAC-SHA1 hash in the known hosts.
      def known_host_hash?(hostlist, entries)
        if hostlist.size == 1 && hostlist.first =~ /\A\|1(\|.+){2}\z/
          chunks = hostlist.first.split(/\|/)
          salt = chunks[2].unpack1("m")
          digest = OpenSSL::Digest.new('sha1')
          entries.each do |entry|
            hmac = OpenSSL::HMAC.digest(digest, salt, entry)
            return true if [hmac].pack("m").chomp == chunks[3]
          end
        end
        false
      end

      # Tries to append an entry to the current source file for the given host
      # and key. If it is unable to (because the file is not writable, for
      # instance), an exception will be raised. The file is only appended to;
      # comments and entries for other hosts are left untouched. Returns
      # :added or :matched like KnownHosts.add.
      def add(host, key)
        KnownHosts.add(host, key, user_known_hosts_file: source, global_known_hosts_file: [])
      end

      # Yields the marker, host patterns, key and comment of each usable line.
      def each_entry
        return unless File.readable?(source)

        File.open(source) do |file|
          file.each_line do |line|
            fields = line.split(' ')
            marker = fields.shift if fields.first&.start_with?('@')
            hosts, type, key_content, comment = fields

            # Skip empty line or one that is commented
            next if hosts.nil? || hosts.start_with?('#')

            next unless SUPPORTED_TYPE.include?(type)

            yield marker, hosts.split(','), key_content, comment
          end
        end
      end

      def read_key(key_content)
        Net::SSH::Buffer.new(key_content.unpack("m*").first).read_key
      end
    end
  end
end
