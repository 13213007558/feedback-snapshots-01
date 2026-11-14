#
# Copyright (c) 2013-2026 Hal Brodigan (postmodern.mod3 at gmail.com)
#
# bundler-audit is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# bundler-audit is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with bundler-audit.  If not, see <https://www.gnu.org/licenses/>.
#

require 'bundler/audit/snapshot'
require 'bundler/audit/version'

require 'digest'
require 'fileutils'
require 'json'
require 'time'
require 'tmpdir'

module Bundler
  module Audit
    class Snapshot
      #
      # Raised when a stored snapshot is corrupt or incomplete.
      #
      # @since 0.9.4
      #
      class Corrupt < Error
      end

      #
      # Content-addressed on-disk storage for snapshots.
      #
      # Each snapshot is stored under `snapshots/<sha256>/` together with a
      # `manifest.json` describing every advisory file and its digest.  The
      # store is only an archive: a {Snapshot} always holds its parsed
      # advisories in memory, so deleting stored files can never change the
      # results of a scan that already started.
      #
      # Active snapshots hold a shared lock on their snapshot directory.
      # {#prune} skips directories locked by a running scan unless `force:`
      # is given, which simulates an external cleaner removing everything.
      #
      # @since 0.9.4
      #
      class Store
        # The default snapshot store directory.
        DEFAULT_DIR = ENV.fetch('BUNDLER_AUDIT_SNAPSHOT_DIR') do
          File.join(Dir.tmpdir,'bundler-audit-snapshots')
        end

        # The name of the manifest file.
        MANIFEST = 'manifest.json'

        # The name of the lease file used to detect active scans.
        LEASE = '.lease'

        # The directory containing stored snapshots.
        #
        # @return [String]
        attr_reader :dir

        #
        # Initializes the store.
        #
        # @param [String] dir
        #
        def initialize(dir=nil)
          dir ||= DEFAULT_DIR
          @dir = File.expand_path(dir)
        end

        #
        # The directory containing all stored snapshots.
        #
        # @return [String]
        #
        def snapshots_dir
          File.join(@dir,'snapshots')
        end

        #
        # The storage directory for a snapshot digest.
        #
        # @param [String] digest
        #   A `sha256:...` digest, or the bare hex digest.
        #
        # @return [String]
        #
        def path_for(digest)
          File.join(snapshots_dir,hexdigest(digest))
        end

        #
        # Stores the exact bytes a snapshot was built from.
        #
        # Storing is idempotent: the content digest names the directory, so
        # a snapshot captured from the same data reuses the existing copy.
        #
        # @param [String] digest
        #   The content digest, without the `sha256:` prefix.
        #
        # @param [Array<Array(String, String)>] entries
        #   Relative paths and their exact contents.
        #
        # @return [Entry]
        #
        def materialize(snapshot,entries)
          digest = hexdigest(snapshot)
          final  = path_for(digest)

          unless File.file?(File.join(final,MANIFEST))
            FileUtils.mkdir_p(snapshots_dir)

            staging = Dir.mktmpdir('staging-',@dir)

            begin
              manifest = {
                'format'        => Snapshot::DIGEST_VERSION,
                'digest'        => "sha256:#{digest}",
                'bundler_audit' => Bundler::Audit::VERSION,
                'created_at'    => Time.now.utc.iso8601,
                'files'         => {}
              }

              entries.each do |relative_path,content|
                target = File.join(staging,relative_path)

                FileUtils.mkdir_p(File.dirname(target))
                File.binwrite(target,content)

                manifest['files'][relative_path] = {
                  'sha256' => ::Digest::SHA256.hexdigest(content),
                  'size'   => content.bytesize
                }
              end

              File.write(File.join(staging,MANIFEST),
                         JSON.pretty_generate(manifest))

              begin
                File.rename(staging,final)
              rescue Errno::ENOTEMPTY, Errno::EEXIST
                # Another process stored the same snapshot concurrently.
                FileUtils.remove_entry(staging)
              end
            rescue
              FileUtils.remove_entry(staging) if File.directory?(staging)
              raise
            end
          end

          Entry.open(final)
        end

        #
        #
        # Loads a stored snapshot as a fresh, independent snapshot.
        #
        # The stored advisories are re-parsed from the archived bytes, so a
        # report can be verified after the live database has moved on or the
        # original commit was deleted.
        #
        # @param [String] digest
        #   A `sha256:...` digest, or the bare hex digest.
        #
        # @return [Snapshot]
        #
        # @raise [KeyError]
        #   No snapshot with that digest is stored.
        #
        def load(digest)
          dir      = path_for(digest)
          manifest = JSON.parse(File.read(File.join(dir,MANIFEST)))

          entries = manifest['files'].sort.map do |relative_path,info|
            content = File.binread(File.join(dir,relative_path))

            unless ::Digest::SHA256.hexdigest(content) == info['sha256']
              raise(Corrupt, "snapshot file #{relative_path.inspect} was modified")
            end

            [relative_path,content]
          end

          if entries.map(&:first).sort != manifest['files'].keys.sort
            raise(Corrupt, "snapshot #{digest.inspect} is incomplete")
          end

          Snapshot.build(
            database_path: dir, commit: nil, last_updated_at: nil,
            entries: entries
          ).tap do |snapshot|
            unless snapshot.content_digest == "sha256:#{manifest['digest'].delete_prefix('sha256:')}"
              raise(Corrupt, "snapshot #{digest.inspect} digest mismatch")
            end
          end
        rescue Errno::ENOENT, JSON::ParserError
          raise(KeyError, "no stored snapshot #{digest.inspect}")
        end

        #
        # Lists stored snapshots.
        #
        # @yield [manifest]
        #
        # @return [Array<Hash>, Enumerator]
        #
        def each(&block)
          return enum_for(__method__) unless block_given?

          Dir.glob(File.join(snapshots_dir,'*',MANIFEST)).sort.each do |path|
            yield JSON.parse(File.read(path))
          rescue Errno::ENOENT
            # The snapshot was pruned while listing.
          end
        end

        #
        # Removes stored snapshots.
        #
        # Snapshots leased by a running scan are kept unless `force:` is
        # true.  Running scans are unaffected either way, because they do
        # not read advisories from the store after capture.
        #
        # @param [Boolean] force
        #   Remove snapshots even if a scan is currently using them.
        #
        # @param [Time, nil] older_than
        #   Only remove snapshots created before this time.
        #
        # @return [Array<String>]
        #   The digests that were removed.
        #
        def prune(force: false, older_than: nil)
          removed = []

          Dir.glob(File.join(snapshots_dir,'*')).sort.each do |dir|
            manifest_path = File.join(dir,MANIFEST)
            next unless File.file?(manifest_path)

            manifest = JSON.parse(File.read(manifest_path)) rescue next

            if older_than && (created_at = manifest['created_at'])
              next unless Time.parse(created_at) < older_than
            end

            unless force
              next unless lease_available?(dir)
            end

            FileUtils.rm_rf(dir)
            removed << manifest['digest']
          end

          return removed
        end

        #
        # The total size of all stored snapshots in bytes.
        #
        # @return [Integer]
        #
        def size
          Dir.glob(File.join(snapshots_dir,'*','**','*'))
             .select { |path| File.file?(path) }
             .sum { |path| File.size(path) }
        end

        private

        #
        # Normalizes a digest, or a snapshot's digest, to bare hex.
        #
        # @param [String, Snapshot] digest
        #
        # @return [String]
        #
        def hexdigest(digest)
          digest = digest.content_digest if digest.kind_of?(Snapshot)
          digest.delete_prefix('sha256:')
        end

        #
        # Tests whether no running scan holds a lease on the directory.
        #
        # @param [String] dir
        #
        # @return [Boolean]
        #
        def lease_available?(dir)
          lease_path = File.join(dir,LEASE)
          return true unless File.exist?(lease_path)

          File.open(lease_path,File::RDWR) do |lease|
            if lease.flock(File::LOCK_EX|File::LOCK_NB)
              true
            else
              false
            end
          end
        rescue Errno::ENOENT
          true
        end

        #
        # An open, leased snapshot directory.
        #
        class Entry
          # The snapshot directory.
          #
          # @return [String]
          attr_reader :path

          #
          # Opens a stored snapshot and takes a shared lease on it.
          #
          # @param [String] path
          #
          # @return [Entry]
          #
          def self.open(path)
            lease = nil

            begin
              lease = File.open(File.join(path,LEASE),File::RDWR|File::CREAT,0o600)
              lease.flock(File::LOCK_SH)
            rescue Errno::ENOENT
              lease = nil
            end

            new(path,lease)
          end

          #
          # @param [String] path
          # @param [File, nil] lease
          #
          def initialize(path,lease)
            @path  = path
            @lease = lease
          end

          #
          # Releases the lease.
          #
          # @return [void]
          #
          def close
            @lease.close if @lease && !@lease.closed?
            @lease = nil
          end
        end
      end
    end
  end
end
