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

require 'bundler/audit/advisory'
require 'bundler/audit/snapshot'
require 'bundler/audit/snapshot/store'

require 'digest'
require 'open3'
require 'rubygems/package'
require 'stringio'
require 'time'
require 'yaml'

module Bundler
  module Audit
    #
    # Represents the directory of advisories, grouped by gem name
    # and CVE number.
    #
    class Database

      class DownloadFailed < RuntimeError
      end

      class UpdateFailed < RuntimeError
      end

      # Git URL of the ruby-advisory-db.
      URL = 'https://github.com/rubysec/ruby-advisory-db.git'

      # Path to the user's copy of the ruby-advisory-db.
      USER_PATH = File.expand_path(File.join(Gem.user_home,'.local','share','ruby-advisory-db'))

      # Default path to the ruby-advisory-db.
      #
      # @since 0.8.0
      DEFAULT_PATH = ENV.fetch('BUNDLER_AUDIT_DB',USER_PATH)

      # Name of the marker file written into `.git/` for an in-progress update.
      UPDATE_MARKER = 'bundler-audit-update'

      # The path to the advisory database.
      #
      # @return [String]
      attr_reader :path

      # Optional on-disk snapshot store.
      #
      # @return [Snapshot::Store, nil]
      attr_reader :store

      #
      # Initializes the Advisory Database.
      #
      # @param [String] path
      #   The path to the advisory database.
      #
      # @raise [ArgumentError]
      #   The path was not a directory.
      #
      def initialize(path=self.class.path,store: nil)
        unless File.directory?(path)
          raise(ArgumentError,"#{path.dump} is not a directory")
        end

        @path  = path
        @store = store
      end

      #
      # The default path for the database.
      #
      # @return [String]
      #   The path to the database directory.
      #
      def self.path
        DEFAULT_PATH
      end

      #
      # Tests whether the database exists.
      #
      # @param [String] path
      #   The given path of the database to check.
      #
      # @return [Boolean]
      #
      # @since 0.8.0
      #
      def self.exists?(path=DEFAULT_PATH)
        File.directory?(path) && !(Dir.entries(path) - %w[. ..]).empty?
      end

      #
      # Downloads the ruby-advisory-db.
      #
      # @param [Hash] options
      #   Additional options.
      #
      # @option options [String] :path (DEFAULT_PATH)
      #   The destination path for the new ruby-advisory-db.
      #
      # @option options [Boolean] :quiet
      #   Specify whether `git` should be `--quiet`.
      #
      # @return [Database]
      #   The newly downloaded database.
      #
      # @raise [DownloadFailed]
      #   Indicates that the download failed.
      #
      # @note
      #   Requires network access.
      #
      # @since 0.8.0
      #
      def self.download(options={})
        unless (options.keys - [:path, :quiet]).empty?
          raise(ArgumentError,"Invalid option(s)")
        end

        path = options.fetch(:path,DEFAULT_PATH)

        command = %w[git clone]
        command << '--quiet' if options[:quiet]
        command << URL << path

        unless system(*command)
          raise(DownloadFailed,"failed to download #{URL} to #{path.inspect}")
        end

        return new(path)
      end

      #
      # Updates the ruby-advisory-db.
      #
      # @param [Hash] options
      #   Additional options.
      #
      # @option options [Boolean] :quiet
      #   Specify whether `git` should be `--quiet`.
      #
      # @return [Boolean]
      #   Specifies whether the update was successful.
      #
      # @raise [ArgumentError]
      #   Invalid options were given.
      #
      # @note
      #   Requires network access.
      #
      # @since 0.3.0
      #
      # @deprecated Use {#update!} instead.
      #
      def self.update!(options={})
        raise "Invalid option(s)" unless (options.keys - [:quiet]).empty?

        if File.directory?(DEFAULT_PATH)
          begin
            new(DEFAULT_PATH).update!(options)
          rescue UpdateFailed then false
          end
        else
          begin
            download(options.merge(path: DEFAULT_PATH))
          rescue DownloadFailed then false
          end
        end
      end

      #
      # Determines if the database is a git repository.
      #
      # @return [Boolean]
      #
      # @since 0.8.0
      #
      def git?
        File.directory?(File.join(@path,'.git'))
      end

      #
      # Whether the working tree contains uncommitted changes.
      #
      # An update marker is stored under `.git/`, so it does not count as
      # a change to the working tree.
      #
      # @return [Boolean]
      #
      # @since 0.9.4
      #
      def dirty?
        return false unless git?

        output,status = Open3.capture2(
          'git','-C',@path,'status','--porcelain=v1','--untracked-files=normal'
        )

        raise(Snapshot::Unavailable,"could not inspect #{@path.inspect}") unless status.success?

        !output.strip.empty?
      end

      #
      # Captures an immutable snapshot of the database as it exists now.
      #
      # For a git repository the snapshot is read from the current `HEAD`
      # commit via `git archive`, so concurrent changes to the working tree
      # or an in-progress update cannot affect it.  For a plain directory
      # every advisory file is read once and re-checked for concurrent
      # modification.
      #
      # If the working tree has uncommitted changes, a
      # {Snapshot::DirtyWorktree} exception is raised rather than silently
      # scanning stale committed data.  The exception is only suppressed
      # when an update is known to be running or to have been interrupted;
      # in those cases the old `HEAD` is still scanned and `#update_state`
      # records why the working tree was ignored.
      #
      # @param [Boolean] ignore_dirty
      #   Explicitly scan committed data even if the working tree is dirty.
      #
      # @return [Snapshot]
      #
      # @raise [Snapshot::DirtyWorktree]
      #   The git working tree contains uncommitted changes.
      #
      # @raise [Snapshot::Unavailable]
      #   The database version or contents could not be read.
      #
      # @since 0.9.4
      #
      def snapshot(ignore_dirty: false)
        if git?
          # Resolve the commit before inspecting the worktree: if an update
          # advances HEAD between the two steps, the worktree check would
          # otherwise describe a different version than the one returned.
          commit = current_commit

          snapshot_from_commit(commit, update_state: update_state,
                                       ignore_dirty: ignore_dirty)
        else
          snapshot_from_directory
        end
      end

      #
      # Re-captures a snapshot from an exact git commit.
      #
      # This is used to verify a report's `database.commit` and
      # `database.digest` after the fact.
      #
      # @param [String] commit
      #
      # @return [Snapshot]
      #
      # @raise [Snapshot::Unavailable]
      #   The commit does not exist locally.
      #
      # @since 0.9.4
      #
      def snapshot_at(commit)
        unless git?
          raise(Snapshot::Unavailable,"#{@path.inspect} is not a git repository")
        end

        snapshot_from_commit(commit, update_state: update_state,
                                     ignore_dirty: true)
      end

      #
      # Re-loads a snapshot by its exact content digest.
      #
      # This needs a {Snapshot::Store} to be configured, and either the
      # stored snapshot itself or the advisory files with that exact
      # content.
      #
      # @param [String] digest
      #   A `sha256:...` digest from a report's `database.digest`.
      #
      # @return [Snapshot]
      #
      # @raise [Snapshot::Unavailable]
      #   The digest cannot be reproduced from the store or database.
      #
      # @since 0.9.4
      #
      def snapshot_with_digest(digest)
        if @store
          begin
            return @store.load(digest)
          rescue KeyError
            # Fall back to reading the database below.
          end
        end

        # Without an archive the live database must still reproduce the
        # exact contents, including any set of clean but uncommitted files
        # that a dirty scan would have read.
        candidate = snapshot(ignore_dirty: true)

        unless candidate.content_digest == digest
          raise(Snapshot::Unavailable,
                "database #{@path.inspect} does not contain #{digest.inspect}")
        end

        candidate
      end

      #
      # Updates the ruby-advisory-db.
      #
      # The update is a plain `git pull` on a clean working tree, so it
      # either advances `HEAD` completely or leaves the old commit untouched.
      # A marker file under `.git/` records
      # that an update is in progress; if the process dies mid-update the
      # marker is left behind, later updates roll the working tree back to
      # the recorded commit before retrying, and scans report
      # `update_state: :interrupted` while still using the old commit.
      #
      # @param [Hash] options
      #   Additional options.
      #
      # @option options [Boolean] :quiet
      #   Specify whether `git` should be `--quiet`.
      #
      # @option options [String] :branch
      #   The remote branch to update from (`master` by default).
      #
      # @return [true, nil]
      #   * `true` - the ruby-advisory-db git repository was successfully
      #     updated.
      #   * `nil` - the ruby-advisory-db is not a git repository or the `git`
      #     command is not installed.
      #
      # @raise [UpdateFailed]
      #   Could not update the ruby-advisory-db git repository.
      #
      # @since 0.8.0
      #
      def update!(options={})
        unless (options.keys - [:quiet, :branch]).empty?
          raise "Invalid option(s)"
        end

        return nil unless git?

        recover_interrupted_update!

        if dirty?
          raise(UpdateFailed,
                "cannot update #{@path.inspect}: the working tree has " \
                "uncommitted changes; commit or discard them first")
        end

        old_commit = current_commit
        marker     = nil

        begin
          marker = begin
                     File.open(update_marker_path,
                               File::WRONLY|File::CREAT|File::EXCL,0o600)
                   rescue Errno::EEXIST
                     raise(UpdateFailed,
                           "another update of #{@path.inspect} is already " \
                           "in progress") if update_state == :running

                     # A previous update died without cleaning up; recover
                     # from it and retry once.
                     recover_interrupted_update!
                     File.open(update_marker_path,
                               File::WRONLY|File::CREAT|File::EXCL,0o600)
                   end

          marker.write("from=#{old_commit}\npid=#{Process.pid}\n" \
                       "started_at=#{Time.now.utc.iso8601}\n")
          marker.flush

          command = %w[git pull]
          command << '--quiet' if options[:quiet]
          command << 'origin' << (options[:branch] || 'master')

          # `git pull` only runs on a clean working tree, and a snapshot is
          # always read from the resulting commit.  If the pull fails, git
          # leaves the old commit in place; a later update cleans up any
          # marker left by an interrupted pull.
          unless system(*command, chdir: @path)
            raise(UpdateFailed,"failed to update #{@path.inspect}")
          end

          return true
        ensure
          if marker
            marker.close
            File.unlink(update_marker_path) if File.exist?(update_marker_path)
          end
        end
      end

      #
      # The last commit ID of the repository.
      #
      # @return [String, nil]
      #   The commit hash or `nil` if the database is not a git repository.
      #
      # @since 0.9.0
      #
      def commit_id
        current_commit if git?
      end

      #
      # Determines the time when the database was last updated.
      #
      # @return [Time]
      #
      # @since 0.8.0
      #
      def last_updated_at
        if git?
          output,status = Open3.capture2(
            'git','-C',@path,'log','-1','--date=iso8601','--format=%cd',current_commit
          )

          raise(Snapshot::Unavailable,"could not read #{@path.inspect}") unless status.success?

          Time.parse(output)
        else
          File.mtime(@path)
        end
      end

      #
      # The state of any update for the database.
      #
      # @return [:none, :running, :interrupted]
      #
      # @since 0.9.4
      #
      def update_state
        return :none unless git?

        marker = update_marker_path
        return :none unless File.exist?(marker)

        pid = File.read(marker)[/^pid=(\d+)$/,1].to_i

        if pid > 0 && process_alive?(pid)
          :running
        else
          :interrupted
        end
      rescue Errno::ENOENT
        :none
      end

      #
      # Enumerates over every advisory in the database.
      #
      # @yield [advisory]
      #   If a block is given, it will be passed each advisory.
      #
      # @yieldparam [Advisory] advisory
      #   An advisory from the database.
      #
      # @return [Enumerator]
      #   If no block is given, an Enumerator will be returned.
      #
      def advisories(&block)
        return enum_for(__method__) unless block_given?

        snapshot.advisories.each(&block)
      end

      #
      # Enumerates over advisories for the given gem.
      #
      # @param [String] name
      #   The gem name to lookup.
      #
      # @yield [advisory]
      #   If a block is given, each advisory for the given gem will be yielded.
      #
      # @yieldparam [Advisory] advisory
      #   An advisory for the given gem.
      #
      # @return [Enumerator]
      #   If no block is given, an Enumerator will be returned.
      #
      def advisories_for(name,&block)
        return enum_for(__method__,name) unless block_given?

        snapshot.advisories_for(name).each(&block)
      end

      #
      # Verifies whether the gem is effected by any advisories.
      #
      # @param [Gem::Specification] gem
      #   The gem to verify.
      #
      # @yield [advisory]
      #   If a block is given, it will be passed advisories that effect
      #   the gem.
      #
      # @yieldparam [Advisory] advisory
      #   An advisory that effects the specific version of the gem.
      #
      # @return [Enumerator]
      #   If no block is given, an Enumerator will be returned.
      #
      def check_gem(gem,&block)
        return enum_for(__method__,gem) unless block_given?

        snapshot.check_gem(gem,&block)
      end

      #
      # The number of advisories within the database.
      #
      # @return [Integer]
      #   The number of advisories.
      #
      def size
        snapshot.size
      end

      #
      # Converts the database to a String.
      #
      # @return [String]
      #   The path to the database.
      #
      def to_s
        @path
      end

      #
      # Inspects the database.
      #
      # @return [String]
      #   The inspected database.
      #
      def inspect
        "#<#{self.class}:#{self}>"
      end

      protected

      #
      # The current `HEAD` commit.
      #
      # @return [String]
      #
      def current_commit
        rev_parse('HEAD')
      end

      #
      # Resolves a git revision to a commit ID.
      #
      # @param [String] revision
      #
      # @return [String]
      #
      def rev_parse(revision)
        output,status = Open3.capture2(
          'git','-C',@path,'rev-parse','--verify',"#{revision}^{commit}"
        )

        unless status.success?
          raise(Snapshot::Unavailable,
                "could not resolve #{revision.inspect} in #{@path.inspect}")
        end

        output.chomp
      end

      #
      # The path to the update marker.
      #
      # @return [String]
      #
      def update_marker_path
        File.join(@path,'.git',UPDATE_MARKER)
      end

      #
      # Removes a marker left behind by an interrupted update and rolls
      # back any partially applied working-tree changes.
      #
      def recover_interrupted_update!
        marker = update_marker_path
        return unless File.exist?(marker)

        contents = File.read(marker)
        pid      = contents[/^pid=(\d+)$/,1].to_i

        if pid > 0 && process_alive?(pid)
          raise(UpdateFailed,
                "another update of #{@path.inspect} is currently running " \
                "(pid #{pid})")
        end

        from = contents[/^from=(.+)$/,1]

        # A dead update process may have left the working tree partially
        # updated.  Only roll back when HEAD moved away from the recorded
        # starting commit; if HEAD is unchanged, dirty files are the user's
        # own edits and must not be destroyed.
        if from && current_commit != from && dirty?
          system('git','reset','--hard',from, chdir: @path)
        end

        File.unlink(marker)
      rescue Errno::ENOENT
        # Another process cleaned up the marker concurrently.
      end

      #
      # Determines whether a process is still running.
      #
      # @param [Integer] pid
      #
      # @return [Boolean]
      #
      def process_alive?(pid)
        Process.kill(0,pid)
        true
      rescue Errno::ESRCH
        false
      rescue Errno::EPERM
        true
      end

      #
      # Captures a snapshot of a plain (non-git) database directory.
      #
      # Advisory files are read once and their sizes/mtimes re-checked
      # afterwards; if anything changed during the read, the snapshot is
      # captured again so that the digest matches a single consistent read.
      #
      # @return [Snapshot]
      #
      # @raise [Snapshot::Unavailable]
      #   The files kept changing while being read.
      #
      def snapshot_from_directory
        attempts = 0

        loop do
          attempts += 1

          begin
            entries = advisory_paths.map do |absolute_path|
              relative_path = relative(absolute_path)
              before        = File.stat(absolute_path)
              content       = File.binread(absolute_path)

              # Read once more and compare, so a file rewritten within the
              # same mtime tick cannot produce a torn snapshot.
              unless content == File.binread(absolute_path)
                raise(IOError,"changed while reading")
              end

              after = File.stat(absolute_path)

              unless before.size == after.size && before.mtime == after.mtime
                raise(IOError,"changed while reading")
              end

              [relative_path, content]
            end

            return build_snapshot(commit: nil, last_updated_at: File.mtime(@path),
                                  entries: entries, update_state: :none,
                                  dirty: false)
          rescue IOError
            if attempts >= 3
              raise(Snapshot::Unavailable,
                    "advisory database #{@path.inspect} changed while being read")
            end
            sleep(0.05)
          end
        end
      rescue Errno::ENOENT
        raise(Snapshot::Unavailable,
              "advisory database #{@path.inspect} changed while being read")
      end

      #
      # Captures a snapshot from an exact git commit.
      #
      # @param [String] commit
      #
      # @param [Symbol] update_state
      #
      # @param [Boolean] ignore_dirty
      #
      # @return [Snapshot]
      #
      def snapshot_from_commit(commit,update_state:,ignore_dirty:)
        dirty = dirty?

        if dirty && update_state == :none && !ignore_dirty
          raise(Snapshot::DirtyWorktree,
                "the working tree of #{@path.inspect} has uncommitted changes; " \
                "a consistent scan cannot be tied to a single database version. " \
                "Commit or discard the changes, or rerun with ignore_dirty: true")
        end

        entries = archive_entries(commit)
        timestamp = commit_timestamp(commit)

        build_snapshot(commit: commit, last_updated_at: timestamp,
                       entries: entries, update_state: update_state,
                       dirty: dirty)
      end

      #
      # Builds a {Snapshot} from relative paths and raw file contents.
      #
      # @param [String, nil] commit
      # @param [Time, nil] last_updated_at
      # @param [Array<Array(String, String)>] entries
      # @param [Symbol] update_state
      # @param [Boolean] dirty
      #
      # @return [Snapshot]
      #
      def build_snapshot(commit:,last_updated_at:,entries:,update_state:,dirty:)
        snapshot = Snapshot.build(
          database_path: @path, commit: commit,
          last_updated_at: last_updated_at, entries: entries,
          update_state: update_state, dirty: dirty
        )

        return snapshot unless @store

        # The store is an archive; the returned snapshot already holds its
        # advisories in memory.  The archive lease is released immediately
        # so it does not outlive the capture.
        @store.materialize(snapshot,entries).close

        snapshot
      end

      #
      # Reads all advisory files from a git commit without touching the
      # working tree.
      #
      # @param [String] commit
      #
      # @return [Array<Array(String, String)>]
      #
      def archive_entries(commit)
        command = ['git','-C',@path,'archive','--format=tar',commit,'--','gems']
        output, error, status = Open3.capture3(*command)

        unless status.success?
          raise(Snapshot::Unavailable,
                "could not read commit #{commit.inspect} of #{@path.inspect}: #{error.strip}")
        end

        entries = []

        Gem::Package::TarReader.new(StringIO.new(output)) do |tar|
          tar.each do |entry|
            next unless entry.file?

            relative_path = entry.full_name

            if relative_path.start_with?('gems/') &&
               relative_path.end_with?('.yml')
              entries << [relative_path, entry.read]
            end
          end
        end

        entries
      end

      #
      # The timestamp of a commit.
      #
      # @param [String] commit
      #
      # @return [Time]
      #
      def commit_timestamp(commit)
        output,status = Open3.capture2(
          'git','-C',@path,'log','-1','--date=iso8601','--format=%cd',commit
        )

        raise(Snapshot::Unavailable,"could not read #{@path.inspect}") unless status.success?

        Time.parse(output)
      end

      #
      # All advisory file paths in a plain database directory.
      #
      # @return [Array<String>]
      #
      def advisory_paths
        Dir.glob(File.join(@path,'gems','*','*.yml')).sort
      end

      #
      # The path relative to the database root.
      #
      # @param [String] absolute_path
      #
      # @return [String]
      #
      def relative(absolute_path)
        absolute_path.delete_prefix(@path + File::SEPARATOR)
      end

    end
  end
end
