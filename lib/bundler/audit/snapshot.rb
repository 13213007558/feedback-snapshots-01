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

require 'digest'
require 'time'

module Bundler
  module Audit
    #
    # An immutable view of the advisory database at one exact version.
    #
    # A snapshot is captured once, before a scan produces any result, and
    # contains every advisory that the scan may read.  It therefore cannot
    # observe a database update half-way through a scan: all results come
    # from the same commit (or, for a plain directory database, from the
    # same set of file contents).
    #
    # The {#commit} and {#digest} values in {#to_h} are stored in reports so
    # that the exact data behind a report can be inspected later.
    #
    # @since 0.9.4
    #
    class Snapshot
      # Raised when a snapshot cannot be captured.
      class Error < RuntimeError
      end

      # Raised when the database working tree contains uncommitted changes,
      # which would make a commit-based snapshot ambiguous.
      class DirtyWorktree < Error
      end

      # Raised when the database version cannot be read.
      class Unavailable < Error
      end

      # The format version of the content digest.
      DIGEST_VERSION = 1

      #
      # Builds a snapshot from relative paths and raw file contents.
      #
      # @param [String] database_path
      # @param [String, nil] commit
      # @param [Time, nil] last_updated_at
      # @param [Array<Array(String, String)>] entries
      #   Pairs of database-relative paths and exact file contents.
      # @param [Symbol] update_state
      # @param [Boolean] dirty
      #
      # @return [Snapshot]
      #
      def self.build(database_path:,commit:,last_updated_at:,entries:,
                     update_state: :none,dirty: false)
        advisories = entries.map do |relative_path,content|
          Advisory.parse(content.dup.force_encoding(Encoding::UTF_8),
                         File.join(database_path,relative_path))
        end

        digest = ::Digest::SHA256.new

        digest << "bundler-audit-snapshot-v#{DIGEST_VERSION}\n"
        entries.sort_by(&:first).each do |relative_path,content|
          bytes = content.b
          digest << relative_path << "\0" << bytes.bytesize.to_s << "\0" <<
                    bytes << "\0"
        end

        new(database_path: database_path, commit: commit,
            last_updated_at: last_updated_at,
            digest: digest.hexdigest, advisories: advisories,
            update_state: update_state, dirty: dirty,
            files: entries.map(&:first))
      end

      # The path of the advisory database.
      #
      # @return [String]
      attr_reader :database_path

      # The git commit the snapshot was read from, or `nil` for a plain
      # directory database.
      #
      # @return [String, nil]
      attr_reader :commit

      # The time the database version was last updated.
      #
      # @return [Time, nil]
      attr_reader :last_updated_at

      # The SHA256 hex digest over the exact advisory files read.
      #
      # @return [String]
      attr_reader :digest

      # The state of any update at snapshot time.
      #
      # @return [:none, :running, :interrupted]
      attr_reader :update_state

      # Whether the snapshot was explicitly taken from a dirty worktree.
      #
      # @return [Boolean]
      attr_reader :dirty

      # All advisories contained in the snapshot, sorted by path.
      #
      # @return [Array<Advisory>]
      attr_reader :advisories

      # The database-relative advisory files the snapshot was built from.
      #
      # @return [Array<String>]
      attr_reader :files

      #
      # Creates a snapshot value object.
      #
      # This is normally called by {Database#snapshot}.
      #
      # @param [String] database_path
      # @param [String, nil] commit
      # @param [Time, nil] last_updated_at
      # @param [String] digest
      # @param [Array<Advisory>] advisories
      # @param [:none, :running, :interrupted] update_state
      # @param [Boolean] dirty
      #
      def initialize(database_path:, commit:, last_updated_at:, digest:,
                     advisories:, update_state: :none, dirty: false,
                     files: nil)
        @database_path   = database_path
        @commit          = commit
        @last_updated_at = last_updated_at
        @digest          = digest
        @update_state    = update_state
        @dirty           = dirty
        @advisories      = advisories.sort_by(&:path).freeze
        @files           = (files || @advisories.map(&:path)).freeze

        @by_id  = @advisories.each_with_object({}) { |a,h| h[a.id] = a }.freeze
        @by_gem = @advisories.group_by { |a| File.basename(File.dirname(a.path)) }.freeze
      end

      #
      # The content digest including its algorithm.
      #
      # @return [String]
      #
      def content_digest
        "sha256:#{@digest}"
      end

      #
      # Whether the snapshot was read from a git repository.
      #
      # @return [Boolean]
      #
      def git?
        !@commit.nil?
      end

      #
      # The number of advisories in the snapshot.
      #
      # @return [Integer]
      #
      def size
        @advisories.size
      end

      alias length size

      #
      # Looks up an advisory by ID.
      #
      # @param [String] id
      #
      # @return [Advisory, nil]
      #
      def [](id)
        @by_id[id]
      end

      #
      # All advisories for the given gem name.
      #
      # @param [String] name
      #
      # @return [Array<Advisory>]
      #
      def advisories_for(name)
        @by_gem.fetch(name, [])
      end

      #
      # Yields advisories affecting the given gem version.
      #
      # @param [Gem::Specification] gem
      #
      # @yield [advisory]
      #
      # @return [Enumerator]
      #
      def check_gem(gem)
        return enum_for(__method__,gem) unless block_given?

        advisories_for(gem.name).each do |advisory|
          yield advisory if advisory.vulnerable?(gem.version)
        end
      end

      #
      # The report-friendly description of this snapshot.
      #
      # @return [Hash{Symbol => Object}]
      #
      def to_h
        {
          source:         git? ? :git : :directory,
          commit:         @commit,
          digest:         content_digest,
          advisories:     size,
          last_updated_at: @last_updated_at && @last_updated_at.iso8601,
          update_state:   @update_state,
          dirty:          @dirty
        }
      end

      #
      # Compares snapshots by the data they actually contain.
      #
      # @param [Object] other
      #
      # @return [Boolean]
      #
      def ==(other)
        other.kind_of?(Snapshot) &&
          @commit == other.commit &&
          @digest == other.digest
      end

      #
      # @return [String]
      #
      def inspect
        if git?
          "#<#{self.class}:#{@commit} #{content_digest}>"
        else
          "#<#{self.class}:#{@database_path} #{content_digest}>"
        end
      end

    end
  end
end
