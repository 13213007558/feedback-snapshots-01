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

      #
      # Indicates that an advisory in the database could not be trusted.
      #
      # Wraps the underlying {Advisory::Invalid} with the offending path, so
      # that callers can report which parts of the database were skipped.
      #
      class AdvisoryError < RuntimeError

        # The path of the advisory which could not be loaded.
        #
        # @return [String]
        attr_reader :advisory_path

        #
        # Initializes the advisory error.
        #
        # @param [String] advisory_path
        #
        # @param [Exception, nil] cause
        #
        # @param [Symbol] code
        #   Either `:invalid_advisory` or `:path_escape`.
        #
        def initialize(advisory_path,cause=nil,code: :invalid_advisory)
          @advisory_path = advisory_path
          @code          = code

          message = "could not load advisory #{advisory_path.dump}"
          message << ": #{cause.message}" if cause

          super(message)
        end

        #
        # The classification of the failure.
        #
        # @return [Symbol]
        attr_reader :code
      end

      # Git URL of the ruby-advisory-db.
      URL = 'https://github.com/rubysec/ruby-advisory-db.git'

      # Path to the user's copy of the ruby-advisory-db.
      USER_PATH = File.expand_path(File.join(Gem.user_home,'.local','share','ruby-advisory-db'))

      # Default path to the ruby-advisory-db.
      #
      # @since 0.8.0
      DEFAULT_PATH = ENV.fetch('BUNDLER_AUDIT_DB',USER_PATH)

      # The path to the advisory database.
      #
      # @return [String]
      attr_reader :path

      #
      # Initializes the Advisory Database.
      #
      # @param [String] path
      #   The path to the advisory database.
      #
      # @raise [ArgumentError]
      #   The path was not a directory.
      #
      def initialize(path=self.class.path)
        unless File.directory?(path)
          raise(ArgumentError,"#{path.dump} is not a directory")
        end

        @path = path
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
      # Updates the ruby-advisory-db.
      #
      # @param [Hash] options
      #   Additional options.
      #
      # @option options [Boolean] :quiet
      #   Specify whether `git` should be `--quiet`.
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
        if git?
          Dir.chdir(@path) do
            command = %w[git pull]
            command << '--quiet' if options[:quiet]
            command << 'origin' << 'master'

            unless system(*command)
              raise(UpdateFailed,"failed to update #{@path.inspect}")
            end

            return true
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
        if git?
          Dir.chdir(@path) do
            `git rev-parse HEAD`.chomp
          end
        end
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
          Dir.chdir(@path) do
            Time.parse(`git log --date=iso8601 --pretty="%cd" -1`)
          end
        else
          File.mtime(@path)
        end
      end

      #
      # Enumerates over every advisory in the database.
      #
      # Advisories which fail validation are not silently skipped: they are
      # reported via the `:on_error` callback, and the enumeration continues
      # so that other trustworthy advisories are still reported.
      #
      # @yield [advisory]
      #   If a block is given, it will be passed each advisory.
      #
      # @yieldparam [Advisory] advisory
      #   An advisory from the database.
      #
      # @option options [Proc] :on_error
      #   Callback invoked with each {AdvisoryError} instead of aborting the
      #   enumeration.
      #
      # @return [Enumerator]
      #   If no block is given, an Enumerator will be returned.
      #
      def advisories(options={},&block)
        return enum_for(__method__,options) unless block

        each_advisory_path do |path|
          advisory = load_advisory(path,options[:on_error])
          yield advisory if advisory
        end
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
      # @option options [Proc] :on_error
      #   Callback invoked with each {AdvisoryError} instead of aborting the
      #   enumeration.
      #
      # @return [Enumerator]
      #   If no block is given, an Enumerator will be returned.
      #
      def advisories_for(name,options={},&block)
        return enum_for(__method__,name,options) unless block

        each_advisory_path_for(name) do |path|
          advisory = load_advisory(path,options[:on_error])
          yield advisory if advisory
        end
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
      # @option options [Proc] :on_error
      #   Callback invoked with each {AdvisoryError} instead of aborting the
      #   enumeration.
      #
      # @return [Enumerator]
      #   If no block is given, an Enumerator will be returned.
      #
      def check_gem(gem,options={})
        return enum_for(__method__,gem,options) unless block_given?

        advisories_for(gem.name,options) do |advisory|
          if advisory.vulnerable?(gem.version)
            yield advisory
          end
        end
      end

      #
      # The number of advisories within the database.
      #
      # @return [Integer]
      #   The number of advisories.
      #
      def size
        each_advisory_path.count
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
      # Loads a single advisory, converting validation failures into
      # {AdvisoryError}s.
      #
      # @param [String] path
      #
      # @param [Proc, nil] on_error
      #   Optional callback which receives the {AdvisoryError}. When absent,
      #   the error is raised so callers cannot mistake a partially parsed
      #   database for a clean one.
      #
      # @return [Advisory, nil]
      #
      def load_advisory(path,on_error=nil)
        unless contained_path?(path)
          error = AdvisoryError.new(path,code: :path_escape)
          raise(error) unless on_error

          on_error.call(error)
          return nil
        end

        Advisory.load(path)
      rescue Advisory::Invalid => error
        wrapped = AdvisoryError.new(path,error)
        raise(wrapped,cause: error) unless on_error

        on_error.call(wrapped)
        nil
      end

      #
      # Determines whether a path stays within the database directory.
      #
      # Enumeration normally yields paths from `Dir.glob`, which cannot
      # escape the database. This check guards callers, subclasses, and
      # crafted gem names (which may contain `..` separators) against
      # reading a file outside of the selected database.
      #
      # @param [String] path
      #
      # @return [Boolean]
      #
      def contained_path?(path)
        database_root = File.realpath(@path)
        real_path     = File.realpath(path)

        real_path == database_root ||
          real_path.start_with?(database_root + File::SEPARATOR)
      rescue SystemCallError
        false
      end

      #
      # Enumerates over every advisory path in the database.
      #
      # @yield [path]
      #   The given block will be passed each advisory path.
      #
      # @yieldparam [String] path
      #   A path to an advisory `.yml` file.
      #
      def each_advisory_path(&block)
        Dir.glob(File.join(@path,'gems','*','*.yml'),&block)
      end

      #
      # Enumerates over the advisories for the given gem.
      #
      # @param [String] name
      #   The gem of the gem.
      #
      # @yield [path]
      #   The given block will be passed each advisory path.
      #
      # @yieldparam [String] path
      #   A path to an advisory `.yml` file.
      #
      def each_advisory_path_for(name,&block)
        unless valid_gem_name?(name)
          raise(ArgumentError,"invalid gem name #{name.inspect}")
        end

        Dir.glob(File.join(@path,'gems',name,'*.yml'),&block)
      end

      #
      # Determines whether a gem name can be used as a single path segment.
      #
      # Gem names come from `Gemfile.lock` files, which are attacker
      # controlled input when auditing untrusted projects. Restricting them
      # to a single, non-traversing path segment prevents a name such as
      # `"../../../etc"` from escaping the selected advisory database.
      #
      # @param [String] name
      #
      # @return [Boolean]
      #
      def valid_gem_name?(name)
        return false unless name.kind_of?(String)
        return false if name.empty? || name == '.' || name == '..'
        return false if name.include?('/')
        return false if name.include?('\\')
        return false if name.include?(File::SEPARATOR)
        return false if File::ALT_SEPARATOR && name.include?(File::ALT_SEPARATOR)

        true
      end

    end
  end
end
