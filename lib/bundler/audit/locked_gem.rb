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

require 'bundler'

module Bundler
  module Audit
    #
    # Represents a single locked gem instance, preserving the platform and
    # supply-source identity that distinguishes multiple lockfile entries that
    # share the same name and version (for example the `ruby`, `x86_64-linux`
    # and `arm64-darwin` variants of a gem, or a rubygems, git and path copy of
    # an internally named gem).
    #
    class LockedGem

      # Rubygems.org style public package index.
      RUBYGEMS = :rubygems

      # A gem sourced directly from a git repository.
      GIT = :git

      # A gem sourced from a local path.
      PATH = :path

      #
      # Wraps a lockfile specification, extracting its platform and
      # supply-source identity.
      #
      # @param [Gem::Specification] spec
      #   A specification parsed from a `Gemfile.lock`.
      #
      # @return [LockedGem]
      #
      def self.from_spec(spec)
        source = spec.source

        source_type, source_evidence =
          case source
          when Bundler::Source::Git
            [GIT, {
              'type'     => 'git',
              'uri'      => source.uri.to_s,
              'ref'      => source.ref,
              'revision' => source.revision
            }]
          when Bundler::Source::Path
            [PATH, {
              'type' => 'path',
              'path' => source.path
            }]
          else
            remotes = source.respond_to?(:remotes) ? Array(source.remotes).map(&:to_s) : []

            [RUBYGEMS, {
              'type'    => 'rubygems',
              'remotes' => remotes
            }]
          end

        new(
          name:        spec.name,
          version:     spec.version,
          platform:    normalize_platform(spec.platform),
          source_type: source_type,
          source:      source_evidence,
          spec:        spec
        )
      end

      #
      # Normalizes a lockfile platform (`"ruby"` or a {Gem::Platform}) into the
      # canonical platform string used for identity and matching.
      #
      # @param [String, Gem::Platform] platform
      #
      # @return [String]
      #
      def self.normalize_platform(platform)
        platform.to_s
      end

      # The name of the gem.
      #
      # @return [String]
      attr_reader :name

      # The locked version of the gem.
      #
      # @return [Gem::Version]
      attr_reader :version

      # The locked platform (for example `ruby`, `arm64-darwin`,
      # `x86_64-linux`).
      #
      # @return [String]
      attr_reader :platform

      # The normalized supply source type.
      #
      # @return [Symbol] `:rubygems`, `:git`, or `:path`.
      attr_reader :source_type

      # The evidence describing where the locked instance came from.
      #
      # @return [Hash{String => Object}]
      attr_reader :source

      # The original lockfile specification.
      #
      # @return [Gem::Specification]
      attr_reader :spec

      #
      # Initializes the locked gem.
      #
      # @param [String] name
      # @param [Gem::Version] version
      # @param [String] platform
      # @param [Symbol] source_type
      # @param [Hash] source
      # @param [Gem::Specification] spec
      #
      def initialize(name:, version:, platform:, source_type:, source:, spec: nil)
        @name        = name
        @version     = version
        @platform    = platform
        @source_type = source_type
        @source      = source
        @spec        = spec
      end

      #
      # Specifies whether the instance was published to a public package
      # index (rubygems source).
      #
      # @return [Boolean]
      #
      def rubygems?
        @source_type == RUBYGEMS
      end

      #
      # Specifies whether the instance was sourced from a git repository.
      #
      # @return [Boolean]
      #
      def git?
        @source_type == GIT
      end

      #
      # Specifies whether the instance was sourced from a local path.
      #
      # @return [Boolean]
      #
      def path?
        @source_type == PATH
      end

      #
      # Specifies whether the instance comes from a source whose contents
      # cannot be proven identical to the published public package of the same
      # name and version.
      #
      # @return [Boolean]
      #
      def unverifiable_source?
        git? || path?
      end

      #
      # A stable identity key distinguishing the platform/source variants of
      # the same named gem.
      #
      # @return [Array]
      #
      def identity
        [@name, @version.to_s, @platform, @source_type, source_location]
      end

      #
      # @return [Boolean]
      #
      def ==(other)
        other.kind_of?(LockedGem) && identity == other.identity
      end

      alias eql? ==

      #
      # @return [Integer]
      #
      def hash
        identity.hash
      end

      #
      # Converts the locked gem identity and evidence into a Hash suitable for
      # machine-readable reports.
      #
      # @return [Hash{Symbol => Object}]
      #
      def to_h
        {
          name:        @name,
          version:     @version,
          platform:    @platform,
          source_type: @source_type,
          source:      @source
        }
      end

      #
      # @return [String]
      #
      def inspect
        "#<#{self.class}: #{@name} #{@version} #{@platform} (#{@source_type})>"
      end

      private

      #
      # The source-specific location used to distinguish instances.
      #
      # @return [String, nil]
      #
      def source_location
        case @source_type
        when GIT  then @source['uri'].to_s
        when PATH then @source['path'].to_s
        else           Array(@source['remotes']).join(',')
        end
      end
    end
  end
end
