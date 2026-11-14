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

require 'bundler/audit/locked_gem'

module Bundler
  module Audit
    #
    # A focused `Gemfile.lock` reader that preserves every locked gem instance,
    # including variants that share the same name and version but differ by
    # platform or supply source.
    #
    # Bundler's own {Bundler::LockfileParser} indexes specifications by their
    # `full_name` (name, version and platform), so a rubygems, git and path copy
    # of an identically named and versioned gem collapse into a single entry and
    # their distinct sources are lost. This reader walks the raw lockfile
    # sections instead, retaining the platform and source evidence for each
    # locked instance.
    #
    class Lockfile

      # Matches a top-level lockfile section header (for example `GIT`, `GEM`,
      # `PATH`, `PLATFORMS`).
      SECTION = /\A([A-Z][A-Z ]*)\s*\z/

      # Matches a gem specification line nested under a section's `specs:`.
      SPEC_LINE = /\A\s{4}([^\s(]+)\s+\(([^-)]+)(?:-(.+?))?\)\s*\z/

      # Matches a section option line (for example `remote: ...`,
      # `revision: ...`, `ref: ...`).
      OPTION_LINE = /\A\s{2}([a-z]+):\s*(.*)\s*\z/

      # The locked gem instances, in lockfile order.
      #
      # @return [Array<LockedGem>]
      attr_reader :gems

      # The platforms declared by the lockfile's `PLATFORMS` section.
      #
      # @return [Array<String>]
      attr_reader :platforms

      #
      # Parses the contents of a `Gemfile.lock`.
      #
      # @param [String] contents
      #
      # @return [Lockfile]
      #
      def self.parse(contents)
        new(contents)
      end

      #
      # @param [String] contents
      #
      def initialize(contents)
        @gems      = []
        @platforms = []

        parse(contents)
      end

      private

      #
      # Walks the lockfile line by line, tracking the active section and source
      # block so each specification is recorded with its platform and the
      # evidence of its supply source.
      #
      def parse(contents)
        section       = nil
        source_type    = nil
        source_evidence = nil
        in_specs       = false

        contents.each_line do |line|
          if (match = line.match(SECTION))
            section = match[1]
            in_specs = false

            case section
            when 'GIT'
              source_type = LockedGem::GIT
              source_evidence = { 'type' => 'git' }
            when 'PATH'
              source_type = LockedGem::PATH
              source_evidence = { 'type' => 'path' }
            when 'GEM'
              source_type = LockedGem::RUBYGEMS
              source_evidence = { 'type' => 'rubygems', 'remotes' => [] }
            else
              source_type = nil
              source_evidence = nil
            end

            next
          end

          if section == 'PLATFORMS' && line =~ /\A\s{2}(\S+)\s*\z/
            @platforms << $1
            next
          end

          next unless source_type

          if line =~ /\A\s{2}specs:\s*\z/
            in_specs = true
            next
          end

          if in_specs
            if (spec_match = line.match(SPEC_LINE))
              add_gem(spec_match, source_type, source_evidence)
            elsif line !~ /\A\s{6,}/
              # A non-dependency line ends the `specs:` block.
              in_specs = false unless line =~ /\A\s*\z/
            end

            next
          end

          collect_option(line, source_type, source_evidence)
        end
      end

      #
      # Records a single specification with its platform and source evidence.
      #
      def add_gem(match, source_type, source_evidence)
        name         = match[1]
        version      = Gem::Version.new(match[2])
        platform     = match[3] || 'ruby'

        @gems << LockedGem.new(
          name:        name,
          version:     version,
          platform:    platform,
          source_type: source_type,
          source:      deep_dup(source_evidence)
        )
      end

      #
      # Captures source-block options used as provenance evidence.
      #
      def collect_option(line, source_type, evidence)
        return unless (option = line.match(OPTION_LINE))

        key   = option[1]
        value = option[2]

        case source_type
        when LockedGem::GIT
          evidence['uri'] = value if key == 'remote'
          evidence[key] = value if %w[ref revision].include?(key)
        when LockedGem::PATH
          evidence['path'] = value if key == 'remote'
        when LockedGem::RUBYGEMS
          evidence['remotes'] << value if key == 'remote'
        end
      end

      #
      # Duplicates the evidence hash so each instance owns an independent copy.
      #
      def deep_dup(hash)
        hash.transform_values do |value|
          value.kind_of?(Array) ? value.dup : value
        end
      end
    end
  end
end
