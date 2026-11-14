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

require 'date'
require 'yaml'

module Bundler
  module Audit
    #
    # Represents an advisory loaded from the {Database}.
    #
    class Advisory < Struct.new(:path,
                                :id,
                                :url,
                                :title,
                                :date,
                                :description,
                                :cvss_v2,
                                :cvss_v3,
                                :cvss_v4,
                                :cve,
                                :osvdb,
                                :ghsa,
                                :unaffected_versions,
                                :patched_versions,
                                :affected_platforms,
                                :affected_sources)

      #
      # Loads the advisory from a YAML file.
      #
      # @param [String] path
      #   The path to the advisory YAML file.
      #
      # @return [Advisory]
      #
      # @api semipublic
      #
      def self.load(path)
        id   = File.basename(path).chomp('.yml')
        data = File.open(path) do |yaml|
                 if Psych::VERSION >= '3.1.0'
                   YAML.safe_load(yaml, permitted_classes: [Date])
                 else
                   # XXX: psych < 3.1.0 YAML.safe_load calling convention
                   YAML.safe_load(yaml, [Date])
                 end
               end

        unless data.kind_of?(Hash)
          raise("advisory data in #{path.dump} was not a Hash")
        end

        parse_versions = lambda { |versions|
          Array(versions).map do |version|
            Gem::Requirement.new(*version.split(', '))
          end
        }

        parse_platforms = lambda { |platforms|
          Array(platforms).map { |platform| platform.to_s }
        }

        parse_sources = lambda { |sources|
          Array(sources).map do |source|
            source.kind_of?(Hash) ? source.transform_keys(&:to_s) : source.to_s
          end
        }

        return new(
          path,
          id,
          data['url'],
          data['title'],
          data['date'],
          data['description'],
          data['cvss_v2'],
          data['cvss_v3'],
          data['cvss_v4'],
          data['cve'],
          data['osvdb'],
          data['ghsa'],
          parse_versions[data['unaffected_versions']],
          parse_versions[data['patched_versions']],
          parse_platforms[data['affected_platforms']],
          parse_sources[data['affected_sources']]
        )
      end

      #
      # The CVE identifier.
      #
      # @return [String, nil]
      #
      def cve_id
        "CVE-#{cve}" if cve
      end

      #
      # The OSVDB identifier.
      #
      # @return [String, nil]
      #
      def osvdb_id
        "OSVDB-#{osvdb}" if osvdb
      end

      #
      # The GHSA (GitHub Security Advisory) identifier
      #
      # @return [String, nil]
      #
      # @since 0.7.0
      #
      def ghsa_id
        "GHSA-#{ghsa}" if ghsa
      end

      #
      # Return a compacted list of all ids
      #
      # @return [Array<String>]
      #
      # @since 0.7.0
      #
      def identifiers
        [
          cve_id,
          osvdb_id,
          ghsa_id
        ].compact
      end

      #
      # Determines how critical the vulnerability is.
      #
      # @return [:none, :low, :medium, :high, :critical, nil]
      #   The criticality of the vulnerability based on the CVSS score.
      #
      def criticality
        if cvss_v4 || cvss_v3
          case cvss_v4 || cvss_v3
          when 0.0       then :none
          when 0.1..3.9  then :low
          when 4.0..6.9  then :medium
          when 7.0..8.9  then :high
          when 9.0..10.0 then :critical
          end
        elsif cvss_v2
          case cvss_v2
          when 0.0..3.9  then :low
          when 4.0..6.9  then :medium
          when 7.0..10.0 then :high
          end
        end
      end

      #
      # Checks whether the version is not affected by the advisory.
      #
      # @param [Gem::Version] version
      #   The version to compare against {#unaffected_versions}.
      #
      # @return [Boolean]
      #   Specifies whether the version is not affected by the advisory.
      #
      # @since 0.2.0
      #
      def unaffected?(version)
        unaffected_versions.any? do |unaffected_version|
          unaffected_version === version
        end
      end

      #
      # Checks whether the version is patched against the advisory.
      #
      # @param [Gem::Version] version
      #   The version to compare against {#patched_versions}.
      #
      # @return [Boolean]
      #   Specifies whether the version is patched against the advisory.
      #
      # @since 0.2.0
      #
      def patched?(version)
        patched_versions.any? do |patched_version|
          patched_version === version
        end
      end

      #
      # Checks whether the version is vulnerable to the advisory.
      #
      # @param [Gem::Version] version
      #   The version to compare against {#patched_versions}.
      #
      # @return [Boolean]
      #   Specifies whether the version is vulnerable to the advisory or not.
      #
      def vulnerable?(version)
        !patched?(version) && !unaffected?(version)
      end

      #
      # Specifies whether the advisory explicitly restricts the platforms it
      # affects.
      #
      # @return [Boolean]
      #
      def platform_restricted?
        Array(affected_platforms).any?
      end

      #
      # Specifies whether the advisory explicitly restricts the supply sources
      # it affects.
      #
      # @return [Boolean]
      #
      def source_restricted?
        Array(affected_sources).any?
      end

      #
      # Determines whether the locked gem's platform is within the advisory's
      # affected platform scope. When the advisory does not declare any
      # platform restriction every platform is in scope, preserving the meaning
      # of advisories that predate platform metadata.
      #
      # @param [LockedGem] locked_gem
      #
      # @return [Boolean]
      #
      def affects_platform?(locked_gem)
        return true unless platform_restricted?

        affected_platforms.include?(locked_gem.platform)
      end

      #
      # Determines whether the locked gem's supply source is within the
      # advisory's affected source scope. When the advisory does not declare
      # any source restriction every source is in scope, preserving the
      # meaning of advisories that predate source metadata.
      #
      # @param [LockedGem] locked_gem
      #
      # @return [Boolean]
      #
      def affects_source?(locked_gem)
        return true unless source_restricted?

        affected_sources.any? do |restriction|
          source_restriction_matches?(restriction, locked_gem)
        end
      end

      #
      # Determines whether the platform/source scope of the advisory applies to
      # the locked gem instance. Restrictions only narrow the applicable
      # instances; they never widen them.
      #
      # @param [LockedGem] locked_gem
      #
      # @return [Boolean]
      #
      def applies_to?(locked_gem)
        affects_platform?(locked_gem) && affects_source?(locked_gem)
      end

      #
      # Classifies a locked gem instance against the advisory while preserving
      # its platform and supply-source identity.
      #
      # Git and path sources cannot be proven identical to the published public
      # package the advisory describes, so a matching name and version only
      # ever yields `:unknown` for them rather than a positive or a negative
      # security conclusion.
      #
      # @param [LockedGem] locked_gem
      #
      # @return [:affected, :unaffected, :unknown]
      #
      # @see Scanner
      #
      def verdict_for(locked_gem)
        unless vulnerable?(locked_gem.version)
          return :unaffected
        end

        if locked_gem.unverifiable_source?
          return :unknown
        end

        applies_to?(locked_gem) ? :affected : :unaffected
      end

      #
      # Compares two advisories.
      #
      # @param [Advisory] other
      #
      # @return [Boolean]
      #
      def ==(other)
        id == other.id
      end

      #
      # Converts the advisory to a Hash.
      #
      # @return [Hash{Symbol => Object}]
      #
      def to_h
        super.merge({
          criticality: criticality,
          affected_platforms: affected_platforms,
          affected_sources: affected_sources
        })
      end

      alias to_s id

      private

      #
      # Determines whether a single affected-sources restriction matches a
      # locked gem's supply source.
      #
      # A plain string restriction (for example `rubygems`, `git`, `path`)
      # matches every instance of that source type. A Hash restriction may add
      # a `uri` for git sources or a `path` for path sources to scope the
      # restriction to a specific origin.
      #
      # @param [String, Hash] restriction
      # @param [LockedGem] locked_gem
      #
      # @return [Boolean]
      #
      def source_restriction_matches?(restriction,locked_gem)
        if restriction.kind_of?(Hash)
          type = restriction['type'].to_s

          return false unless locked_gem.source_type.to_s == type

          if restriction.key?('uri')
            return false unless locked_gem.source['uri'].to_s == restriction['uri'].to_s
          end

          if restriction.key?('path')
            return false unless locked_gem.source['path'].to_s == restriction['path'].to_s
          end

          if restriction.key?('remote')
            return false unless Array(locked_gem.source['remotes']).include?(restriction['remote'].to_s)
          end

          true
        else
          locked_gem.source_type.to_s == restriction.to_s
        end
      end

    end
  end
end
