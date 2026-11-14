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
                                :patched_versions)

      #
      # Indicates that an advisory file could not be trusted and/or parsed.
      #
      # Raised instead of silently skipping, widening, or narrowing an
      # advisory's version ranges, so callers can tell that the database is
      # incomplete rather than conclude that the scanned bundle is safe.
      #
      class Invalid < RuntimeError
      end

      #
      # Loads the advisory from a YAML file.
      #
      # @param [String] path
      #   The path to the advisory YAML file.
      #
      # @return [Advisory]
      #
      # @raise [Invalid]
      #   The advisory file contained duplicate keys, multiple YAML documents,
      #   non-String values in scalar fields, malformed version requirements,
      #   or a requirement that does not actually constrain any version.
      #
      # @api semipublic
      #
      def self.load(path)
        id = File.basename(path).chomp('.yml')

        begin
          content = File.read(path)
          validate_ast!(path,content)

          data = if Psych::VERSION >= '3.1.0'
                   YAML.safe_load(content, permitted_classes: [Date])
                 else
                   # XXX: psych < 3.1.0 YAML.safe_load calling convention
                   YAML.safe_load(content, [Date])
                 end
        rescue Invalid
          raise
        rescue StandardError => error
          raise(Invalid,"could not parse advisory #{path.dump}: #{error.message}")
        end

        unless data.kind_of?(Hash)
          raise(Invalid, "advisory data in #{path.dump} was not a Hash")
        end

        parse_versions = lambda { |field,versions|
          # An absent range means "no version is covered by this field",
          # which is the upstream convention for advisories without a patch.
          return [] if versions.nil?

          unless versions.kind_of?(Array)
            raise(Invalid,"#{path.dump}: #{field} must be an Array of version requirements, got #{versions.class}")
          end

          versions.map do |version|
            unless version.kind_of?(String)
              raise(Invalid,"#{path.dump}: #{field} contains a non-String requirement #{version.inspect}")
            end

            requirement = begin
                            parse_requirement(version)
                          rescue Gem::Requirement::BadRequirementError, ArgumentError => error
                            raise(Invalid,"#{path.dump}: invalid #{field} requirement #{version.inspect}: #{error.message}")
                          end

            if tautological?(requirement)
              raise(Invalid,"#{path.dump}: #{field} requirement #{version.inspect} matches every version")
            end

            requirement
          end
        }

        return new(
          path,
          id,
          string_field(path,'url',data['url'],required: true),
          string_field(path,'title',data['title'],required: true),
          date_field(path,data['date']),
          string_field(path,'description',data['description'],required: true),
          score_field(path,'cvss_v2',data['cvss_v2']),
          score_field(path,'cvss_v3',data['cvss_v3']),
          score_field(path,'cvss_v4',data['cvss_v4']),
          identifier_field(path,'cve',data['cve']),
          identifier_field(path,'osvdb',data['osvdb']),
          identifier_field(path,'ghsa',data['ghsa']),
          parse_versions['unaffected_versions',data['unaffected_versions']],
          parse_versions['patched_versions',data['patched_versions']]
        )
      end

      #
      # Parses a single version requirement.
      #
      # Splits on comma-separated constraints like `"~> 4.2.5, >= 4.2.5.2"`.
      #
      # @param [String] version
      #
      # @return [Gem::Requirement]
      #
      # @api private
      #
      def self.parse_requirement(version)
        Gem::Requirement.new(*version.split(', '))
      end

      #
      # Determines whether a requirement matches every possible version.
      #
      # An empty requirement (or one built from an empty string) is
      # normalized by RubyGems to `>= 0`, which silently marks every version
      # as patched. Such a "fix" is indistinguishable from an attacker
      # widening the range so that a vulnerable gem is reported as safe.
      #
      # @param [Gem::Requirement] requirement
      #
      # @return [Boolean]
      #
      # @api private
      #
      def self.tautological?(requirement)
        requirements = requirement.requirements

        requirements.empty? || requirements.all? do |operator,version|
          case operator
          when '>='
            version == Gem::Version.new('0')
          else
            false
          end
        end
      end

      #
      # Validates the YAML AST before any Ruby object is materialized.
      #
      # Rejects duplicate mapping keys (which YAML would otherwise silently
      # resolve to the last value), multiple documents (where only the first
      # is loaded), aliases/merge keys (which can hide a duplicate key behind
      # an anchor), and explicit tags (which could name an arbitrary class).
      #
      # @param [String] path
      #
      # @param [String] content
      #
      # @raise [Invalid]
      #
      # @api private
      #
      def self.validate_ast!(path,content)
        stream = begin
                   Psych.parse_stream(content)
                 rescue Psych::SyntaxError => error
                   raise(Invalid,"could not parse advisory #{path.dump}: #{error.message}")
                 end

        if stream.children.length != 1
          raise(Invalid,"#{path.dump}: expected exactly one YAML document, found #{stream.children.length}")
        end

        walk = lambda do |node|
          case node
          when Psych::Nodes::Alias
            raise(Invalid,"#{path.dump}: YAML aliases are not permitted")
          when Psych::Nodes::Mapping
            keys = node.children.each_slice(2).map { |key,_value| key }

            keys.each do |key|
              unless key.kind_of?(Psych::Nodes::Scalar)
                raise(Invalid,"#{path.dump}: advisory keys must be scalar strings")
              end

              if key.value == '<<'
                raise(Invalid,"#{path.dump}: YAML merge keys are not permitted")
              end
            end

            duplicated = keys.map(&:value).group_by(&:itself).select { |_key,occurrences| occurrences.length > 1 }
            unless duplicated.empty?
              raise(Invalid,"#{path.dump}: duplicate YAML key(s): #{duplicated.keys.map(&:dump).join(', ')}")
            end
          end

          if node.respond_to?(:tag) && node.tag
            raise(Invalid,"#{path.dump}: explicit YAML tags are not permitted")
          end

          if node.respond_to?(:children) && node.children
            node.children.each { |child| walk.call(child) }
          end
        end

        walk.call(stream)
      end

      #
      # Extracts a required or optional String field.
      #
      # @api private
      #
      def self.string_field(path,name,value,required: false)
        if value.nil?
          if required
            raise(Invalid,"#{path.dump}: missing required String field #{name.dump}")
          end
          return nil
        end

        unless value.kind_of?(String)
          raise(Invalid,"#{path.dump}: #{name} must be a String, got #{value.class}")
        end

        if value.strip.empty?
          raise(Invalid,"#{path.dump}: #{name} must not be blank")
        end

        return value
      end

      #
      # Extracts an optional publication date.
      #
      # @api private
      #
      def self.date_field(path,value)
        return nil if value.nil?

        case value
        when Date
          value
        when String
          begin
            Date.iso8601(value)
          rescue ArgumentError
            raise(Invalid,"#{path.dump}: date must be an ISO-8601 date, got #{value.inspect}")
          end
        else
          raise(Invalid,"#{path.dump}: date must be a YAML date, got #{value.class}")
        end
      end

      #
      # Extracts an optional CVSS score field.
      #
      # @api private
      #
      def self.score_field(path,name,value)
        return nil if value.nil?

        unless value.kind_of?(Numeric) && value >= 0.0 && value <= 10.0
          raise(Invalid,"#{path.dump}: #{name} must be a numeric CVSS score between 0.0 and 10.0, got #{value.inspect}")
        end

        return value
      end

      #
      # Extracts an optional identifier field.
      #
      # Identifiers are interpolated into human-readable output, so they are
      # restricted to the characters used by CVE/OSVDB/GHSA identifiers. This
      # prevents terminal or report-injection via control characters.
      #
      # @api private
      #
      def self.identifier_field(path,name,value)
        return nil if value.nil?

        text = case value
               when Integer then value.to_s
               when String  then value
               else
                 raise(Invalid,"#{path.dump}: #{name} must be a String or Integer, got #{value.class}")
               end

        unless text =~ /\A[A-Za-z0-9][A-Za-z0-9._-]*\z/
          raise(Invalid,"#{path.dump}: #{name} contains unsafe characters: #{value.inspect}")
        end

        # Preserve the original scalar type; OSVDB ids are YAML integers and
        # are rendered through interpolation, not as String-only fields.
        return value
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
          criticality: criticality
        })
      end

      alias to_s id

    end
  end
end
