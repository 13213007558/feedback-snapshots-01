module Generative
  #
  # Independent reference model for RubyGem version comparison and
  # requirement matching, restricted to the limited version syntax used by
  # the generators (numeric segments plus `.preN` / `.alphaN` / `.betaN` /
  # `.rcN` pre-release suffixes).
  #
  # This module deliberately does NOT call Gem::Requirement, Gem::Version
  # comparison operators, or Advisory#vulnerable?. The property tests use it
  # as an oracle that is computed independently from the code under test, so
  # that a divergence pinpoints the exact version where a miss happens.
  #
  module VersionModel
    module_function

    # Tokenizes a version string into segments, mirroring how RubyGems
    # splits versions into runs of digits and runs of letters
    # ("1.0.pre1" -> [1, 0, "pre", 1]).
    #
    # @param [String] version
    #
    # @return [Array<Integer, String>]
    #
    def segments(version)
      version.to_s.scan(/\d+|[a-zA-Z]+/).map do |segment|
        segment =~ /\A\d+\z/ ? segment.to_i : segment
      end
    end

    # @param [String] version
    #
    # @return [Boolean]
    #   Whether the version carries a pre-release segment.
    #
    def prerelease?(version)
      segments(version).any? { |segment| segment.is_a?(String) }
    end

    def compare(version_a, version_b)
      compare_segments(segments(version_a), segments(version_b))
    end

    # Canonicalizes a segment list the way Gem::Version#canonical_segments
    # does: trailing zero segments are dropped, and zero segments
    # immediately before the first pre-release letter are dropped
    # ("2.0.pre1" and "2.pre1" canonicalize identically).
    #
    # @param [Array<Integer, String>] segment_list
    #
    # @return [Array<Integer, String>]
    #
    def canonical_segments(segment_list)
      canonical = segment_list.dup
      canonical.pop while canonical.length > 1 && canonical.last == 0

      first_string = canonical.index { |segment| segment.is_a?(String) }

      if first_string
        keep = first_string
        keep -= 1 while keep > 0 && canonical[keep - 1] == 0
        canonical = canonical[0...keep] + canonical[first_string..-1] if keep < first_string
      end

      canonical
    end

    # Three-way comparison over segment lists, following
    # Gem::Version#<=> semantics:
    #
    # * segments are canonicalized first ("1.0" == "1.0.0",
    #   "2.pre1" == "2.0.pre1"),
    # * numeric segments sort after alphabetic (pre-release) segments
    #   ("1.0.0.pre1" < "1.0.0").
    #
    # @param [Array<Integer, String>] segments_a
    # @param [Array<Integer, String>] segments_b
    #
    # @return [-1, 0, 1]
    #
    def compare_segments(raw_segments_a, raw_segments_b)
      segments_a = canonical_segments(raw_segments_a)
      segments_b = canonical_segments(raw_segments_b)
      limit      = [segments_a.length, segments_b.length].min

      index = 0

      while index < limit
        segment_a = segments_a[index]
        segment_b = segments_b[index]
        index    += 1

        next if segment_a == segment_b

        return -1 if segment_a.is_a?(String) && segment_b.is_a?(Numeric)
        return  1 if segment_a.is_a?(Numeric) && segment_b.is_a?(String)

        return segment_a <=> segment_b
      end

      if index >= segments_a.length
        while index < segments_b.length
          segment_b = segments_b[index]
          return 1 if segment_b.is_a?(String)
          return -1 unless segment_b.zero?
          index += 1
        end
      else
        while index < segments_a.length
          segment_a = segments_a[index]
          return -1 if segment_a.is_a?(String)
          return 1 unless segment_a.zero?
          index += 1
        end
      end

      0
    end

    # Re-implements Gem::Version#bump over the segment list: trailing
    # pre-release segments are dropped, the last remaining segment is
    # dropped (when more than one segment exists), and the new last
    # segment is incremented.
    #
    # @param [String] version
    #
    # @return [Array<Integer>]
    #
    def bump_segments(version)
      bumped = segments(version)
      bumped.pop while bumped.any? { |segment| segment.is_a?(String) }
      bumped.pop if bumped.length > 1
      bumped[-1] += 1
      bumped
    end

    # The numeric prefix of a version as segment list, dropping any
    # pre-release tail ("1.2.pre1" -> [1, 2]).
    #
    # @param [String] version
    #
    # @return [Array<Integer>]
    #
    def release_segments(version)
      release = segments(version).take_while { |segment| segment.is_a?(Numeric) }
      release.empty? ? [0] : release
    end

    CONSTRAINT_PATTERN = /\A(=|!=|>=|>|<=|<|~>)\s*(\S+)\z/

    # Evaluates a single constraint (e.g. ">= 1.2") against a version.
    #
    # @param [String] constraint
    # @param [String] version
    #
    # @return [Boolean]
    #
    def constraint_satisfied?(constraint, version)
      match = CONSTRAINT_PATTERN.match(constraint.strip)
      raise "unparseable generated constraint: #{constraint.inspect}" unless match

      operator = match[1]
      bound    = match[2]

      case operator
      when '='  then compare(version, bound) == 0
      when '!=' then compare(version, bound) != 0
      when '>'  then compare(version, bound) >  0
      when '>=' then compare(version, bound) >= 0
      when '<'  then compare(version, bound) <  0
      when '<=' then compare(version, bound) <= 0
      when '~>'
        # Gem::Requirement's "~>" operator compares the *release* of the
        # version (pre-release tail stripped) against the bumped bound:
        #   v >= r && v.release < r.bump
        compare(version, bound) >= 0 &&
          compare_segments(release_segments(version), bump_segments(bound)) < 0
      end
    end

    # Evaluates one requirement entry as it appears in an advisory YAML
    # file. Multiple constraints are joined with ", " exactly the way
    # Advisory.load splits them.
    #
    # @param [String] requirement_entry
    #   e.g. ">= 1.2, < 2.0"
    #
    # @param [String] version
    #
    # @return [Boolean]
    #
    def requirement_satisfied?(requirement_entry, version)
      requirement_entry.split(', ').all? do |constraint|
        constraint_satisfied?(constraint, version)
      end
    end

    # The reference oracle: a version is affected by an advisory unless it
    # is covered by any of the patched or unaffected requirements. An
    # advisory with no patched and no unaffected requirements therefore
    # affects every version.
    #
    # @param [Array<String>] patched_entries
    # @param [Array<String>] unaffected_entries
    # @param [String] version
    #
    # @return [Boolean]
    #
    def vulnerable?(patched_entries, unaffected_entries, version)
      patched = patched_entries.any? do |entry|
        requirement_satisfied?(entry, version)
      end

      unaffected = unaffected_entries.any? do |entry|
        requirement_satisfied?(entry, version)
      end

      !patched && !unaffected
    end
  end
end
