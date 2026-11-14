require_relative 'version_model'

module Generative
  #
  # Deterministic, seed-driven generators producing advisories (lists of
  # patched / unaffected requirement entries) and probe version points over
  # a deliberately limited RubyGem version syntax:
  #
  # * versions: 1-3 numeric segments, optionally a `.preN` / `.alphaN` /
  #   `.betaN` / `.rcN` pre-release suffix,
  # * constraints: `=`, `!=`, `>`, `>=`, `<`, `<=`, `~>` against those
  #   versions (`~>` bounds stay numeric so the reference bump is exact),
  # * entries: one constraint, or two joined with ", " the way advisory
  #   YAML files express compound requirements.
  #
  # Probe points are clustered around the generated constraint bounds
  # (the bound itself, its neighbours, and pre-release variants) so that
  # off-by-one boundary errors are hit with high probability.
  #
  class Generators
    PRE_RELEASE_SUFFIXES = %w[pre alpha beta rc].freeze
    OPERATORS            = %w[= != > >= < <=].freeze

    # A generated test case.
    Case = Struct.new(:patched, :unaffected, :points)

    attr_reader :random

    def initialize(seed)
      @random = Random.new(seed)
    end

    # @return [Case]
    #
    def advisory_case
      patched    = Array.new(random.rand(0..3)) { requirement_entry }
      unaffected = Array.new(random.rand(0..2)) { requirement_entry }

      Case.new(patched, unaffected, probe_points(patched + unaffected))
    end

    # @return [String]
    #   e.g. ">= 1.2" or ">= 1.2, < 2.0".
    #
    def requirement_entry
      constraint = self.constraint

      if constraint.start_with?('~>') || random.rand(4) > 0
        constraint
      else
        # Gem::Requirement de-duplicates identical constraints, which
        # would break the YAML round-trip check; keep them distinct
        other = self.constraint
        other = self.constraint while other == constraint

        "#{constraint}, #{other}"
      end
    end

    # @return [String]
    #
    def constraint
      operator = random.rand(5).zero? ? '~>' : OPERATORS.sample(random: random)
      bound    = numeric_version

      bound = "#{bound}.#{PRE_RELEASE_SUFFIXES.sample(random: random)}#{random.rand(1..3)}" if operator != '~>' && random.rand(4).zero?

      "#{operator} #{bound}"
    end

    # @return [String]
    #   e.g. "2", "0.4", "1.2.3".
    #
    def numeric_version
      Array.new(random.rand(1..3)) { random.rand(0..4) }.join('.')
    end

    # @return [String]
    #   A numeric version, sometimes with a pre-release suffix.
    #
    def version
      base = numeric_version

      if random.rand(4).zero?
        "#{base}.#{PRE_RELEASE_SUFFIXES.sample(random: random)}#{random.rand(1..3)}"
      else
        base
      end
    end

    # Builds probe points densely covering the boundaries of the given
    # requirement entries, plus a few fully random versions.
    #
    # @param [Array<String>] entries
    #
    # @return [Array<String>]
    #
    def probe_points(entries)
      points = []

      entries.each do |entry|
        entry.split(', ').each do |constraint|
          operator, bound = constraint.split(' ', 2)

          points << bound
          points << shift_last_number(bound, -1)
          points << shift_last_number(bound,  1)
          points << "#{release_part(bound)}.pre1"
          points << "#{release_part(bound)}.pre2"

          if operator == '~>'
            upper = VersionModel.bump_segments(bound).join('.')
            points << upper
            points << shift_last_number(upper, 1)
            points << "#{upper}.pre1"
          end
        end
      end

      points.concat(Array.new(4) { version })
      points.compact.uniq
    end

    # The numeric prefix of a version, dropping any pre-release tail
    # ("1.2.pre1" -> "1.2").
    #
    # @param [String] version
    #
    # @return [String]
    #
    def release_part(version)
      segments = VersionModel.segments(version)
      release  = segments.take_while { |segment| segment.is_a?(Numeric) }
      release.empty? ? '0' : release.join('.')
    end

    # Returns the version with its last numeric segment shifted by delta,
    # or nil when the shift would go below zero.
    #
    # @param [String] version
    # @param [Integer] delta
    #
    # @return [String, nil]
    #
    def shift_last_number(version, delta)
      segments = VersionModel.segments(version)
      index    = segments.rindex { |segment| segment.is_a?(Numeric) }
      return nil unless index

      shifted = segments[index] + delta
      return nil if shifted.negative?

      segments.dup.tap { |copy| copy[index] = shifted }.join('.')
    end
  end
end
