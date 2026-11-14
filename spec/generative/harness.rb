require_relative 'version_model'

module Generative
  #
  # Raised when the code under test diverges from the reference model.
  # Carries the shrunken counter-example so the failure message names the
  # exact requirement ranges and the exact version where the divergence
  # (a missed vulnerability or a false alarm) happens.
  #
  class PropertyFailure < StandardError
    attr_reader :seed, :iteration, :layer,
                :patched, :unaffected, :point,
                :expected, :actual

    def initialize(seed:, iteration:, layer:, patched:, unaffected:, point:, expected:, actual:)
      @seed       = seed
      @iteration  = iteration
      @layer      = layer
      @patched    = patched
      @unaffected = unaffected
      @point      = point
      @expected   = expected
      @actual     = actual

      super(build_message)
    end

    private

    def build_message
      direction = if expected && !actual
                    'missed vulnerability: the version IS affected but was not reported'
                  else
                    'false alarm: the version is NOT affected but was reported'
                  end

      [
        'scan result diverged from the independently computed reference set',
        '',
        "  layer:      #{layer}",
        "  seed:       #{seed} (replay with PROP_SEED=#{seed})",
        "  iteration:  #{iteration}",
        "  version:    #{point.inspect}",
        "  expected (reference model): vulnerable=#{expected}",
        "  actual   (code under test): vulnerable=#{actual}",
        "  #{direction}",
        '',
        '  minimal reproducing ranges after shrinking:',
        "    patched_versions:    #{patched.inspect}",
        "    unaffected_versions: #{unaffected.inspect}"
      ].join("\n")
    end
  end

  #
  # Property runner: compares the verdict produced by the code under test
  # against the reference model for every probe point. On divergence it
  # greedily shrinks the requirement ranges and the failing version before
  # raising PropertyFailure, so the failure pinpoints the minimal ranges
  # and the exact version of the miss.
  #
  module Harness
    module_function

    # Checks one generated case.
    #
    # @param [Array<String>] patched
    #   patched_versions requirement entries.
    #
    # @param [Array<String>] unaffected
    #   unaffected_versions requirement entries.
    #
    # @param [Array<String>] points
    #   Version strings to probe.
    #
    # @param [Integer] seed
    # @param [Integer] iteration
    # @param [String] layer
    #   Name of the layer under test, for the failure message.
    #
    # @param [Proc] build_actual
    #   Called with (patched, unaffected) and must return a callable
    #   mapping a version String to the Boolean verdict of the code under
    #   test. Called again with shrunken ranges while shrinking.
    #
    # @raise [PropertyFailure]
    #
    def check(patched:, unaffected:, points:, seed:, iteration:, layer:, build_actual:)
      failing_point = points.find do |point|
        diverges?(patched, unaffected, point, build_actual)
      end

      return unless failing_point

      shrunk_patched, shrunk_unaffected = shrink_ranges(patched, unaffected, failing_point, build_actual)
      shrunk_point = shrink_point(shrunk_patched, shrunk_unaffected, failing_point, build_actual)

      raise PropertyFailure.new(
        seed:       seed,
        iteration:  iteration,
        layer:      layer,
        patched:    shrunk_patched,
        unaffected: shrunk_unaffected,
        point:      shrunk_point,
        expected:   VersionModel.vulnerable?(shrunk_patched, shrunk_unaffected, shrunk_point),
        actual:     build_actual.call(shrunk_patched, shrunk_unaffected).call(shrunk_point)
      )
    end

    # @return [Boolean]
    #   Whether the actual verdict diverges from the reference model.
    #
    def diverges?(patched, unaffected, point, build_actual)
      actual = build_actual.call(patched, unaffected)

      VersionModel.vulnerable?(patched, unaffected, point) != actual.call(point)
    end

    # Greedily drops requirement entries, then constraints within entries,
    # while the divergence at the failing point persists.
    #
    # @return [Array(Array<String>, Array<String>)]
    #
    def shrink_ranges(patched, unaffected, point, build_actual)
      patched    = patched.dup
      unaffected = unaffected.dup

      loop do
        changed = false

        # drop whole entries
        [[:patched, patched], [:unaffected, unaffected]].each do |which, list|
          (list.length - 1).downto(0) do |index|
            candidate = list[0...index] + list[(index + 1)..-1]

            trial_patched    = (which == :patched) ? candidate : patched
            trial_unaffected = (which == :patched) ? unaffected : candidate

            if diverges?(trial_patched, trial_unaffected, point, build_actual)
              patched    = trial_patched
              unaffected = trial_unaffected
              list       = candidate
              changed    = true
            end
          end
        end

        # drop constraints within compound entries
        [[:patched, patched], [:unaffected, unaffected]].each do |which, list|
          list.each_with_index do |entry, entry_index|
            constraints = entry.split(', ')
            next if constraints.length < 2

            constraints.each do |single|
              candidate = list.dup
              candidate[entry_index] = single

              trial_patched    = (which == :patched) ? candidate : patched
              trial_unaffected = (which == :patched) ? unaffected : candidate

              if diverges?(trial_patched, trial_unaffected, point, build_actual)
                patched    = trial_patched
                unaffected = trial_unaffected
                list       = candidate
                changed    = true
              end
            end
          end
        end

        break unless changed
      end

      [patched, unaffected]
    end

    # Replaces the failing version with the simplest version that still
    # diverges: pre-release suffixes are stripped, segments are dropped,
    # and numbers are lowered towards zero.
    #
    # @return [String]
    #
    def shrink_point(patched, unaffected, point, build_actual)
      current = point

      loop do
        candidate = simpler_versions(current).find do |simpler|
          diverges?(patched, unaffected, simpler, build_actual)
        end

        break unless candidate

        current = candidate
      end

      current
    end

    # Candidate simpler versions, ordered from simplest to most complex.
    #
    # @param [String] version
    #
    # @return [Array<String>]
    #
    def simpler_versions(version)
      segments   = VersionModel.segments(version)
      release    = segments.take_while { |segment| segment.is_a?(Numeric) }
      release    = [0] if release.empty?
      candidates = []

      # drop the pre-release tail
      candidates << release.join('.') if release.length < segments.length

      # drop trailing segments
      (release.length - 1).downto(1) do |length|
        candidates << release.first(length).join('.')
      end

      # lower individual numbers towards zero
      release.each_with_index do |number, index|
        (number - 1).downto(0) do |lower|
          lowered = release.dup
          lowered[index] = lower
          candidates << lowered.join('.')
        end
      end

      candidates.uniq
    end
  end
end
