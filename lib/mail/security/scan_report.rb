# encoding: utf-8
# frozen_string_literal: true

module Mail
  module Security
    # Result of scanning one leaf part for dangerous content.
    #
    # Verdict semantics:
    #
    # * +:dangerous+     - a pattern matched inside a complete, lossless decode.
    # * +:clean+         - every byte decoded cleanly and no pattern matched.
    # * +:indeterminate+ - bytes were replaced, dropped or unexplainable, so a
    #                      missing match cannot be trusted as "safe".
    class PartScan
      attr_reader :part_label, :decode_result, :matches

      def initialize(part_label:, decode_result:, matches:)
        @part_label = part_label
        @decode_result = decode_result
        @matches = matches
      end

      def verdict
        return :dangerous unless matches.empty?
        return :clean if decode_result.complete?

        :indeterminate
      end

      def complete?
        decode_result.complete?
      end

      def issues
        decode_result.issues
      end
    end

    # Aggregated verdict for a whole (possibly multipart) message.
    class ScanReport
      attr_reader :part_scans, :patterns

      def initialize(patterns:, part_scans:)
        @patterns = patterns
        @part_scans = part_scans
      end

      def dangerous?
        part_scans.any? { |scan| scan.verdict == :dangerous }
      end

      def clean?
        part_scans.any? && part_scans.all? { |scan| scan.verdict == :clean }
      end

      # True when at least one part could not be fully decoded. Such a message
      # must never be reported as scanned clean, even if the tolerant display
      # text contains none of the patterns.
      def indeterminate?
        part_scans.any? { |scan| scan.verdict == :indeterminate }
      end

      def verdict
        return :dangerous if dangerous?
        return :clean if clean?

        :indeterminate
      end

      def issues
        part_scans.flat_map(&:issues)
      end

      def matches
        part_scans.reject { |scan| scan.matches.empty? }
      end
    end
  end
end
