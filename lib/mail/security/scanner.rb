# encoding: utf-8
# frozen_string_literal: true

require 'mail/security/strict_decode'
require 'mail/security/scan_report'

module Mail
  module Security
    # Pattern scanner built on strict decoding.
    #
    # Patterns are matched against losslessly decoded text only. A part whose
    # decoding is incomplete is reported as +:indeterminate+ instead of being
    # scanned against a tolerant string that may have destroyed the very bytes
    # that made the content dangerous.
    class Scanner
      DEFAULT_PATTERNS = [
        /evil\.example/i,
        /malware/i,
        /<script[\s>]/i,
        /javascript:/i
      ].freeze

      attr_reader :patterns

      def initialize(patterns = DEFAULT_PATTERNS)
        @patterns = Array(patterns)
      end

      def scan(message)
        leaves = message.multipart? ? message.all_parts.reject(&:multipart?) : [message]
        part_scans = leaves.each_with_index.map do |part, index|
          scan_part(part, index)
        end
        ScanReport.new(patterns: patterns, part_scans: part_scans)
      end

      def scan_part(part, index = 0)
        result = StrictDecode.decode_part(part)
        label = part_label(part, index)

        matches =
          if result.safe_to_scan?
            target = result.strict_text || result.transfer_decoded_bytes
            find_matches(target)
          else
            # Deliberately do not scan the lenient text: hidden or replaced
            # bytes could remove a match and create a false "safe" result.
            []
          end

        PartScan.new(part_label: label, decode_result: result, matches: matches)
      end

      def find_matches(text)
        patterns.each_with_object([]) do |pattern, found|
          text.scan(pattern) do
            found << { pattern: pattern, offset: Regexp.last_match.begin(0),
                       match: Regexp.last_match[0] }
          end
        end
      end

      def part_label(part, index)
        type = part.mime_type || 'application/octet-stream'
        cid = part.content_id || "part-#{index}"
        "#{type} (#{cid})"
      end
    end
  end
end
