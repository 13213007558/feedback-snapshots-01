# encoding: utf-8
# frozen_string_literal: true

require 'mail/security/issue'

module Mail
  module Security
    # Outcome of decoding one MIME body through both decoding stages.
    #
    # Two independent results are kept side by side:
    #
    # * +strict_text+ / +strict_bytes+ are only present when both the transfer
    #   encoding and charset stages explain every single byte. They are the
    #   only inputs a security scan may treat as fully decoded.
    # * +lenient_text+ mirrors Mail's historical, display-oriented decoding and
    #   may contain U+FFFD or "?" where bytes were replaced. It is never marked
    #   as scan-complete on its own.
    class DecodeResult
      attr_reader :transfer_encoding, :charset
      attr_reader :transfer_decoded_bytes, :issues
      attr_reader :strict_text, :strict_bytes, :lenient_text

      def initialize(transfer_encoding:, charset:, transfer_decoded_bytes:,
                     transfer_issues:, charset_issues:, strict_text:, lenient_text:,
                     charset_applicable: true)
        @transfer_encoding = transfer_encoding
        @charset = charset
        @transfer_decoded_bytes = transfer_decoded_bytes
        @issues = transfer_issues + charset_issues
        @transfer_issues = transfer_issues
        @charset_issues = charset_issues
        @charset_applicable = charset_applicable
        @strict_text = strict_text
        @strict_bytes = strict_text && strict_text.dup.force_encoding(Encoding::ASCII_8BIT)
        @lenient_text = lenient_text
      end

      def transfer_encoding_complete?
        @transfer_issues.empty?
      end

      # True when the declared charset applies to these bytes at all. Binary
      # media types (RFC 2045 section 6.1) carry no charset semantics.
      def charset_applicable?
        @charset_applicable
      end

      def charset_complete?
        @charset_issues.empty?
      end

      # True only when no byte was replaced, repaired or left unexplained.
      def complete?
        @issues.empty?
      end

      # A scan may only treat decoded text as covering the whole message when
      # both stages decoded cleanly. Binary parts are complete once the
      # transfer encoding alone validates, but expose bytes rather than text.
      def safe_to_scan?
        complete? && (!@charset_applicable || !@strict_text.nil?)
      end

      def transfer_encoding_issues
        @transfer_issues
      end

      def charset_issues
        @charset_issues
      end

      def issues_for(stage)
        @issues.select { |issue| issue.stage == stage }
      end

      # Bytes a tolerant decoder replaced or dropped, located in the original
      # stage input. Transfer-stage offsets address raw source; charset-stage
      # offsets address the transfer-decoded bytes.
      def unexplainable_bytes
        @issues.map(&:bytes)
      end

      def summary
        stages = []
        stages << "transfer_encoding=#{transfer_encoding_complete? ? 'complete' : 'incomplete'}"
        stages << if !charset_applicable?
                    'charset=not-applicable'
                  elsif charset_complete?
                    'charset=complete'
                  else
                    'charset=incomplete'
                  end
        "#{complete? ? 'complete' : 'incomplete'} (#{stages.join(', ')}, #{@issues.length} issue(s))"
      end
    end
  end
end
