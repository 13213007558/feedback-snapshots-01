# frozen_string_literal: true

module Zip
  module Forensic
    # A span of raw bytes that is not interpreted as a zip structure (a
    # preamble, a gap between records, or bytes trailing the end of central
    # directory record). Only a short {#preview} is retained so that reports
    # stay small even when the unparsed region itself is large.
    class Region
      attr_reader :kind, :offset, :length, :preview, :note

      def initialize(kind, offset, length, preview, note: nil)
        @kind    = kind
        @offset  = offset
        @length  = length
        @preview = preview
        @note    = note
      end

      def to_h
        {
          kind: kind, offset: offset, length: length,
          hex_offset: Forensic.hex_offset(offset),
          hex_end: Forensic.hex_offset(offset + length),
          preview_hex: Forensic.hex_bytes(preview), note: note
        }
      end
    end
  end
end
