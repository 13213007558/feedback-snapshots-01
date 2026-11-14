# frozen_string_literal: true

module Zip
  module Forensic
    # A single parsed value together with the exact bytes it came from.
    #
    # Every value reported by the forensic inspection is wrapped in a Field so
    # that a reviewer can independently verify it against the source archive:
    #
    # - {#value}        - the parsed (interpreted) value.
    # - {#raw}          - the untouched source bytes for the value, as a
    #                     binary-encoded String.
    # - {#offset}       - absolute byte offset of {#raw} in the archive.
    # - {#length}       - number of bytes the value occupies.
    # - {#source}       - which structure the bytes belong to (for example
    #                     `'central directory record #1'` or `'EOCD'`).
    #
    # Field objects are never reconstructed or repaired: if a record is
    # malformed, the corresponding field is reported alongside an anomaly
    # rather than silently replaced with a guessed value.
    class Field
      attr_reader :value, :raw, :offset, :length, :source

      def initialize(value, raw, offset, source)
        @value  = value
        @raw    = raw
        @offset = offset
        @length = raw.bytesize
        @source = source
      end

      # The half-open byte range `[offset, offset + length)` as a human
      # readable string, for example `@0x001e..0x0022 (4 bytes)`.
      def byte_range
        "#{Forensic.hex_offset(@offset)}..#{Forensic.hex_offset(@offset + @length)}"
      end

      def hex_raw
        Forensic.hex_bytes(@raw)
      end

      def to_s
        "#{value.inspect} [#{source} bytes #{byte_range}: #{hex_raw}]"
      end
    end
  end
end
