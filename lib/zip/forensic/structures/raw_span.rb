# frozen_string_literal: true

module Zip
  module Forensic
    # A raw (unparsed) variable-length span such as an extra field or a
    # comment. The bytes are retained verbatim.
    class RawSpan
      attr_reader :offset, :raw

      def initialize(offset, raw)
        @offset = offset
        @raw    = raw
      end

      def length
        @raw.bytesize
      end

      def byte_range
        "#{Forensic.hex_offset(@offset)}..#{Forensic.hex_offset(@offset + @raw.bytesize)}"
      end
    end
  end
end
