# frozen_string_literal: true

module Zip
  module Forensic
    # A local file header discovered by scanning the archive for local header
    # signatures, independent of the central directory.
    class LocalHeader
      attr_accessor :index, :valid, :parse_error, :referenced_by,
                    :data_descriptor_range
      attr_reader :header_offset, :header_length, :fields, :name,
                  :extra, :data_range

      # Allows the link phase to fill in a payload span that was unknown when
      # the local header was scanned (streamed entries with bit 3 set report a
      # zero size in their local header).
      attr_writer :data_range

      def initialize(header_offset, header_length, fields, name, extra,
                     data_range, valid: true, parse_error: nil)
        @index         = nil
        @header_offset = header_offset
        @header_length = header_length
        @fields        = fields
        @name          = name
        @extra         = extra
        @data_range    = data_range
        @valid          = valid
        @parse_error    = parse_error
        @referenced_by = []
        @data_descriptor_range = nil
      end

      def data_descriptor?
        !@data_descriptor_range.nil?
      end

      def data_start
        @data_range&.first
      end

      def data_end
        @data_range&.last
      end

      def orphan?
        @referenced_by.empty?
      end

      def to_h
        {
          index: index, valid: valid, parse_error: parse_error,
          header_offset: header_offset,
          hex_header_offset: Forensic.hex_offset(header_offset),
          header_length: header_length,
          name_hex: Forensic.hex_bytes(name.raw),
          name_inspect: name.value.inspect,
          name_offset: name.offset, name_length: name.length,
          extra_offset: extra&.offset, extra_length: extra&.length,
          data_range: data_range_hash,
          referenced_by_central_records: referenced_by,
          orphan: orphan?,
          fields: fields.transform_values(&:to_s)
        }
      end

      private

      def data_range_hash
        return nil unless data_range

        {
          start: data_range.first,
          hex_start: Forensic.hex_offset(data_range.first),
          end: data_range.last,
          hex_end: Forensic.hex_offset(data_range.last)
        }
      end
    end
  end
end
