# frozen_string_literal: true

module Zip
  module Forensic
    # One central directory record, kept in the exact order in which it
    # appears in the central directory. Nothing here is keyed by entry name,
    # so duplicate names are all retained.
    class CentralRecord
      attr_accessor :index, :local_header, :link_status
      attr_reader :record_offset, :record_length, :fields, :name, :extra,
                  :comment, :effective_offset

      def initialize(index, record_offset, record_length, fields, name,
                     extra, comment, effective_offset)
        @index            = index
        @record_offset    = record_offset
        @record_length    = record_length
        @fields           = fields
        @name             = name
        @extra            = extra
        @comment          = comment
        @effective_offset = effective_offset
        @local_header     = nil
        @link_status       = :unlinked
      end

      def to_h
        {
          index: index,
          record_offset: record_offset,
          hex_record_offset: Forensic.hex_offset(record_offset),
          record_length: record_length,
          name_hex: Forensic.hex_bytes(name.raw),
          name_inspect: name.value.inspect,
          name_offset: name.offset, name_length: name.length,
          extra_offset: extra&.offset, extra_length: extra&.length,
          comment_offset: comment&.offset, comment_length: comment&.length,
          effective_local_header_offset: effective_offset.value,
          effective_offset_provenance: effective_offset.source,
          effective_offset_field: effective_offset.to_s,
          link_status: link_status,
          linked_local_header_index: local_header&.index,
          fields: fields.transform_values(&:to_s)
        }
      end
    end
  end
end
