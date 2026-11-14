# frozen_string_literal: true

module Zip
  module Forensic
    class Inspector
      # Locates and parses the End of Central Directory record, including the
      # Zip64 locator/record when the classic EOCD carries placeholders. The
      # numeric geometry is retained on the report for later phases while the
      # provenance-bearing {Field} rendering is kept for the report output.
      module EocdScanner
        EOCD_LAYOUT = [
          [:signature, 0, 'V'], [:number_of_this_disk, 4, 'v'],
          [:disk_with_cdir, 6, 'v'], [:entries_on_this_disk, 8, 'v'],
          [:total_entries, 10, 'v'], [:central_directory_size, 12, 'V'],
          [:central_directory_offset, 16, 'V'], [:comment_length, 20, 'v']
        ].freeze

        private

        def scan_eocd
          window_start = [0, @bytes.bytesize - MAX_EOCD_SCAN].max
          window = @bytes.byteslice(window_start, @bytes.bytesize - window_start)
          relative = rindex_signature(window, EOCD_SIG)
          return eocd_missing unless relative

          parse_eocd(window_start + relative)
        end

        def eocd_missing
          add_anomaly(:eocd_not_found,
                      'End of central directory signature not found', {}, [])
        end

        def parse_eocd(offset)
          return truncated_eocd(offset) unless offset + STATIC_EOCD_SIZE <= @bytes.bytesize

          fields = unpack_fields(offset, EOCD_LAYOUT, 'EOCD')
          comment_length = fields[:comment_length].value
          comment = safe_span(offset + STATIC_EOCD_SIZE, comment_length)
          flag_truncated_comment(comment, comment_length)
          store_eocd(offset, fields, comment)
          apply_zip64_eocd(offset, fields)
        end

        def truncated_eocd(offset)
          add_anomaly(:eocd_truncated,
                      'EOCD signature found but the 22-byte record is truncated',
                      {}, [offset])
        end

        def flag_truncated_comment(comment, declared_length)
          return if declared_length.zero? || comment.length == declared_length

          add_anomaly(:eocd_truncated_comment,
                      'EOCD comment extends past end of file',
                      { declared_comment_length: declared_length,
                        available_bytes: comment.length }, [comment.offset])
        end

        def store_eocd(offset, fields, comment)
          numeric = fields.transform_values(&:value)
          report.store_eocd(
            offset: offset,
            hex_offset: Forensic.hex_offset(offset),
            total_entries: numeric[:total_entries],
            central_directory_size: numeric[:central_directory_size],
            central_directory_offset: numeric[:central_directory_offset],
            comment_offset: comment.offset, comment_length: comment.length,
            comment_hex: Forensic.hex_bytes(comment.raw),
            fields: fields.transform_values(&:to_s)
          )
        end

        def apply_zip64_eocd(eocd_offset, fields)
          return unless zip64_placeholders?(fields)

          locator_offset = eocd_offset - 20
          return unless locator_offset >= 0 &&
                        signature_at?(locator_offset, ZIP64_LOCATOR_SIG)

          zip64_offset = @bytes.byteslice(locator_offset + 8, 8)&.unpack1('Q<')
          parse_zip64_eocd(zip64_offset, locator_offset)
        end

        def zip64_placeholders?(fields)
          fields[:total_entries].value == 0xFFFF ||
            fields[:central_directory_size].value == 0xFFFFFFFF ||
            fields[:central_directory_offset].value == 0xFFFFFFFF
        end

        def parse_zip64_eocd(offset, locator_offset)
          return unless offset && offset + 56 <= @bytes.bytesize &&
                        signature_at?(offset, ZIP64_EOCD_SIG)

          report.store_zip64_geometry(
            total_entries: @bytes.byteslice(offset + 32, 8).unpack1('Q<'),
            central_directory_size: @bytes.byteslice(offset + 40, 8).unpack1('Q<'),
            central_directory_offset: @bytes.byteslice(offset + 48, 8).unpack1('Q<'),
            record_offset: offset,
            locator_offset: locator_offset
          )
        end
      end
    end
  end
end
