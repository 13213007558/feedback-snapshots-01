# frozen_string_literal: true

module Zip
  module Forensic
    class Inspector
      # Walks the central directory sequentially from the offset declared in
      # the EOCD (or Zip64 EOCD). Records are kept in on-disk order; no name
      # keying happens here, so duplicate names survive intact.
      module CentralScanner
        CENTRAL_LAYOUT = [
          [:signature, 0, 'V'], [:version_made_by, 4, 'v'],
          [:version_needed, 6, 'v'], [:gp_flags, 8, 'v'],
          [:compression_method, 10, 'v'], [:mod_time, 12, 'v'],
          [:mod_date, 14, 'v'], [:crc32, 16, 'V'],
          [:compressed_size, 20, 'V'], [:uncompressed_size, 24, 'V'],
          [:name_length, 28, 'v'], [:extra_length, 30, 'v'],
          [:comment_length, 32, 'v'], [:disk_number_start, 34, 'v'],
          [:internal_attributes, 36, 'v'], [:external_attributes, 38, 'V'],
          [:local_header_offset, 42, 'V']
        ].freeze

        private

        def scan_central_directory
          geometry = central_geometry
          return unless geometry

          walk_central_records(geometry)
          verify_central_count(geometry[:total_entries])
        end

        def walk_central_records(geometry)
          offset = geometry[:central_directory_offset]
          geometry[:total_entries].times do |index|
            record = parse_central_record(offset, index)
            break unless record

            report.central_records << record
            offset += record.record_length
          end
        end

        def verify_central_count(declared)
          return if report.central_records.size == declared

          add_anomaly(:central_entry_count_mismatch,
                      'Number of central directory records found does not match ' \
                      'the count declared in the EOCD',
                      { declared: declared, found: report.central_records.size }, [])
        end

        def parse_central_record(offset, index)
          unless signature_at?(offset, CENTRAL_SIG)
            add_anomaly(:central_directory_interrupted,
                        'Expected a central directory signature but found another ' \
                        'structure; remaining declared records were not parsed',
                        { expected_record_index: index + 1 }, [offset])
            return nil
          end
          return truncated_central(offset, index) unless
            offset + STATIC_CENTRAL_SIZE <= @bytes.bytesize

          build_central_record(offset, index)
        end

        def truncated_central(offset, index)
          add_anomaly(:central_record_truncated,
                      "Central directory record ##{index + 1} is truncated by end of file",
                      {}, [offset])
          nil
        end

        def build_central_record(offset, index)
          source = "central directory record ##{index + 1}"
          fields = unpack_fields(offset, CENTRAL_LAYOUT, source)
          name = read_name_span(offset + STATIC_CENTRAL_SIZE,
                                fields[:name_length].value, source)
          extra = safe_span(name.offset + name.length, fields[:extra_length].value)
          comment = safe_span(extra.offset + extra.length,
                              fields[:comment_length].value)
          record_length = STATIC_CENTRAL_SIZE + name.length +
                          extra.length + comment.length
          effective_offset = resolve_central_offset(fields, extra, offset)
          CentralRecord.new(index, offset, record_length, fields, name, extra,
                            comment, effective_offset)
        end

        # The local header offset comes from the static central header unless
        # the 0xFFFFFFFF placeholder is used, in which case it is taken from
        # the Zip64 extra field. The provenance string records which bytes won.
        def resolve_central_offset(fields, extra, record_offset)
          static_field = fields[:local_header_offset]
          return static_field unless static_field.value == 0xFFFFFFFF

          relative_offset = zip64_relative_offset_location(extra)
          return unresolved_placeholder(static_field) unless relative_offset

          raw = extra.raw.byteslice(relative_offset, 8)
          Field.new(raw.unpack1('Q<'), raw, extra.offset + relative_offset,
                    "Zip64 extra field of central record #{Forensic.hex_offset(record_offset)}")
        end

        def unresolved_placeholder(static_field)
          Field.new(nil, static_field.raw, static_field.offset,
                    'central static header local_header_offset ' \
                    '(0xFFFFFFFF placeholder, no Zip64 extra field)')
        end

        # Minimal Zip64 extra parser returning the position of the relative
        # header offset inside the extra field blob. The classic header's
        # uncompressed size, compressed size and disk number placeholders
        # determine how many 8-byte fields precede it.
        def zip64_relative_offset_location(extra)
          blob = extra.raw
          pos = 0
          while pos + 4 <= blob.bytesize
            break unless blob.byteslice(pos, 2) == ["0100"].pack('H*')

            data_size = blob.byteslice(pos + 2, 2).unpack1('v')
            data_pos = pos + 4
            consumed = zip64_field_count(blob, data_pos, data_size)
            return data_pos + consumed if data_size >= consumed + 8

            break
          end
          nil
        end

        def zip64_field_count(blob, data_pos, data_size)
          consumed = 0
          if data_size >= 8 && blob.byteslice(data_pos, 8).unpack1('Q<') == 0xFFFFFFFF
            consumed += 8
          end
          if data_size >= 16 && blob.byteslice(data_pos + 8, 8).unpack1('Q<') == 0xFFFFFFFF
            consumed += 8
          end
          if data_size >= 24 && blob.byteslice(data_pos + 16, 8).unpack1('Q<') == 0xFFFF
            consumed += 4
          end
          consumed
        end
      end
    end
  end
end
