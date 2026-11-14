# frozen_string_literal: true

module Zip
  module Forensic
    class Inspector
      # Establishes the correspondence between central directory records and
      # the independently scanned local headers, then checks for orphan local
      # headers and overlapping compressed-data ranges. A failed link is an
      # anomaly; no fallback entry is synthesized to hide it.
      module LinkAnalyzer
        private

        def link_records
          headers_by_offset = report.local_headers.group_by(&:header_offset)
          report.central_records.each do |record|
            target = record.effective_offset.value
            if target.nil?
              mark_unresolved_offset(record)
            else
              link_record(record, headers_by_offset[target], target)
            end
          end
          flag_orphan_headers
        end

        def mark_unresolved_offset(record)
          record.link_status = :unresolved_zip64_offset
          add_anomaly(:unresolved_local_header_offset,
                      "Central record ##{record.index + 1} " \
                      "(#{record.name.value.inspect}) declares a Zip64 local " \
                      'header offset that cannot be resolved',
                      { central_record: record.index + 1 }, [record.record_offset])
        end

        def link_record(record, matches, target)
          return mark_dangling_offset(record, target) if matches.nil?

          header = matches.first
          record.local_header = header
          record.link_status = :linked
          header.referenced_by << record.index
          resolve_streamed_data(header, record)
          flag_name_mismatch(record, header)
        end

        # Local headers streamed with data descriptors (general purpose bit 3)
        # carry zero sizes, so their payload span is unknown until the central
        # directory supplies it. Reconstruct the range from the central
        # record's compressed size and, when bit 3 is set, account for the
        # trailing 16-byte data descriptor.
        def resolve_streamed_data(header, record)
          return unless header.data_range.nil?

          data_start = header.header_offset + header.header_length
          compressed_size = record.fields[:compressed_size].value
          return if compressed_size.zero?

          header.data_range = data_start...(data_start + compressed_size)
          mark_data_descriptor(header, data_start + compressed_size) if
            (header.fields[:gp_flags].value & 8) == 8
        end

        def mark_data_descriptor(header, descriptor_start)
          descriptor = descriptor_start...(descriptor_start + 16)
          header.data_descriptor_range = descriptor
        end

        def mark_dangling_offset(record, target)
          record.link_status = :dangling_offset
          add_anomaly(:dangling_local_header_offset,
                      "Central record ##{record.index + 1} " \
                      "(#{record.name.value.inspect}) points at " \
                      "#{Forensic.hex_offset(target)} where no local header exists",
                      { central_record: record.index + 1,
                        declared_offset: Forensic.hex_offset(target) },
                      [record.effective_offset.offset, target])
        end

        def flag_name_mismatch(record, header)
          return if header.name.raw == record.name.raw

          add_anomaly(:local_central_name_mismatch,
                      "Central record ##{record.index + 1} and its local header " \
                      "##{header.index + 1} carry different raw name bytes",
                      { central_name: Forensic.hex_bytes(record.name.raw),
                        local_name: Forensic.hex_bytes(header.name.raw) },
                      [record.name.offset, header.name.offset])
        end

        def flag_orphan_headers
          report.local_headers.select(&:orphan?).each do |header|
            add_anomaly(:orphan_local_header,
                        "Local header ##{header.index + 1} at " \
                        "#{Forensic.hex_offset(header.header_offset)} " \
                        "(#{header.name.value.inspect}) is not referenced by any " \
                        'central directory record',
                        { local_header: header.index + 1 }, [header.header_offset])
          end
        end

        def detect_overlaps
          central_ranges = linked_central_ranges
          orphan_ranges = orphan_header_ranges
          detect_pairwise(central_ranges, :overlapping_data_ranges)
          detect_pairwise(orphan_ranges, :orphan_local_data_overlap)
          detect_cross(central_ranges, orphan_ranges)
        end

        def linked_central_ranges
          report.central_records.filter_map do |record|
            header = record.local_header
            next unless header&.data_range

            [record, header.data_start, header.data_end]
          end
        end

        def orphan_header_ranges
          report.local_headers.select(&:orphan?).filter_map do |header|
            next unless header.data_range

            [header, header.data_start, header.data_end]
          end
        end

        def detect_pairwise(ranges, type)
          ranges.combination(2) do |left, right|
            emit_overlap(type, left, right) if overlapping?(left, right)
          end
        end

        def detect_cross(central_ranges, orphan_ranges)
          central_ranges.each do |central|
            orphan_ranges.each do |orphan|
              emit_overlap(:orphan_local_data_overlap, central, orphan) if
                overlapping?(central, orphan)
            end
          end
        end

        def overlapping?(left, right)
          left[1] < right[2] && right[1] < left[2]
        end

        def emit_overlap(type, left, right)
          add_anomaly(type, 'Declared compressed data ranges overlap',
                      { left: span_label(left), right: span_label(right),
                        intersection: intersection_label(left, right) },
                      [left[1], right[1]])
        end

        def span_label(span)
          owner, start_offset, end_offset = span
          "#{owner_label(owner)} data #{Forensic.hex_offset(start_offset)}.." \
          "#{Forensic.hex_offset(end_offset)}"
        end

        def owner_label(owner)
          case owner
          when CentralRecord then "central record ##{owner.index + 1}"
          when LocalHeader then "local header ##{owner.index + 1}"
          else owner.to_s
          end
        end

        def intersection_label(left, right)
          start_offset = [left[1], right[1]].max
          end_offset = [left[2], right[2]].min
          "#{Forensic.hex_offset(start_offset)}..#{Forensic.hex_offset(end_offset)}"
        end
      end
    end
  end
end
