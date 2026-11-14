# frozen_string_literal: true

module Zip
  module Forensic
    class Inspector
      # Builds an explicit list of byte ranges that the inspection does not
      # interpret as zip structures: preamble bytes, gaps between parsed
      # structures, and bytes trailing the EOCD. Every gap between parsed
      # structures and every trailing region is surfaced, including zero
      # metadata about their meaning, so reviewers know what was not parsed.
      module RegionMapper
        private

        def map_unparsed_regions
          spans = known_spans.sort_by(&:first)
          cursor = 0
          spans.each do |start_offset, end_offset|
            add_region(cursor, start_offset, cursor.zero? ? :preamble : :gap) if
              start_offset > cursor
            cursor = [cursor, end_offset].max
          end
          add_region(cursor, @bytes.bytesize, :trailing) if cursor < @bytes.bytesize
        end

        def known_spans
          spans = []
          report.local_headers.each do |header|
            end_offset = header.data_end || header.header_offset + header.header_length
            spans << [header.header_offset, end_offset]
            if header.data_descriptor?
              spans << [header.data_descriptor_range.first,
                        header.data_descriptor_range.last]
            end
          end
          report.central_records.each do |record|
            spans << [record.record_offset, record.record_offset + record.record_length]
          end
          if report.eocd
            end_offset = report.eocd[:offset] + STATIC_EOCD_SIZE +
                         report.eocd[:comment_length]
            spans << [report.eocd[:offset], end_offset]
          end
          if report.zip64_geometry
            geometry = report.zip64_geometry
            spans << [geometry[:record_offset], geometry[:record_offset] + 56]
            if geometry[:locator_offset]
              spans << [geometry[:locator_offset], geometry[:locator_offset] + 20]
            end
          end
          spans.reject { |start_offset, _end| start_offset >= @bytes.bytesize }
        end

        def add_region(start_offset, end_offset, kind)
          length = end_offset - start_offset
          report.regions << Region.new(
            kind, start_offset, length,
            slice_preview(start_offset, length), note: region_note(kind)
          )
        end

        def region_note(kind)
          case kind
          when :preamble then 'bytes before the first zip structure'
          when :trailing then 'bytes after the end of central directory'
          else 'bytes between parsed structures'
          end
        end
      end
    end
  end
end
