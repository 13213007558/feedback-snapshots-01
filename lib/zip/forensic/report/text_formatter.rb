# frozen_string_literal: true

module Zip
  module Forensic
    class Report
      # Renders a {Report} as a human-readable, offset-oriented text document.
      # Each section mirrors one phase of the inspection so a reviewer can
      # walk the archive byte range by byte range.
      class TextFormatter
        def initialize(report)
          @report = report
        end

        def render
          lines = []
          render_header(lines)
          render_eocd(lines)
          render_central_records(lines)
          render_duplicate_names(lines)
          render_local_headers(lines)
          render_anomalies(lines)
          render_regions(lines)
          lines.join("\n")
        end

        private

        def render_header(lines)
          lines << 'Zip forensic structure inspection (read-only)'
          lines << "source: #{@report.source_path || '(in-memory IO)'}"
          lines << "file size: #{@report.file_size} bytes " \
                   "(#{Forensic.hex_offset(@report.file_size)})"
          lines << "sha256: #{@report.sha256}"
        end

        def render_eocd(lines)
          lines << '' << 'End of central directory'
          return lines << '  (not found)' unless @report.eocd

          @report.eocd[:fields].each_value { |field| lines << "  #{field}" }
        end

        def render_central_records(lines)
          lines << '' << "Central directory records " \
                         "(#{@report.central_records.size}, in on-disk order)"
          @report.central_records.each { |record| render_central_record(lines, record) }
        end

        def render_central_record(lines, record)
          lines << "  record ##{record.index + 1} " \
                   "#{Forensic.hex_offset(record.record_offset)} " \
                   "(#{record.record_length} bytes): " \
                   "name=#{record.name.value.inspect} " \
                   "name_bytes=#{Forensic.hex_bytes(record.name.raw)}"
          record.fields.each_value { |field| lines << "    #{field}" }
          render_central_spans(lines, record)
          linked = record.local_header&.index&.then { |i| i + 1 } || '-'
          lines << "    local header link: #{record.link_status} " \
                   "(local header ##{linked})"
        end

        def render_central_spans(lines, record)
          lines << "    raw name:        #{record.name.byte_range} " \
                   "#{Forensic.hex_bytes(record.name.raw)}"
          if record.extra&.length&.positive?
            lines << "    raw extra field: #{record.extra.byte_range} " \
                     "#{Forensic.hex_bytes(record.extra.raw)}"
          end
          return unless record.comment&.length&.positive?

          lines << "    raw comment:     #{record.comment.byte_range} " \
                   "#{Forensic.hex_bytes(record.comment.raw)}"
        end

        def render_duplicate_names(lines)
          lines << '' << "Duplicate names (#{@report.duplicate_names.size} name group(s))"
          @report.duplicate_names.each { |dup| render_duplicate(lines, dup) }
        end

        def render_duplicate(lines, dup)
          indexes = dup[:central_record_indexes].map { |i| i + 1 }.inspect
          lines << "  #{dup[:name_inspect]} (#{dup[:name_hex]}) appears in central " \
                   "records #{indexes} at #{dup[:central_record_offsets].join(', ')}"
        end

        def render_local_headers(lines)
          lines << '' << "Local file headers " \
                         "(#{@report.local_headers.size}, in on-disk order)"
          @report.local_headers.each { |header| render_local_header(lines, header) }
        end

        def render_local_header(lines, header)
          lines << "  local header ##{header.index + 1} " \
                   "#{Forensic.hex_offset(header.header_offset)} " \
                   "(#{header.header_length} bytes): " \
                   "name=#{header.name.value.inspect} " \
                   "name_bytes=#{Forensic.hex_bytes(header.name.raw)}"
          header.fields.each_value { |field| lines << "    #{field}" }
          render_local_spans(lines, header)
          render_local_link(lines, header)
        end

        def render_local_spans(lines, header)
          lines << "    raw name:        #{header.name.byte_range} " \
                   "#{Forensic.hex_bytes(header.name.raw)}"
          if header.extra&.length&.positive?
            lines << "    raw extra field: #{header.extra.byte_range} " \
                     "#{Forensic.hex_bytes(header.extra.raw)}"
          end
          return unless header.data_range

          lines << "    data range:      #{Forensic.hex_offset(header.data_start)}.." \
                   "#{Forensic.hex_offset(header.data_end)} " \
                   "(#{header.data_end - header.data_start} bytes)"
        end

        def render_local_link(lines, header)
          references = header.referenced_by.map { |i| i + 1 }.inspect
          lines << "    referenced by central records: #{references}"
          lines << '    ORPHAN local header' if header.orphan?
          lines << "    parse error: #{header.parse_error}" unless header.valid
        end

        def render_anomalies(lines)
          lines << '' << "Anomalies (#{@report.anomalies.size})"
          @report.anomalies.each { |anomaly| render_anomaly(lines, anomaly) }
        end

        def render_anomaly(lines, anomaly)
          lines << "  [#{anomaly.type}] #{anomaly.message}"
          offsets = anomaly.offsets.map { |off| Forensic.hex_offset(off) }.join(', ')
          lines << "      at: #{offsets}" unless offsets.empty?
          anomaly.details.each { |key, value| lines << "      #{key}: #{value}" }
        end

        def render_regions(lines)
          lines << '' << "Unparsed byte regions (#{@report.regions.size}) " \
                         '- not interpreted as entries'
          @report.regions.each { |region| render_region(lines, region) }
        end

        def render_region(lines, region)
          stop = Forensic.hex_offset(region.offset + region.length)
          lines << "  [#{region.kind}] #{Forensic.hex_offset(region.offset)}..#{stop} " \
                   "(#{region.length} bytes) #{region.note}".rstrip
          lines << "      preview: #{Forensic.hex_bytes(region.preview)}"
        end
      end
    end
  end
end
