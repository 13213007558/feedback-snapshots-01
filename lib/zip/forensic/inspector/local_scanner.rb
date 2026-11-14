# frozen_string_literal: true

module Zip
  module Forensic
    class Inspector
      # Scans the bytes preceding the central directory for local file header
      # signatures. This scan is independent of the central directory, which is
      # what allows local headers that no central record points at (orphans)
      # to be discovered. Candidate signatures are sanity-checked so that a
      # signature appearing inside file data is not mistaken for a header.
      module LocalScanner
        LOCAL_LAYOUT = [
          [:signature, 0, 'V'], [:version_needed, 4, 'v'],
          [:gp_flags, 6, 'v'], [:compression_method, 8, 'v'],
          [:mod_time, 10, 'v'], [:mod_date, 12, 'v'], [:crc32, 14, 'V'],
          [:compressed_size, 18, 'V'], [:uncompressed_size, 22, 'V'],
          [:name_length, 26, 'v'], [:extra_length, 28, 'v']
        ].freeze

        private

        def scan_local_headers
          local_signature_positions.each do |position|
            header = parse_local_header(position)
            report.local_headers << header if header
          end
          report.local_headers.each_with_index { |header, index| header.index = index }
        end

        def local_signature_positions
          limit = central_geometry&.dig(:central_directory_offset) || @bytes.bytesize
          search_area = @bytes.byteslice(0, limit)
          signature = [LOCAL_SIG].pack('V')
          positions = []
          covered_until = 0
          position = 0
          while (found = search_area.index(signature, position))
            if plausible_local_header?(found, limit, covered_until)
              positions << found
              covered_until = [covered_until, header_span(found, limit)].max
            end
            position = found + 4
          end
          positions
        end

        def plausible_local_header?(offset, limit, covered_until)
          return false unless offset + STATIC_LOCAL_SIZE <= limit
          return false if offset < covered_until # inside an accepted header/payload

          name_length = @bytes.byteslice(offset + 26, 2).unpack1('v')
          extra_length = @bytes.byteslice(offset + 28, 2).unpack1('v')
          header_end = offset + STATIC_LOCAL_SIZE + name_length + extra_length
          name_length.positive? && header_end <= limit
        end

        # The byte just past the header starting at `start`, using its declared
        # name, extra and (non-Zip64) compressed sizes. A signature inside that
        # span is data, not another header.
        def header_span(start, limit)
          name_length = @bytes.byteslice(start + 26, 2).unpack1('v')
          extra_length = @bytes.byteslice(start + 28, 2).unpack1('v')
          compressed = @bytes.byteslice(start + 18, 4).unpack1('V')
          compressed = 0 if compressed == 0xFFFFFFFF
          [start + STATIC_LOCAL_SIZE + name_length + extra_length + compressed, limit].min
        end

        def parse_local_header(offset)
          unless offset + STATIC_LOCAL_SIZE <= @bytes.bytesize
            add_anomaly(:local_header_truncated,
                        "Local header signature at #{Forensic.hex_offset(offset)} is truncated",
                        {}, [offset])
            return nil
          end
          source = "local header #{Forensic.hex_offset(offset)}"
          fields = unpack_fields(offset, LOCAL_LAYOUT, source)
          unless fields[:signature].value == LOCAL_SIG
            add_anomaly(:local_header_bad_signature,
                        "Bytes at #{Forensic.hex_offset(offset)} are not a local header",
                        {}, [offset])
            return nil
          end
          build_local_header(fields, offset, source)
        end

        def build_local_header(fields, offset, source)
          name = read_name_span(offset + STATIC_LOCAL_SIZE,
                                fields[:name_length].value, source)
          extra = safe_span(name.offset + name.length, fields[:extra_length].value)
          header_length = STATIC_LOCAL_SIZE + name.length + extra.length
          data_start = offset + header_length
          compressed_size = effective_compressed_size(fields, extra)
          data_range = compressed_size.zero? ? nil : data_start...(data_start + compressed_size)
          LocalHeader.new(offset, header_length, fields, name, extra, data_range)
        end

        # Local headers of small Zip64-enabled archives carry 0xFFFFFFFF in the
        # static size fields, with the real sizes first in the Zip64 extra
        # field. Without resolving them the data ranges would span gigabytes
        # and produce false overlaps.
        def effective_compressed_size(fields, extra)
          static_size = fields[:compressed_size].value
          return static_size unless static_size == 0xFFFFFFFF

          zip64_sizes(extra)&.fetch(:compressed_size, static_size) || static_size
        end

        # Returns the uncompressed/compressed sizes from a Zip64 extra field
        # when both static placeholders are present, otherwise nil.
        def zip64_sizes(extra)
          blob = extra.raw
          return nil unless blob.bytesize >= 4 &&
                            blob.byteslice(0, 2) == ["0100"].pack('H*')

          data_size = blob.byteslice(2, 2).unpack1('v')
          return nil unless data_size >= 16 && blob.bytesize >= 20

          {
            uncompressed_size: blob.byteslice(4, 8).unpack1('Q<'),
            compressed_size: blob.byteslice(12, 8).unpack1('Q<')
          }
        end
      end
    end
  end
end
