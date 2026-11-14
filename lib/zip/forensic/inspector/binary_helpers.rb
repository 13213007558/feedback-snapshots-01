# frozen_string_literal: true

module Zip
  module Forensic
    class Inspector
      # Byte-level parsing helpers shared by the scanning phases. All offsets
      # are absolute positions in the archive and every interpreted value is
      # kept paired with its raw bytes in a {Field}.
      module BinaryHelpers
        private

        def unpack_fields(base_offset, layout, source)
          layout.each_with_object({}) do |(name, relative_offset, directive), fields|
            raw = @bytes.byteslice(base_offset + relative_offset,
                                   directive_size(directive))
            fields[name] = Field.new(raw.unpack1(directive), raw,
                                     base_offset + relative_offset, source)
          end
        end

        def directive_size(directive)
          directive == 'V' ? 4 : 2
        end

        def signature_at?(offset, signature)
          @bytes.byteslice(offset, 4)&.unpack1('V') == signature
        end

        def rindex_signature(string, signature)
          string.rindex([signature].pack('V'))
        end

        def read_name_span(offset, length, source)
          raw = @bytes.byteslice(offset, length) || ''.b
          Field.new(decode_name(raw), raw, offset, "#{source} name")
        end

        def safe_span(offset, length)
          RawSpan.new(offset, @bytes.byteslice(offset, length) || ''.b)
        end

        def decode_name(raw)
          name = raw.dup
          if ::Zip.force_entry_names_encoding
            name.force_encoding(::Zip.force_entry_names_encoding)
          end
          name.tr('\\', '/')
        end

        def slice_preview(offset, length)
          @bytes.byteslice(offset, [length, Inspector::REGION_PREVIEW_SIZE].min) || ''.b
        end

        def central_geometry
          report.zip64_geometry || eocd_geometry
        end

        def eocd_geometry
          return nil unless report.eocd

          {
            total_entries: report.eocd[:total_entries],
            central_directory_size: report.eocd[:central_directory_size],
            central_directory_offset: report.eocd[:central_directory_offset]
          }
        end
      end
    end
  end
end
