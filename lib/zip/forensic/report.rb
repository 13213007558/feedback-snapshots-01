# frozen_string_literal: true

require_relative 'report/text_formatter'

module Zip
  module Forensic
    # The result of a read-only forensic inspection. A report is deliberately
    # separate from {Zip::File}/{Zip::Entry}: opening a {Report} never creates
    # an EntrySet, never normalises names and never offers a way to extract or
    # repair data, so the ordinary decompression API keeps its existing
    # behaviour regardless of what an inspection finds.
    class Report
      attr_reader :source_path, :file_size, :sha256, :eocd,
                  :central_records, :local_headers, :anomalies, :regions,
                  :duplicate_names

      def initialize(source_path, file_size, sha256)
        @source_path     = source_path
        @file_size       = file_size
        @sha256          = sha256
        @eocd            = nil
        @zip64_geometry  = nil
        @central_records = []
        @local_headers   = []
        @anomalies       = []
        @regions         = []
        @duplicate_names = []
      end

      # Stores the parsed EOCD record. Used by the inspector while it walks the
      # archive; consumers read the frozen result through {#eocd}.
      def store_eocd(eocd)
        @eocd = eocd
      end

      # Stores the geometry taken from a Zip64 EOCD when the classic EOCD uses
      # the all-ones placeholders.
      def store_zip64_geometry(geometry)
        @zip64_geometry = geometry
      end

      # The Zip64 central-directory geometry, if any.
      def zip64_geometry
        @zip64_geometry
      end

      def anomaly?
        !@anomalies.empty?
      end

      # Every central record that shares its raw name bytes with at least one
      # other central record. These are the records that a name-keyed
      # EntrySet would collapse. The same groups are also emitted as
      # `duplicate_entry_name` anomalies so a single `#anomalies` scan surfaces
      # every finding.
      def compute_duplicate_names!
        buckets = @central_records.group_by { |rec| rec.name.raw }
        @duplicate_names = buckets.each_value.select { |bucket| bucket.size > 1 }
                                            .map { |bucket| duplicate_group(bucket) }
      end

      # A plain-data representation suitable for JSON/YAML serialisation.
      def to_h
        {
          source_path: source_path,
          file_size: file_size,
          sha256: sha256,
          eocd: eocd,
          central_records: central_records.map(&:to_h),
          local_headers: local_headers.map(&:to_h),
          duplicate_names: duplicate_names,
          anomalies: anomalies.map(&:to_h),
          unparsed_regions: regions.map(&:to_h)
        }
      end

      # A human-readable, offset-oriented rendering. The layout is meant to let
      # a reviewer walk the file byte range by byte range.
      def to_text
        TextFormatter.new(self).render
      end

      private

      def duplicate_group(bucket)
        group = {
          name_hex: Forensic.hex_bytes(bucket.first.name.raw),
          name_inspect: bucket.first.name.value.inspect,
          central_record_indexes: bucket.map(&:index),
          central_record_offsets:
            bucket.map { |rec| Forensic.hex_offset(rec.record_offset) },
          local_header_offsets:
            bucket.map { |rec| safe_hex(rec.effective_offset.value) }
        }
        flag_duplicate_name(bucket, group)
        group
      end

      def safe_hex(offset)
        offset.nil? ? nil : Forensic.hex_offset(offset)
      end

      def flag_duplicate_name(bucket, group)
        @anomalies << Anomaly.new(
          :duplicate_entry_name,
          "#{group[:name_inspect]} is declared by #{bucket.size} central " \
          'directory records; a name-keyed EntrySet would keep only the last one',
          { central_record_indexes: group[:central_record_indexes].map { |i| i + 1 },
            central_record_offsets: group[:central_record_offsets] },
          bucket.map(&:record_offset)
        )
      end
    end
  end
end
