# frozen_string_literal: true

require 'digest'

require_relative 'inspector/eocd_scanner'
require_relative 'inspector/central_scanner'
require_relative 'inspector/local_scanner'
require_relative 'inspector/link_analyzer'
require_relative 'inspector/region_mapper'
require_relative 'inspector/binary_helpers'

module Zip
  module Forensic
    # Read-only structural inspector for ZIP archives.
    #
    # The inspector walks the raw bytes of an archive without building any
    # {Zip::Entry} objects and without consulting {Zip::EntrySet}. It preserves
    # the on-disk order of central directory records, the original bytes of
    # every name, every declared offset and the correspondence between central
    # records and local headers. Anything that cannot be confirmed is reported
    # as an anomaly or an unparsed region rather than repaired.
    class Inspector
      include BinaryHelpers
      include EocdScanner
      include CentralScanner
      include LocalScanner
      include LinkAnalyzer
      include RegionMapper

      LOCAL_SIG           = 0x04034b50
      CENTRAL_SIG         = 0x02014b50
      EOCD_SIG            = 0x06054b50
      ZIP64_EOCD_SIG      = 0x06064b50
      ZIP64_LOCATOR_SIG   = 0x07064b50
      STATIC_EOCD_SIZE    = 22
      STATIC_CENTRAL_SIZE = 46
      STATIC_LOCAL_SIZE   = 30
      MAX_EOCD_SCAN       = 65_557
      REGION_PREVIEW_SIZE = 32

      def self.inspect(path_or_io)
        new.inspect(path_or_io)
      end

      # Performs the inspection. The argument is opened for reading only and is
      # never written to; when an IO-like object is passed its position is
      # restored before the method returns.
      def inspect(path_or_io)
        bytes, source_path = read_all_bytes(path_or_io)
        @report = Report.new(source_path, bytes.bytesize,
                             Digest::SHA256.hexdigest(bytes))
        @bytes = bytes
        scan_eocd
        scan_central_directory
        scan_local_headers
        link_records
        detect_overlaps
        map_unparsed_regions
        @report.compute_duplicate_names!
        @report
      ensure
        @bytes = nil
        @report = nil
      end

      private

      def report
        @report
      end

      def read_all_bytes(path_or_io)
        if path_or_io.kind_of?(::String) && likely_path?(path_or_io)
          [::File.binread(path_or_io), path_or_io]
        elsif io_like?(path_or_io)
          read_from_io(path_or_io)
        else
          # Treat the argument as raw archive bytes. Wrapping it in a StringIO
          # keeps the inspection strictly in memory and never writes a file.
          read_from_io(::StringIO.new(path_or_io.to_s))
        end
      end

      # A real filesystem path never contains a NUL byte; a binary archive
      # almost always does (its signatures do), so this distinguishes the two
      # when a plain String is passed in.
      def likely_path?(string)
        !string.include?("\0") && ::File.exist?(string)
      end

      def io_like?(object)
        object.respond_to?(:read) && object.respond_to?(:seek)
      end

      def read_from_io(io)
        saved_position = io.tell
        io.seek(0, IO::SEEK_SET)
        bytes = io.read.dup
        io.seek(saved_position, IO::SEEK_SET)
        [bytes, io.respond_to?(:path) ? io.path : nil]
      end

      def add_anomaly(type, message, details = {}, offsets = [])
        report.anomalies << Anomaly.new(type, message, details, offsets)
      end
    end
  end
end
