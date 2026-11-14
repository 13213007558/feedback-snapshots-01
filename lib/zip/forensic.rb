# frozen_string_literal: true

require_relative '../zip'
require_relative 'forensic/field'
require_relative 'forensic/structures'
require_relative 'forensic/report'
require_relative 'forensic/inspector'

module Zip
  # A read-only, forensic-oriented view over ZIP archives.
  #
  # Unlike {Zip::File}, this module never builds an {EntrySet}, never treats
  # an entry name as a unique key, and offers no extraction or repair
  # facilities. It exists to examine archives that may contain deliberately
  # hidden or malformed records - duplicate names, dangling or misaligned local
  # header offsets, orphan local headers, overlapping data ranges and trailing
  # or interstitial bytes - while preserving the exact byte offsets and raw
  # bytes needed to independently verify every finding.
  #
  # The ordinary decompression APIs ({Zip::File}, {Zip::InputStream}) are
  # untouched by an inspection: nothing here mutates their state or their
  # interpretation of an archive.
  #
  # @example Inspect a file on disk
  #   require 'zip/forensic'
  #
  #   report = Zip::Forensic.inspect('suspicious.zip')
  #   puts report.to_text
  #   report.anomalies.each { |anomaly| puts anomaly.type }
  module Forensic
    module_function

    # Runs a read-only structural inspection against a file path, an IO-like
    # object, or the raw archive bytes as a binary String. The source is never
    # written to; an IO object is returned to its original position.
    #
    # @param path_or_io [String, IO] a filesystem path, an open IO, or raw
    #   archive bytes. Strings containing a NUL byte are always treated as raw
    #   bytes rather than paths.
    # @return [Report] the structural findings.
    def inspect(path_or_io)
      Inspector.inspect(path_or_io)
    end

    # Formats an absolute byte offset as a fixed-width hexadecimal string with
    # an `@` prefix, for example `@0x0042`.
    def hex_offset(offset)
      format('@0x%04x', offset)
    end

    # Renders raw bytes as space-separated uppercase hexadecimal pairs,
    # truncating anything longer than 16 bytes so reports stay readable. The
    # full bytes remain available on the report objects.
    def hex_bytes(bytes)
      hex = bytes.bytes.map { |byte| format('%02X', byte) }
      shown = hex.size > 16 ? hex.first(16) + ['...'] : hex
      shown.join(' ')
    end
  end
end
