# encoding: utf-8
# frozen_string_literal: true

module Mail
  module Security
    # A single byte range that could not be explained by the declared
    # transfer encoding or character set.
    #
    # +stage+ is either +:transfer_encoding+ or +:charset+ and identifies the
    # decoding stage that rejected the bytes. +offset+ counts raw bytes from
    # the start of the stage input (the body raw source for the transfer
    # encoding stage, and the transfer-decoded bytes for the charset stage).
    # +bytes+ holds the exact, unmodified octets so a scanner can inspect what
    # a tolerant decoder would have replaced or dropped.
    class Issue
      attr_reader :stage, :reason, :offset, :bytes, :message

      def initialize(stage:, reason:, offset:, bytes:, message: nil)
        @stage = stage
        @reason = reason
        @offset = offset
        @bytes = bytes.to_s.dup.force_encoding(Encoding::ASCII_8BIT)
        @message = message
      end

      def end_offset
        offset + bytes.bytesize
      end

      def byte_offset_range
        offset...end_offset
      end

      def hex_bytes
        bytes.bytes.map { |octet| format('%02X', octet) }.join(' ')
      end

      def to_h
        {
          stage: stage,
          reason: reason,
          offset: offset,
          bytes: bytes,
          hex_bytes: hex_bytes,
          message: message
        }
      end

      def to_s
        location = "#{stage} byte #{offset}"
        location += "-#{end_offset - 1}" if bytes.bytesize > 1
        "#{reason} at #{location}: #{hex_bytes}#{" (#{message})" if message}"
      end
    end
  end
end
