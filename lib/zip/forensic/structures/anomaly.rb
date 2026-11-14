# frozen_string_literal: true

module Zip
  module Forensic
    # Something in the archive that does not match the expectations of the
    # ZIP specification. Anomalies are observations only; the inspector never
    # guesses how a malformed record should have looked.
    class Anomaly
      attr_reader :type, :message, :details, :offsets

      def initialize(type, message, details = {}, offsets = [])
        @type    = type
        @message = message
        @details = details
        @offsets = offsets
      end

      def to_h
        {
          type: type, message: message, details: details,
          hex_offsets: offsets.map { |off| Forensic.hex_offset(off) }
        }
      end
    end
  end
end
