# encoding: BINARY

require 'mqtt/forensics/frame'

module MQTT
  module Forensics
    # Holds the two unidirectional byte streams (client->broker and
    # broker->client) and reassembles them into ordered Frames.
    #
    # A Capture is intentionally ignorant of MQTT session semantics: it only
    # knows how bytes were observed. It preserves every fragment so the
    # analyser can distinguish "not present in capture" from "proven absent".
    class Capture
      attr_reader :fragments

      def initialize
        @fragments = []
        @splitters = {
          :client => FrameSplitter.new(:client),
          :broker => FrameSplitter.new(:broker)
        }
      end

      # Add raw bytes for one direction. captured_at/source are optional and
      # only improve traceability; their absence is recorded, not invented.
      def add(direction, bytes, captured_at = nil, source = nil)
        fragment = Fragment.new(direction, bytes, captured_at, source)
        @fragments << fragment
        @splitters[direction].push(fragment)
        self
      end

      def add_fragment(fragment)
        @fragments << fragment
        @splitters[fragment.direction].push(fragment)
        self
      end

      # All reassembled frames in each direction's wire order.
      def frames
        @splitters[:client].flush
        @splitters[:broker].flush
        @splitters[:client].frames + @splitters[:broker].frames
      end

      def frames_by_direction(direction)
        @splitters[direction].flush
        @splitters[direction].frames
      end

      # Fragments observed on one direction, in arrival order. The index in
      # this array matches the fragment_index recorded in frame provenance.
      def fragments_by_direction(direction)
        @fragments.select { |f| f.direction == direction }
      end

      # Total raw bytes observed per direction (the captured universe).
      def byte_counts
        counts = { :client => 0, :broker => 0 }
        @fragments.each { |f| counts[f.direction] += f.bytesize }
        counts
      end

      # True when any fragment carries a wall-clock timestamp. When false the
      # report must not claim inter-packet timing it cannot prove.
      def timestamps?
        @fragments.any? { |f| !f.captured_at.nil? }
      end
    end
  end
end
