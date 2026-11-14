# encoding: BINARY

require 'mqtt'

module MQTT
  module Forensics
    # A direction-tagged chunk of raw bytes, exactly as captured from the wire.
    # No assumption is made that a fragment aligns with an MQTT packet
    # boundary: a packet may be split across several fragments and several
    # packets may share one fragment.
    class Fragment
      # :client or :broker
      attr_reader :direction

      # Raw bytes (ASCII-8BIT), never transcoded
      attr_reader :bytes

      # Optional capture timestamp (Float, seconds). nil when unknown.
      attr_reader :captured_at

      # Free-form source label used for traceability (file, offset, id)
      attr_reader :source

      def initialize(direction, bytes, captured_at = nil, source = nil)
        unless [:client, :broker].include?(direction)
          raise ArgumentError, "direction must be :client or :broker, got #{direction.inspect}"
        end

        @direction = direction
        @bytes = bytes.to_s.dup.force_encoding('ASCII-8BIT')
        @captured_at = captured_at
        @source = source
      end

      def bytesize
        @bytes.bytesize
      end
    end

    # One decoded MQTT control packet plus the provenance needed to trace it
    # back to the exact raw fragments that supplied its bytes.
    class Frame
      attr_reader :packet, :direction, :fragments, :byte_offset, :raw, :parse_error

      # packet       - a parsed MQTT::Packet (or nil for a malformed/truncated frame)
      # direction    - :client or :broker
      # fragments    - ordered Array of provenance Hashes:
      #                {fragment_index:, source:, start:, length:}
      # byte_offset  - absolute offset of the frame within its direction stream
      # raw          - the exact bytes consumed for the frame (may be partial)
      # parse_error  - String explaining why the packet could not be fully parsed
      def initialize(packet, direction, fragments, byte_offset, raw, parse_error = nil)
        @packet = packet
        @direction = direction
        @fragments = fragments
        @raw = raw
        @byte_offset = byte_offset
        @parse_error = parse_error
      end

      def type_name
        @packet.nil? ? 'MALFORMED' : @packet.type_name
      end

      def parse_error?
        !@parse_error.nil?
      end

      def complete?
        !parse_error?
      end

      # Stable identifier used throughout the report for cross-reference.
      def ref
        "#{@direction.to_s[0].upcase}F#{'%04d' % @byte_offset}"
      end
    end

    # Incrementally reassembles MQTT control packets from a continuous byte
    # stream per direction, surviving arbitrary fragmentation and truncation.
    #
    # The splitter never discards bytes silently. Anything that cannot be
    # turned into a complete, valid frame is emitted as a MALFORMED Frame with
    # an explanatory parse_error, so capture defects stay visible instead of
    # being misread as protocol behaviour.
    class FrameSplitter
      # Maximum permitted value of the MQTT remaining-length field (4 bytes).
      MAX_REMAINING_LENGTH = 268_435_455

      def initialize(direction)
        unless [:client, :broker].include?(direction)
          raise ArgumentError, "direction must be :client or :broker, got #{direction.inspect}"
        end

        @direction = direction
        @buffer = ''.b
        @offset = 0
        # Provenance for the bytes currently in the buffer, each entry a Hash:
        #   {fragment_index:, source:, start:, length:}
        @provenance = []
        @frames = []
        @fragment_counter = 0
      end

      # All frames decoded so far, in wire order. Call flush first to surface
      # any truncated trailing bytes.
      attr_reader :frames

      # Append one Fragment. Returns the frames that became decodable as a
      # result, in wire order.
      def push(fragment)
        unless fragment.bytes.empty?
          @buffer << fragment.bytes
          @provenance << {
            :fragment_index => @fragment_counter,
            :source => fragment.source,
            :start => 0,
            :length => fragment.bytesize
          }
          @fragment_counter += 1
        end
        drain
      end

      # Signal end of capture. A non-empty residual buffer means the stream
      # was truncated in the middle of a frame; emit it as evidence rather
      # than dropping it.
      def flush
        if @buffer.bytesize.positive?
          register(emit_malformed("truncated stream: #{@buffer.bytesize} byte(s) with no complete frame " \
                                  '(capture ends mid-packet or remaining-length is larger than captured body)'))
        end
        @frames
      end

      private

      def drain
        produced = []
        loop do
          frame = try_frame
          break if frame.nil?

          # try_frame (via emit_malformed or the parse path) has already
          # registered the frame in @frames; here we only collect what became
          # newly decodable so #push can return it.
          produced << frame
        end
        produced
      end

      def try_frame
        return nil if @buffer.bytesize < 2

        type_id = (@buffer.getbyte(0) & 0xF0) >> 4
        unless type_id.between?(1, 14)
          # Illegal/reserved control packet type (0 and 15 are forbidden).
          return register(emit_malformed("reserved/forbidden control packet type #{type_id} " \
                                         "(first byte 0x%02X)" % @buffer.getbyte(0)))
        end

        length, header_size, length_error = read_remaining_length
        if length_error
          return register(emit_malformed(length_error)) unless length_error == :incomplete

          return nil # wait for more length bytes / body
        end

        total = header_size + length
        return nil if @buffer.bytesize < total # whole frame not arrived yet

        raw = @buffer.byteslice(0, total)
        provenance = slice_provenance(total)
        consume(total)
        register(parse_frame(type_id, raw, provenance))
      end

      # Single place that records a decoded frame, keeping @frames in sync with
      # the frames returned by #push/#flush.
      def register(frame)
        @frames << frame
        frame
      end

      # Returns [length, header_size, error].
      # error is nil on success, :incomplete if more bytes are needed, or a
      # String describing an invalid encoding.
      def read_remaining_length
        multiplier = 1
        value = 0
        pos = 1
        loop do
          return [0, pos, :incomplete] if @buffer.bytesize <= pos

          digit = @buffer.getbyte(pos)
          value += (digit & 0x7F) * multiplier
          pos += 1
          if (digit & 0x80).zero?
            return [value, pos, nil]
          end
          if pos > 4
            return [0, pos, 'malformed remaining-length: continuation bit set on a 5th byte']
          end
          if multiplier == 128 * 128 * 128 && (digit & 0x7F) > 0
            return [0, pos, 'malformed remaining-length: value exceeds 268435455']
          end

          multiplier *= 128
        end
      end

      def parse_frame(type_id, raw, provenance)
        packet = MQTT::Packet.parse(raw.dup)
        Frame.new(packet, current_direction, provenance, frame_offset(raw), raw)
      rescue MQTT::ProtocolException, StandardError => e
        Frame.new(nil, current_direction, provenance, frame_offset(raw), raw,
                  "#{e.class.name.split('::').last}: #{e.message}")
      end

      def frame_offset(raw)
        @offset - raw.bytesize
      end

      def current_direction
        @direction
      end

      def consume(count)
        @buffer.slice!(0, count)
        @provenance = drop_provenance(count)
        @offset += count
      end

      # Remove `count` bytes worth of provenance entries, splitting the entry
      # that straddles the boundary so retained bytes keep accurate offsets.
      def drop_provenance(count)
        remaining = count
        kept = []
        @provenance.each do |entry|
          len = entry[:length]
          if remaining >= len
            remaining -= len
          else
            split = entry.dup
            split[:start] += remaining
            split[:length] = len - remaining
            kept << split
            remaining = 0
          end
        end
        kept
      end

      def slice_provenance(count)
        wanted = count
        result = []
        @provenance.each do |entry|
          break if wanted <= 0

          take = [entry[:length], wanted].min
          result << entry.merge(:length => take)
          wanted -= take
        end
        result
      end

      def emit_malformed(message)
        raw = @buffer.dup
        provenance = slice_provenance(@buffer.bytesize)
        offset = @offset
        frame = Frame.new(nil, current_direction, provenance, offset, raw, message)
        @buffer = ''.b
        @provenance = []
        @offset += raw.bytesize
        frame
      end
    end
  end
end
