# encoding: utf-8
# frozen_string_literal: true
require 'digest'

module Mail
  # = Raw Evidence
  #
  # Mail::RawEvidence maps the parsed structure of a message back onto the
  # exact bytes that were received, without re-encoding, re-folding or
  # normalising line endings.
  #
  # Every range stored by this object is an absolute, half-open byte range
  # (+start_offset...end_offset+) into the frozen, untouched source string.
  # Ranges never overlap and nothing is ever synthesised: a missing closing
  # boundary, a synthesised header or a part added after parsing simply has no
  # evidence range.
  #
  # The evidence is a point-in-time snapshot.  Mutating the message (changing a
  # header, the body or its parts) does not alter the recorded bytes, but makes
  # #current? return false so that the old evidence can be distinguished from
  # the new content.
  class RawEvidence

    # A single, non-overlapping byte region of the received source.
    class Node
      # Symbolic kind of the region, e.g. +:message+, +:header+, +:field+,
      # +:body+, +:part+, +:boundary+, +:preamble+, +:epilogue+.
      attr_reader :kind

      # Absolute, half-open byte range into the root source string.
      attr_reader :start_offset, :end_offset

      # Header field name (down-cased) when +kind == :field+, otherwise nil.
      attr_reader :name

      # A Mail::RawEvidence for the region's own children (for +:message+,
      # +:body+ and +:part+ nodes), or nil for leaf regions.
      attr_reader :evidence

      # True when this region is anchored to real source bytes.  A synthesised
      # node (for example a part fabricated when a closing boundary is
      # missing) is never anchored and carries no usable range.
      attr_reader :anchored

      def initialize(kind, start_offset, end_offset, name: nil, evidence: nil, anchored: true)
        @kind = kind
        @start_offset = start_offset
        @end_offset = end_offset
        @name = name
        @evidence = evidence
        @anchored = anchored
        freeze
      end

      def anchored?
        @anchored
      end

      # The exact bytes of this region, sliced from +root_source+.  Returns
      # nil for a node that is not anchored to any received bytes.
      def bytes(root_source)
        return nil unless anchored?
        root_source.byteslice(start_offset, end_offset - start_offset)
      end

      # Absolute, half-open range of this region.
      def range
        start_offset...end_offset
      end

      def inspect
        suffix = name ? " #{name.inspect}" : nil
        "#<#{self.class.name} #{kind}#{suffix} #{start_offset}...#{end_offset}#{anchored? ? '' : ' unanchored'}>"
      end
    end

    # The byte ranges that make up a single multipart body.  The delimiter,
    # preamble, epilogue and part ranges partition the body region without
    # overlap.
    class Multipart
      # Boundary delimiter token as declared by the Content-Type header.
      attr_reader :boundary

      # True when a closing delimiter ("--boundary--") was actually present.
      attr_reader :closed

      # Node of kind +:preamble+ or nil.
      attr_reader :preamble

      # Node of kind +:epilogue+ or nil.
      attr_reader :epilogue

      # Nodes of kind +:boundary+, in source order.
      attr_reader :delimiters

      # Nodes in source order, aligned with the segments between opening
      # delimiters.  Real parsed parts are kind +:part+; empty segments the
      # parser discarded are recorded with their bytes as kind +:segment+ so
      # that no range is fabricated or left unaccounted for.
      attr_reader :parts

      def initialize(boundary, closed, preamble, epilogue, delimiters, parts)
        @boundary = boundary
        @closed = closed
        @preamble = preamble
        @epilogue = epilogue
        @delimiters = delimiters
        @parts = parts
        freeze
      end

      def closed?
        @closed
      end
    end

    # The frozen, untouched bytes this evidence covers.  For the root evidence
    # this is the whole message; nested evidence for a part holds just that
    # part's bytes.  All node ranges are still absolute into the root source.
    attr_reader :source

    # SHA-256 hex digest of the received source covered by this evidence.
    attr_reader :digest

    # Root Node describing the whole message/part region.
    attr_reader :node

    # Multipart metadata when the region's body is multipart, otherwise nil.
    attr_reader :multipart

    # Structural fingerprint captured at build time.
    attr_reader :fingerprint

    def self.build(message, received_source, base_offset = 0, root_source: nil)
      new(message, received_source, base_offset, root_source: root_source)
    end

    def initialize(message, received_source, base_offset, root_source: nil)
      @source = received_source.to_s.dup.force_encoding(Encoding::BINARY).freeze
      @root_source = (root_source ? root_source.dup.force_encoding(Encoding::BINARY) : @source).freeze
      @base_offset = base_offset
      @digest = Digest::SHA256.hexdigest(@source)
      @fingerprint = self.class.structure_fingerprint(message)

      @node, @multipart = scan(message, @source, base_offset)
      freeze
    end

    # Length of the received source in bytes.
    def bytesize
      @source.bytesize
    end

    # Extracts the exact received bytes for an absolute, half-open range.
    def slice(start_offset, end_offset)
      @root_source.byteslice(start_offset, end_offset - start_offset)
    end

    # Every Node in the tree in depth-first, source order, including the root.
    # A nested Mail::RawEvidence (the contents of a part) is descended into
    # exactly once.
    def nodes
      result = []
      collect(@node, result)
      result
    end

    # Header field nodes of this region's own header, in source order.  Folded
    # continuation lines stay part of the field they belong to and duplicate
    # fields remain separate.  Fields inside nested parts are reached through
    # that part's own RawEvidence, not included here.
    def fields
      header = header_node
      return [] unless header&.evidence
      header.evidence.nodes.select { |candidate| candidate.kind == :field }
    end

    # The +:header+ node of this region, or nil when the region has no header.
    def header_node
      return nil unless @node.evidence
      @node.evidence.nodes.find { |candidate| candidate.kind == :header }
    end
    # Nodes of kind +:part+ that were anchored to real bytes and correspond to
    # a part the parser actually produced.  Discarded empty segments (kind
    # +:segment+) are excluded.
    def part_nodes
      (@multipart ? @multipart.parts : []).select { |node| node.kind == :part }
    end

    # True when the live message still matches the structure that was
    # evidenced.  The recorded bytes and digest never change; this only reports
    # whether the parsed object has been modified since the evidence was taken.
    #
    # Read-only access (decoding, re-encoding, inspecting fields) never changes
    # the structural fingerprint, so evidence stays current.
    def current?(message)
      self.class.structure_fingerprint(message) == @fingerprint
    end

    # Inverse of #current?.
    def stale?(message)
      !current?(message)
    end

    # Recursively fingerprints the parsed structure (headers + body/parts),
    # independent of received byte positions or line endings.
    def self.structure_fingerprint(message)
      digest = Digest::SHA256.new
      fingerprint_node(digest, message)
      digest.hexdigest
    end

    def self.fingerprint_node(digest, message)
      header_text =
        begin
          message.header.encoded
        rescue StandardError => error
          "header-error:#{error.class}"
        end
      digest.update('H:')
      digest.update(header_text.to_s)

      body = message.body
      if body.respond_to?(:multipart?) && body.multipart?
        digest.update("B:boundary=#{body.boundary}")
        digest.update("B:preamble=#{body.preamble}")
        digest.update("B:epilogue=#{body.epilogue}")
        body.parts.each do |part|
          digest.update('P:')
          fingerprint_node(digest, part)
        end
      else
        digest.update('B:')
        digest.update(body.respond_to?(:raw_source) ? body.raw_source.to_s : body.to_s)
        digest.update("E:#{body.encoding}") if body.respond_to?(:encoding)
      end
    end

    private

    def collect(current, result)
      result << current
      return unless current.evidence
      evidence = current.evidence
      children =
        if evidence.is_a?(RawEvidence)
          evidence.node.evidence&.nodes || []
        else
          evidence.nodes
        end
      children.each { |child| collect(child, result) }
    end

    # Scans one message/part region. Returns [root_node, multipart_or_nil].
    def scan(message, source, base)
      separator = find_header_separator(source, message.is_a?(Mail::Part))
      if separator
        header_end, body_start = separator
        field_nodes = scan_fields(source, 0, header_end, base)
        header_node = Node.new(:header, base, base + header_end,
                               evidence: EvidenceView.new(field_nodes))
        body_node = build_body_node(message, source, body_start, source.bytesize, base)
        children = [header_node] + [body_node].compact
        region = wrap(:message, base, source, children)
        [region, body_node.evidence&.multipart]
      elsif parsed_as_header?(message)
        # No blank separator line, but the whole region is a header (for
        # example a header-only message with no trailing blank line).
        field_nodes = scan_fields(source, 0, source.bytesize, base)
        header_node = Node.new(:header, base, base + source.bytesize,
                               evidence: EvidenceView.new(field_nodes))
        [wrap(:message, base, source, [header_node]), nil]
      else
        # No recognisable header: treat the entire region as the body.
        body_node = Node.new(:body, base, base + source.bytesize)
        [wrap(:message, base, source, [body_node]), nil]
      end
    end

    # Uses the already-parsed object to decide whether a separator-less region
    # carries header fields rather than an unstructured body.
    def parsed_as_header?(message)
      fields =
        begin
          message.header&.fields
        rescue StandardError
          nil
        end
      fields && !fields.empty?
    end

    def wrap(kind, base, source, children, multipart: nil)
      view = EvidenceView.new(children, multipart)
      Node.new(kind, base, base + source.bytesize, evidence: view)
    end

    # Returns [header_end, body_start] local byte offsets, or nil.  The blank
    # separator line's line ending is consumed; the body starts after it.
    def find_header_separator(source, part)
      each_line(source) do |line_start, line_end, break_end|
        line = source.byteslice(line_start, line_end - line_start).to_s
        blank = part ? /\A[ \t]*\z/.match?(line) : line.empty?
        next unless blank
        return [line_start, break_end]
      end
      nil
    end

    # Splits a header region into individual field nodes.
    def scan_fields(source, region_start, region_end, base)
      nodes = []
      field_start = nil
      field_name = nil
      each_line(source, region_start, region_end, include_final: true) do |line_start, line_end, _break_end|
        line = source.byteslice(line_start, line_end - line_start).to_s
        match = FIELD_NAME_PREFIX.match(line)
        if match
          if field_start
            nodes << Node.new(:field, base + field_start, base + line_start,
                              name: field_name)
          end
          field_start = line_start
          field_name = match[1].downcase
        end
      end
      if field_start
        nodes << Node.new(:field, base + field_start, base + region_end,
                          name: field_name)
      end
      nodes
    end

    FIELD_NAME_PREFIX = /\A([\x21-\x39\x3b-\x7e]+):/n

    # Builds the body node, recursing into multipart and message/rfc822 parts.
    def build_body_node(message, source, body_start, body_end, base)
      body_source = source.byteslice(body_start, body_end - body_start).to_s
      body_abs = base + body_start

      if multipart_boundary(message)
        build_multipart_body(message, body_source, body_abs)
      else
        nested = nested_message_evidence(message, body_source, body_abs)
        if nested
          Node.new(:body, body_abs, body_abs + body_source.bytesize, evidence: nested)
        else
          Node.new(:body, body_abs, body_abs + body_source.bytesize)
        end
      end
    end

    def multipart_boundary(message)
      return nil unless message.respond_to?(:multipart?) && message.multipart?
      message.boundary
    rescue StandardError
      nil
    end

    def build_multipart_body(message, body_source, body_abs)
      boundary = message.boundary
      delimiters = []
      each_line(body_source, include_final: true) do |line_start, line_end, _break_end|
        line = body_source.byteslice(line_start, line_end - line_start).to_s
        match = /\A--#{Regexp.escape(boundary)}(--)?[ \t]*\z/.match(line)
        next unless match
        delimiters << [match[1] ? :close : :open,
                       Node.new(:boundary, body_abs + line_start, body_abs + line_end)]
      end

      closed = delimiters.any? { |kind, _| kind == :close }
      delimiter_nodes = delimiters.map(&:last)
      openings = delimiters.select { |kind, _| kind == :open }.map(&:last)
      closing = delimiters.find { |kind, _| kind == :close }&.last

      preamble_node = nil
      if openings.any? && openings.first.start_offset > body_abs
        preamble_node = Node.new(:preamble, body_abs, openings.first.start_offset)
      end

      part_nodes = build_part_nodes(message, body_source, body_abs,
                                    openings, delimiter_nodes)

      epilogue_node = nil
      # An epilogue only exists after a *closing* delimiter.  With no closing
      # delimiter the trailing bytes are the final part, not an epilogue.
      if closing
        epilogue_start = first_byte_after_line(body_source,
                                               closing.end_offset - body_abs)
        if epilogue_start < body_source.bytesize &&
           !blank_bytes?(body_source, epilogue_start, body_source.bytesize)
          epilogue_node = Node.new(:epilogue, body_abs + epilogue_start,
                                   body_abs + body_source.bytesize)
        end
      end

      multipart = Multipart.new(boundary, closed, preamble_node, epilogue_node,
                                delimiter_nodes, part_nodes)
      children = [preamble_node, epilogue_node].compact + delimiter_nodes + part_nodes
      Node.new(:body, body_abs, body_abs + body_source.bytesize,
               evidence: EvidenceView.new(children, multipart))
    end

    def build_part_nodes(message, body_source, body_abs, openings, delimiter_nodes)
      parsed_parts = message.body.respond_to?(:parts) ? message.body.parts.to_a : []
      regions = content_regions(body_source, body_abs, openings, delimiter_nodes)

      regions.map do |region|
        part_start, part_end = region
        part_source = slice_local(body_source, part_start - body_abs,
                                  part_end - part_start)
        # Match the parsed object to its received bytes.  Blank segments are
        # dropped by the parser, so a positional index is not reliable; match
        # on the normalised raw source instead.
        part = match_parsed_part(parsed_parts, part_source)
        if part
          nested = scan_part(part, part_source, part_start)
          Node.new(:part, part_start, part_end, evidence: nested)
        else
          # A segment with no parsed part (for example an empty segment that
          # the parser discarded).  Its real bytes are recorded as a segment,
          # not claimed as a parsed part and never fabricated into one.
          Node.new(:segment, part_start, part_end)
        end
      end
    end

    # Finds the parsed part whose raw source corresponds to a region's bytes.
    # Depending on the line ending that separated the boundary delimiter from
    # the part, the parser may keep or strip the leading line ending, so the
    # match is tried with and without a leading CRLF or LF.
    def match_parsed_part(parsed_parts, part_source)
      candidates = [part_source, "\r\n" + part_source, "\n" + part_source]
      if part_source.start_with?("\r\n")
        candidates << part_source.byteslice(2, part_source.bytesize - 2)
      elsif part_source.start_with?("\n")
        candidates << part_source.byteslice(1, part_source.bytesize - 1)
      end
      parsed_parts.find do |part|
        raw = part.raw_source.to_s.dup.force_encoding(Encoding::BINARY)
        candidates.any? { |candidate| candidate == raw }
      end
    end

    # Absolute [start, stop] content regions between opening delimiters.
    # When the closing boundary is missing, the bytes after the last opening
    # delimiter are still genuine received bytes and are evidenced as the final
    # part; nothing is invented.
    def content_regions(body_source, body_abs, openings, delimiter_nodes)
      openings.each_with_index.map do |opening, _index|
        content_start = first_byte_after_line(body_source,
                                              opening.end_offset - body_abs)
        following = delimiter_nodes.detect do |candidate|
          candidate.start_offset >= opening.end_offset
        end

        if following
          content_end = content_end_before(body_source,
                                           following.start_offset - body_abs)
          [body_abs + content_start, body_abs + content_end]
        else
          [body_abs + content_start, body_abs + body_source.bytesize]
        end
      end
    end

    def slice_local(source, offset, length)
      source.byteslice(offset, length).to_s
    end

    def first_byte_after_line(source, offset)
      if source.byteslice(offset, 2) == "\r\n"
        offset + 2
      elsif offset < source.bytesize && (source.getbyte(offset) == 10 || source.getbyte(offset) == 13)
        offset + 1
      else
        offset
      end
    end

    def content_end_before(source, delimiter_line_start)
      if delimiter_line_start >= 2 &&
         source.getbyte(delimiter_line_start - 2) == 13 &&
         source.getbyte(delimiter_line_start - 1) == 10
        delimiter_line_start - 2
      elsif delimiter_line_start >= 1 &&
            (source.getbyte(delimiter_line_start - 1) == 10 ||
             source.getbyte(delimiter_line_start - 1) == 13)
        delimiter_line_start - 1
      else
        delimiter_line_start
      end
    end

    def blank_bytes?(source, start, stop)
      /\A[ \t\r\n]*\z/.match?(source.byteslice(start, stop - start).to_s)
    end

    def scan_part(part, part_source, part_abs_start)
      RawEvidence.new(part, part_source, part_abs_start, root_source: @root_source)
    rescue StandardError
      nil
    end

    def nested_message_evidence(message, body_source, body_abs_start)
      return nil unless message.respond_to?(:mime_type) &&
                        message.mime_type == 'message/rfc822'
      nested = Mail::Part.new(body_source)
      RawEvidence.new(nested, body_source, body_abs_start, root_source: @root_source)
    rescue StandardError
      nil
    end

    # Yields [line_start, line_end, break_end] for every line.  A line ending
    # is a lone CR, a lone LF or a CRLF, matching the received bytes exactly.
    # +line_end+ excludes the line ending; +break_end+ includes it.  With
    # +include_final+, a trailing line without a line ending is also yielded.
    def each_line(source, from = 0, to = source.bytesize, include_final: false)
      line_start = from
      offset = from
      while offset < to
        byte = source.getbyte(offset)
        if byte == 13 || byte == 10
          if byte == 13 && offset + 1 < to && source.getbyte(offset + 1) == 10
            line_end = offset
            break_end = offset + 2
            offset += 2
          else
            line_end = offset
            break_end = offset + 1
            offset += 1
          end
          yield(line_start, line_end, break_end)
          line_start = break_end
        else
          offset += 1
        end
      end
      yield(line_start, to, to) if include_final && line_start < to
    end

    # Exposes a node's child nodes and optional multipart metadata.
    class EvidenceView
      attr_reader :multipart
      def initialize(nodes, multipart = nil)
        @nodes = nodes
        @multipart = multipart
      end

      def nodes
        @nodes
      end
    end
  end
end
