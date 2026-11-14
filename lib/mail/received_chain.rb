# encoding: utf-8
# frozen_string_literal: true
require 'digest'
require 'mail/constants'
require 'mail/received_chain/parser'
require 'mail/received_chain/time_parser'

module Mail
  # A forensic view of the Received trace fields in a message header.
  #
  # The chain deliberately keeps the header order.  It never sorts hops by
  # their timestamps: a chain with a clock reversal is evidence, not something
  # to repair.  It also only looks at header fields, so a "Received:" line in
  # the body cannot become a hop, and comments are parsed as comments rather
  # than as top-level clauses.
  #
  # Callers can declare which part of the trace they can vouch for:
  #
  #   mail.received_chain(trusted_receivers: ['mx.corp.example'])
  #   mail.received_chain(trusted_boundary: 1)
  #
  # Hops at or above that boundary are attributed to trusted infrastructure;
  # every hop below it is only what the mail itself asserts.
  class ReceivedChain
    include Enumerable

    class Hop
      attr_reader :index, :position, :field_index, :raw_index,
                  :raw_field, :raw_sha256,
                  :raw_preserved, :value, :parsed, :timestamp, :trust,
                  :trust_basis, :from, :by

      def initialize(index:, position:, field_index:, raw_index:,
                     raw_field:, raw_preserved:, value:, parsed:, timestamp:,
                     trust:, trust_basis:)
        @index = index
        @position = position
        @field_index = field_index
        @raw_index = raw_index
        @raw_field = raw_field
        @raw_sha256 = Digest::SHA256.hexdigest(raw_field.to_s)
        @raw_preserved = raw_preserved
        @value = value
        @parsed = parsed
        @timestamp = timestamp
        @trust = trust
        @trust_basis = trust_basis
        @from = parsed.from
        @by = parsed.by
      end

      def trusted?
        trust == :trusted
      end

      def self_asserted?
        trust == :self_asserted
      end

      def evidence
        trusted? ? 'trusted_source' : 'mail_self_report'
      end

      def info
        parsed.info
      end

      def leading
        parsed.leading
      end

      def via
        parsed.via
      end

      def with
        parsed.with
      end

      def protocol
        parsed.protocol
      end

      def id
        parsed.id
      end

      def for_addresses
        parsed.for_addresses
      end

      def comments
        parsed.comments
      end

      def clauses
        parsed.clauses
      end

      def timestamp_comparable?
        timestamp && timestamp.comparable
      end

      def missing
        fields = []
        fields << 'from' if from.nil?
        fields << 'by' if by.nil?
        fields << 'protocol' if protocol.nil?
        fields << 'id' if id.nil?
        fields << 'timestamp' if timestamp.nil? || timestamp.raw.nil?
        fields
      end

      def to_h
        {
          'index' => index,
          'position' => position,
          'field_index' => field_index,
          'raw_index' => raw_index,
          'raw_field' => raw_field,
          'raw_sha256' => raw_sha256,
          'raw_preserved' => raw_preserved,
          'value' => value,
          'info' => info,
          'leading' => leading,
          'from' => endpoint_h(:from),
          'by' => endpoint_h(:by),
          'via' => via,
          'with' => with,
          'protocol' => protocol,
          'id' => id,
          'for_addresses' => for_addresses,
          'comments' => comments.map(&:to_h),
          'timestamp' => timestamp_h,
          'trust' => trust.to_s,
          'trust_basis' => trust_basis,
          'evidence' => evidence,
          'missing' => missing
        }
      end

      private

      def endpoint_h(role)
        endpoint = role == :from ? from : by
        return nil if endpoint.nil?

        endpoint.to_h.merge(
          'role' => role.to_s,
          'identity_basis' => role == :by ? 'receiver_declared' : 'peer_declared',
          'evidence' => endpoint_evidence(role)
        )
      end

      def endpoint_evidence(role)
        return 'mail_self_report' unless trusted?
        role == :by ? 'trusted_source' : 'trusted_observation'
      end

      def timestamp_h
        return nil if timestamp.nil?
        timestamp.to_h.merge('evidence' => trusted? ? 'trusted_source' : 'mail_self_report')
      end
    end

    attr_reader :hops, :trusted_boundary, :time_anomalies, :time_ordering,
                :observations, :hop_travel

    def initialize(source, options = {})
      @trusted_receivers = Array(options[:trusted_receivers]).compact.map(&:to_s)
      @requested_boundary = options[:trusted_boundary]
      @raw_entries = self.class.extract_received_entries(source)
      @resolved = resolve_boundary
      @trusted_boundary = @resolved[:index]
      @hops = build_hops
      analyze
    end

    def each(&block)
      hops.each(&block)
    end

    def size
      hops.size
    end
    alias_method :length, :size

    def empty?
      hops.empty?
    end

    def [](index)
      hops[index]
    end

    def trusted_hops
      hops.select(&:trusted?)
    end

    def self_asserted_hops
      hops.select(&:self_asserted?)
    end

    def raw_order
      hops.map(&:index)
    end

    def chronological_order
      comparable = hops.select(&:timestamp_comparable?)
      order = comparable.sort_by { |hop| [hop.timestamp.utc.to_i, hop.index] }.map do |hop|
        { 'index' => hop.index, 'utc' => hop.timestamp.utc.iso8601 }
      end
      excluded = hops.reject(&:timestamp_comparable?).map do |hop|
        { 'index' => hop.index, 'reason' => timestamp_exclusion_reason(hop) }
      end

      {
        'annotation_only' => true,
        'note' => 'Raw header order is authoritative; this is a derived view only.',
        'order' => order,
        'excluded' => excluded
      }
    end

    def trust_summary
      boundary_hop = trusted_boundary ? hops[trusted_boundary] : nil
      boundary_host = boundary_hop && boundary_hop.by && boundary_hop.by.host

      {
        'boundary' => {
          'requested' => requested_boundary_h,
          'resolved_index' => trusted_boundary,
          'resolved_host' => boundary_host,
          'method' => @resolved[:method].to_s,
          'note' => @resolved[:note]
        },
        'trusted_indexes' => trusted_hops.map(&:index),
        'self_asserted_indexes' => self_asserted_hops.map(&:index)
      }
    end

    # Concise, source-labelled statements derived from each hop.  A trusted
    # hop's "by" record comes from trusted infrastructure; its "from" record is
    # still a peer claim that trusted infrastructure merely observed.
    def conclusions
      hops.flat_map do |hop|
        entries = []
        if hop.by
          entries << conclusion(hop, 'by', hop.by.host, hop.evidence)
        end
        if hop.from
          entries << conclusion(hop, 'from', hop.from.host, hop.trusted? ? 'trusted_observation' : 'mail_self_report')
        end
        if hop.timestamp && hop.timestamp.valid?
          entries << conclusion(hop, 'timestamp', hop.timestamp.utc.iso8601, hop.trusted? ? 'trusted_source' : 'mail_self_report')
        end
        if hop.protocol
          entries << conclusion(hop, 'protocol', hop.protocol, hop.evidence)
        end
        entries
      end
    end

    def to_h
      {
        'hop_count' => size,
        'raw_order' => hops.map(&:to_h),
        'chronological_order' => chronological_order,
        'trust' => trust_summary,
        'conclusions' => conclusions,
        'time_ordering' => time_ordering,
        'hop_travel' => hop_travel,
        'time_anomalies' => time_anomalies,
        'observations' => observations
      }
    end

    # Returns ordered entries for every Received field the header exposes.
    # Raw header text is the backbone of the order; if the field list holds a
    # field the raw text does not cover (for example a field added with
    # #received= after parsing), it is appended and marked as not raw.
    def self.extract_received_entries(source)
      header =
        if source.respond_to?(:header)
          source.header
        elsif source.is_a?(String)
          # A raw message string: parse its header block into a Header so the
          # same field-order rules apply as for a Mail::Message.
          Header.new(source.split(/\r?\n\r?\n/, 2).first.to_s)
        else
          source
        end

      raw_entries = raw_received_entries(header)
      fields = header.respond_to?(:fields) ? header.fields : nil
      return raw_entries unless fields

      received_fields = fields.each_with_index.select do |field, _|
        field.responsible_for?('Received')
      end
      return raw_entries if received_fields.empty?

      entries = []
      cursor = 0

      received_fields.each do |field, field_index|
        value = field.value.to_s
        match = find_raw_entry(raw_entries, cursor, value)

        if match
          while cursor < match
            entries << raw_entry_hash(raw_entries[cursor])
            cursor += 1
          end
          entry = raw_entry_hash(raw_entries[match])
          entry[:field_index] = field_index
          entries << entry
          cursor = match + 1
        else
          entries << {
            field_index: field_index,
            raw_index: nil,
            raw_field: "#{field.name}: #{value}",
            value: value,
            raw_preserved: false
          }
        end
      end

      while cursor < raw_entries.size
        entries << raw_entry_hash(raw_entries[cursor])
        cursor += 1
      end

      entries
    end

    def self.find_raw_entry(raw_entries, cursor, value)
      index = cursor
      while index < raw_entries.size
        # A field that failed structured parsing (for example an
        # UnstructuredField fallback) keeps its folded text in #value, so
        # compare on collapsed whitespace but retain the raw field as-is.
        return index if normalize_value(raw_entries[index][:value]) == normalize_value(value)
        index += 1
      end
      nil
    end

    def self.normalize_value(value)
      value.to_s.gsub(/\s+/, ' ').strip
    end

    def self.raw_entry_hash(entry)
      entry.merge(raw_preserved: true)
    end

    def self.raw_received_entries(header)
      raw = header.respond_to?(:raw_source) ? header.raw_source.to_s : ''
      return [] if raw.empty?

      entries = []
      field_index = 0
      # Only the header block may contribute hops.  Anything after the blank
      # line is message body, even if it looks like a Received line.
      header_block = raw.split(/\r?\n\r?\n/, 2).first.to_s
      header_block.split(Constants::HEADER_SPLIT, -1).each do |line|
        next if line.empty?
        name, body = split_field_line(line)
        next unless name

        if name.casecmp('Received').zero?
          entries << {
            field_index: field_index,
            raw_index: field_index,
            raw_field: line,
            value: unfold(body.to_s),
            raw_preserved: true
          }
        end
        field_index += 1
      end

      entries
    end

    def self.split_field_line(line)
      match = line.match(/\A([^\s:]+)[ \t]*:[ \t]*(.*)\z/m)
      return nil unless match
      name = match[1]
      return nil unless Constants::FIELD_NAME.match?(name)
      [name, match[2]]
    end

    # Same unfolding rule as Mail::Field: drop the line break and keep the
    # folding whitespace, so #value matches what Field#value reports.
    def self.unfold(value)
      value.to_s.gsub(/\r?\n([ \t]+)/, '\\1').strip
    end

    private

    def build_hops
      @raw_entries.each_with_index.map do |entry, index|
        parsed = Parser.parse(entry[:value])
        timestamp = TimeParser.parse(parsed.timestamp)
        index_trust, basis = trust_for(index)
        Hop.new(
          index: index,
          position: index + 1,
          field_index: entry[:field_index],
          raw_index: entry[:raw_index],
          raw_field: entry[:raw_field],
          raw_preserved: entry[:raw_preserved],
          value: entry[:value],
          parsed: parsed,
          timestamp: timestamp,
          trust: index_trust,
          trust_basis: basis
        )
      end
    end

    def trust_for(index)
      if trusted_boundary.nil?
        [:self_asserted, 'no_trusted_boundary']
      elsif index == trusted_boundary
        [:trusted, 'trusted_boundary_hop']
      elsif index < trusted_boundary
        [:trusted, 'above_trusted_boundary']
      else
        [:self_asserted, 'below_trusted_boundary']
      end
    end

    def resolve_boundary
      requested = @requested_boundary
      receivers = @trusted_receivers.dup
      explicit_index = nil

      case requested
      when nil
        nil
      when Integer
        explicit_index = requested
      when String
        receivers << requested
      when Hash
        explicit_index = requested[:index] || requested['index']
        host = requested[:host] || requested['host']
        receivers << host.to_s if host
      else
        return { index: nil, method: :none, note: "Unsupported trusted_boundary: #{requested.inspect}" }
      end

      if explicit_index
        unless explicit_index.is_a?(Integer) && explicit_index >= 0 && explicit_index < @raw_entries.size
          return {
            index: nil,
            method: :none,
            note: "trusted_boundary index #{explicit_index.inspect} is outside the #{@raw_entries.size} Received hop(s)"
          }
        end
        return { index: explicit_index, method: :explicit_index, note: 'Boundary supplied as a zero-based raw header position.' }
      end

      if receivers.empty?
        return { index: nil, method: :none, note: 'No trusted boundary was supplied; every hop is treated as mail self-report.' }
      end

      normalized = receivers.map { |receiver| normalize_receiver(receiver) }.reject(&:empty?)
      @raw_entries.each_with_index do |entry, index|
        parsed = Parser.parse(entry[:value])
        # Only the "by" clause names the system that received this hop's
        # message.  A "from" match would mark the sender's hop as trusted.
        candidate = parsed.by && parsed.by.normalized_host
        if candidate && (match = (normalized.include?(candidate) ? candidate : nil))
          return {
            index: index,
            method: :receiver_match,
            note: "First hop matching trusted receiver #{match.inspect}; that hop and those above it are trusted."
          }
        end
      end

      {
        index: nil,
        method: :none,
        note: "None of the trusted receivers #{receivers.inspect} matched a Received hop."
      }
    end

    def normalize_receiver(receiver)
      value = receiver.to_s.strip
      value = value.split('@').last if value.include?('@')
      value = value[1..-2] if value.start_with?('[') && value.end_with?(']')
      value = value.sub(/\Aipv6:/i, '').sub(/[.,;:]+\z/, '')
      value.downcase
    end

    def analyze
      @time_ordering = []
      @time_anomalies = []
      @observations = []
      @hop_travel = []

      hops.each do |hop|
        analyze_timestamp(hop)
        analyze_addresses(hop)
        analyze_structural(hop)
      end

      hops.each_cons(2) do |top, bottom|
        analyze_edge(top, bottom)
      end

      hops.each do |hop|
        elapsed = travel_time(hop.index)
        next if elapsed.nil?
        if elapsed < 0
          @time_anomalies << {
            'hop' => hop.index,
            'kind' => 'negative_travel_time',
            'severity' => 'warning',
            'elapsed_seconds' => elapsed,
            'message' => "Hop #{hop.index} claims to have arrived #{elapsed.abs} second(s) before its predecessor.",
            'evidence' => edge_evidence(hop, hops[hop.index + 1])
          }
        end
        bottom = hops[hop.index + 1]
        @hop_travel << {
          'hop' => hop.index,
          'elapsed_seconds' => elapsed,
          'evidence' => edge_evidence(hop, bottom)
        }
      end
    end

    def analyze_timestamp(hop)
      stamp = hop.timestamp
      if stamp.nil? || stamp.raw.nil?
        @time_anomalies << anomaly(hop, 'timestamp_missing', 'The hop has no timestamp.', 'warning')
        return
      end

      if !stamp.valid?
        @time_anomalies << anomaly(hop, 'timestamp_invalid', stamp.error, 'warning')
        return
      end

      if stamp.offset_meaning == 'unrecognized_zone'
        @time_anomalies << anomaly(hop, 'offset_unrecognized',
          "Zone label #{stamp.zone_label.inspect} is not a recognized offset; this hop is not safely comparable.",
          'warning')
      elsif !stamp.offset_present
        @time_anomalies << anomaly(hop, 'offset_missing',
          'No UTC offset was written; the parsed UTC instant assumes +00:00.',
          'warning')
      end

      if stamp.offset_meaning == 'unknown'
        @time_anomalies << anomaly(hop, 'offset_unknown',
          'A -0000 offset means the local offset is unknown; this hop is not safely comparable.',
          'warning')
      end

      if stamp.offset_consistent == false
        @time_anomalies << anomaly(hop, 'offset_label_mismatch',
          "Numeric offset #{stamp.offset_text} disagrees with zone label #{stamp.zone_label.inspect}.",
          'warning')
      end

      unless stamp.missing_components.empty?
        @time_anomalies << anomaly(hop, 'timestamp_incomplete',
          "Missing date-time component(s): #{stamp.missing_components.join(', ')}.",
          'warning')
      end
    end

    def analyze_addresses(hop)
      [hop.from, hop.by].compact.each do |endpoint|
        role = endpoint.equal?(hop.from) ? 'from' : 'by'

        if endpoint.address && endpoint.address_source == :comment &&
           endpoint.address_depth.to_i > 1
          @observations << {
            'kind' => 'nested_comment_address',
            'hop' => hop.index,
            'role' => role,
            'address' => endpoint.address,
            'depth' => endpoint.address_depth,
            'note' => 'The selected address came from a nested comment; its depth is recorded for review.',
            'evidence' => hop.evidence
          }
        end

        endpoint.comment_addresses.each do |entry|
          next if entry.depth == 1
          @observations << {
            'kind' => 'nested_comment_address_unused',
            'hop' => hop.index,
            'role' => role,
            'address' => entry.address,
            'depth' => entry.depth,
            'note' => 'Address text inside a nested comment is comment evidence, not a transfer endpoint.',
            'evidence' => hop.evidence
          }
        end
      end

      hop.comments.each do |comment|
        next if comment.claims.nil? || comment.claims.empty?
        @observations << {
          'kind' => 'comment_clause_claim',
          'hop' => hop.index,
          'depth' => comment.depth,
          'claims' => comment.claims,
          'note' => 'Clause-like words inside a comment were not treated as Received clauses.',
          'evidence' => hop.evidence
        }
      end
    end

    def analyze_structural(hop)
      if hop.from.nil? && hop.by.nil? && hop.leading
        @observations << {
          'kind' => 'comment_only_hop',
          'hop' => hop.index,
          'note' => 'No top-level from/by clause; the leading comment is the only transfer evidence.',
          'evidence' => hop.evidence
        }
      end

      %w[from by].each do |clause|
        present = !hop.parsed.clauses[clause].nil?
        if !present
          @observations << {
            'kind' => 'missing_clause',
            'hop' => hop.index,
            'clause' => clause,
            'note' => "No top-level #{clause} clause was written.",
            'evidence' => hop.evidence
          }
        elsif (clause == 'from' ? hop.from : hop.by).nil?
          @observations << {
            'kind' => 'unresolved_clause',
            'hop' => hop.index,
            'clause' => clause,
            'value' => hop.parsed.clauses[clause].value,
            'note' => "The #{clause} clause contains no host outside comments.",
            'evidence' => hop.evidence
          }
        end
      end
    end

    # Received fields are prepended as a message travels, so the topmost hop
    # is the one nearest the final receiver and the bottom-most hop is the
    # oldest.  A healthy trace therefore has non-increasing timestamps as the
    # header is read from top to bottom.  This method compares adjacent hops
    # in header order and records a reversal instead of reordering anything.
    def analyze_edge(top, bottom)
      top_stamp = top.timestamp
      bottom_stamp = bottom.timestamp

      if top_stamp && bottom_stamp && top_stamp.valid? && bottom_stamp.valid?
        if top_stamp.offset_present && bottom_stamp.offset_present &&
           top_stamp.offset_seconds != bottom_stamp.offset_seconds
          @observations << {
            'kind' => 'timezone_shift',
            'edge' => [top.index, bottom.index],
            'offset_seconds' => [top_stamp.offset_seconds, bottom_stamp.offset_seconds],
            'offset_delta_seconds' => top_stamp.offset_seconds - bottom_stamp.offset_seconds,
            'note' => 'Adjacent hops used different UTC offsets. This is normal across hosts; ordering is evaluated in UTC.',
            'evidence' => edge_evidence(top, bottom)
          }
        end
      end

      if top_stamp.nil? || bottom_stamp.nil? || !top_stamp.valid? || !bottom_stamp.valid?
        @time_ordering << {
          'edge' => [top.index, bottom.index],
          'status' => 'not_comparable',
          'reason' => 'One or both hops have a missing or invalid timestamp.',
          'evidence' => edge_evidence(top, bottom)
        }
        return
      end

      unless top_stamp.comparable && bottom_stamp.comparable
        @time_ordering << {
          'edge' => [top.index, bottom.index],
          'status' => 'not_comparable',
          'reason' => 'One or both hops have an unknown or missing UTC offset.',
          'evidence' => edge_evidence(top, bottom)
        }
        return
      end

      skew = top_stamp.utc.to_i - bottom_stamp.utc.to_i
      if skew < 0
        @time_ordering << {
          'edge' => [top.index, bottom.index],
          'status' => 'time_reversal',
          'delta_seconds' => -skew,
          'top_utc' => top_stamp.utc.iso8601,
          'bottom_utc' => bottom_stamp.utc.iso8601,
          'note' => 'The hop nearer the top of the header claims an earlier UTC time than the hop it received from.',
          'evidence' => edge_evidence(top, bottom)
        }
        @time_anomalies << {
          'hop' => top.index,
          'compared_with_hop' => bottom.index,
          'kind' => 'time_reversal',
          'severity' => 'warning',
          'delta_seconds' => -skew,
          'message' => "Hop #{top.index} predates hop #{bottom.index} by #{-skew} second(s) in UTC.",
          'evidence' => edge_evidence(top, bottom)
        }
      else
        @time_ordering << {
          'edge' => [top.index, bottom.index],
          'status' => 'consistent_descending',
          'delta_seconds' => skew,
          'top_utc' => top_stamp.utc.iso8601,
          'bottom_utc' => bottom_stamp.utc.iso8601,
          'evidence' => edge_evidence(top, bottom)
        }
      end
    end

    # Difference between a hop and the hop below it (the one it received
    # from), in seconds.  Only comparable timestamps produce a value.
    def travel_time(index)
      top = hops[index]
      bottom = hops[index + 1]
      return nil if bottom.nil?
      return nil unless top && bottom
      return nil unless top.timestamp_comparable? && bottom.timestamp_comparable?
      top.timestamp.utc.to_i - bottom.timestamp.utc.to_i
    end

    def timestamp_exclusion_reason(hop)
      stamp = hop.timestamp
      return 'missing timestamp' if stamp.nil? || stamp.raw.nil?
      return stamp.error if !stamp.valid?
      return 'offset unknown or missing' unless stamp.comparable
      'not comparable'
    end

    def anomaly(hop, kind, message, severity)
      {
        'hop' => hop.index,
        'kind' => kind,
        'severity' => severity,
        'message' => message,
        'evidence' => hop.evidence
      }
    end

    def edge_evidence(top, bottom)
      states = [top.trust, bottom.trust].uniq
      if states == [:trusted]
        'trusted_source'
      elsif states == [:self_asserted]
        'mail_self_report'
      else
        'mixed'
      end
    end

    def conclusion(hop, subject, value, evidence)
      {
        'hop' => hop.index,
        'subject' => subject,
        'value' => value,
        'evidence' => evidence,
        'trust' => hop.trust.to_s
      }
    end

    def requested_boundary_h
      {
        'trusted_receivers' => @trusted_receivers,
        'trusted_boundary' => @requested_boundary
      }
    end
  end
end
