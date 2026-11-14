# encoding: BINARY

require 'json'

module MQTT
  module Forensics
    # Renders an Analyzer result as a human-readable text report or structured
    # JSON. All rendered rows carry raw frame references so every definite
    # event is traceable to the originating fragment bytes.
    class Report
      SEVERITY_LABEL = {
        :violation => 'VIOLATION',
        :evidence  => 'EVIDENCE ',
        :gap       => 'GAP     '
      }.freeze

      def initialize(capture, events, findings, meta = {})
        @capture = capture
        @events = events
        @findings = findings
        @meta = meta
      end

      attr_reader :events, :findings

      def violations
        @findings.select { |f| f.severity == :violation }
      end

      def evidence
        @findings.select { |f| f.severity == :evidence }
      end

      def gaps
        @findings.select { |f| f.severity == :gap }
      end

      # Findings whose provenance cannot close the loop (capture may explain
      # them). Kept separate from proven violations to avoid over-claiming.
      def unproven
        @findings.select { |f| f.status == 'unproven' }
      end

      def to_h
        {
          'capture' => {
            'timestamps_available' => @meta[:timestamps_available],
            'ordering_note' => 'per-direction wire order; cross-direction timing is not inferred ' \
                               'from fragment timestamps',
            'bytes_client_to_broker' => @capture.byte_counts[:client],
            'bytes_broker_to_client' => @capture.byte_counts[:broker],
            'fragments' => @capture.fragments.map do |f|
              {
                'direction' => f.direction.to_s,
                'bytes' => f.bytesize,
                'source' => f.source,
                'captured_at' => f.captured_at
              }
            end
          },
          'identity' => identity_summary,
          'timeline' => @events.map { |e| event_to_h(e) },
          'findings' => @findings.map do |f|
            {
              'severity' => f.severity.to_s,
              'code' => f.code,
              'status' => f.status,
              'message' => f.message,
              'evidence_refs' => Array(f.refs).map(&:to_s)
            }
          end,
          'tables' => {
            'duplicate_acknowledgements' => table_rows('DUPLICATE_ACK'),
            'unsolicited_responses' => unsolicited_rows,
            'capture_gaps' => gaps.map { |f| finding_row(f) }
          }
        }
      end

      def to_json(*_args)
        JSON.pretty_generate(to_h)
      end

      def to_text
        lines = []
        lines << 'MQTT OFFLINE SESSION ANALYSIS'
        lines << '=' * 60
        if @meta[:timestamps_available]
          lines << 'Timeline ordering: per-direction wire order (fragment timestamps not used as a cross-direction clock)'
        else
          lines << 'Timeline ordering: per-direction wire order only (no timestamps; no cross-direction timing claimed)'
        end
        lines << "Bytes client->broker: #{@capture.byte_counts[:client]}, " \
                 "broker->client: #{@capture.byte_counts[:broker]}"
        lines << ''
        lines << identity_text
        lines << ''
        lines << 'CORRELATED TIMELINE (each event traceable to a raw frame)'
        lines << 'Each direction is in exact wire order; the C/B interleaving is a presentation'
        lines << 'merge and is NOT a proven cross-direction ordering. Ref = direction + stream offset.'
        lines << '-' * 60
        @events.each { |e| lines << event_line(e) }
        lines << ''
        lines << finding_section('PROTOCOL TIMING VIOLATIONS (proven from observed bytes)', violations)
        lines << finding_section('SUSPICIOUS / ABNORMAL (may be explained by capture loss)', evidence)
        lines << finding_section('CAPTURE GAPS (incomplete evidence, not attacks)', gaps)
        lines << ''
        lines << duplicate_table_text
        lines << unsolicited_table_text
        lines << gap_table_text
        lines.join("\n")
      end

      private

      def identity_summary
        connect = @events.find { |e| e.kind == 'CONNECT' }
        if connect.nil?
          { 'state' => 'unknown',
            'note' => 'No CONNECT observed; client identity cannot be established from the capture.' }
        else
          d = connect.detail
          {
            'state' => 'declared_only',
            'client_id' => d['client_id'],
            'username' => d['username'],
            'authentication_note' => 'Username is a client-side declaration in CONNECT and does not by ' \
                                     'itself prove an authenticated identity; the broker CONNACK result is ' \
                                     'the only acceptance signal in the capture.'
          }
        end
      end

      def identity_text
        connack = @events.find { |e| e.kind == 'CONNACK' }
        id = identity_summary
        return "IDENTITY: #{id['note']}" if id['state'] == 'unknown'

        line = "IDENTITY: client_id=#{id['client_id'].inspect}, declared username=#{id['username'].inspect}"
        if connack
          line += " | broker result: #{connack.detail['result']} (#{connack.detail['authenticated']})"
        else
          line += ' | broker acceptance: UNKNOWN (no CONNACK captured)'
        end
        line
      end

      def event_to_h(event)
        {
          'seq' => event.seq,
          'event' => event.kind,
          'direction' => event.direction.to_s,
          'frame_ref' => event.ref,
          'frame_offset' => event.frame.byte_offset,
          'provenance' => event.frame.fragments,
          'detail' => event.detail,
          'related_refs' => Array(event.related).map(&:to_s)
        }
      end

      def event_line(event)
        arrow = event.direction == :client ? 'C->B' : 'B->C'
        base = format('%2d %-4s %-10s %-8s', event.seq, event.ref.to_s, event.kind, arrow)
        "#{base} #{summarise_detail(event)}".rstrip
      end

      def summarise_detail(event)
        d = event.detail
        case event.kind
        when 'CONNECT'
          "proto=#{d['protocol']} client_id=#{d['client_id'].inspect} user=#{d['username'].inspect} " \
            "clean=#{d['clean_session']} keepalive=#{d['keep_alive']}"
        when 'CONNACK'
          "rc=#{d['return_code']} (#{d['result']}) session_present=#{d['session_present']}"
        when 'PUBLISH'
          "id=#{d['packet_id'] || '-'} qos=#{d['qos']} dup=#{d['dup']} retain=#{d['retain']} " \
            "topic=#{d['topic'].inspect} payload=#{d['payload_bytes']}B"
        when 'SUBSCRIBE'
          "id=#{d['packet_id']} filters=#{d['filters'].map { |f| "#{f['filter']}:#{f['qos']}" }.join(',')}"
        when 'SUBACK'
          "id=#{d['packet_id']} rc=#{d['return_codes'].map { |c| format('0x%02X', c) }.join(',')}"
        when 'UNSUBSCRIBE'
          "id=#{d['packet_id']} filters=#{d['filters'].join(',')}"
        when 'MALFORMED'
          d.to_s
        else
          d.empty? ? '' : d.map { |k, v| "#{k}=#{v}" }.join(' ')
        end
      end

      def finding_section(title, list)
        block = ["#{title} [#{list.size}]", '-' * 60]
        if list.empty?
          block << '  (none)'
        else
          list.each { |f| block << "  [#{SEVERITY_LABEL[f.severity]}|#{f.status}] #{f.code} #{f.refs.join(',')}" \
                                   " - #{f.message}" }
        end
        block << ''
        block.join("\n")
      end

      def table_rows(code)
        @findings.select { |f| f.code == code }.map { |f| finding_row(f) }
      end

      def unsolicited_rows
        @findings.select { |f| f.code.to_s.start_with?('UNSOLICITED_') }.map { |f| finding_row(f) }
      end

      def finding_row(f)
        { 'code' => f.code, 'status' => f.status, 'message' => f.message,
          'evidence_refs' => Array(f.refs).map(&:to_s) }
      end

      def duplicate_table_text
        rows = table_rows('DUPLICATE_ACK')
        build_table('DUPLICATE ACKNOWLEDGEMENTS', rows,
                    %w[code status evidence_refs message])
      end

      def unsolicited_table_text
        build_table('UNSOLICITED RESPONSES (request absent from capture)',
                    unsolicited_rows, %w[code status evidence_refs message])
      end

      def gap_table_text
        build_table('CAPTURE GAPS (do not treat as confirmed attacks)',
                    gaps.map { |f| finding_row(f) }, %w[code status evidence_refs message])
      end

      def build_table(title, rows, columns)
        block = ["#{title} [#{rows.size}]", '-' * 60]
        if rows.empty?
          block << '  (none)'
          return block.join("\n")
        end

        string_rows = rows.map do |r|
          columns.map do |col|
            col == 'evidence_refs' ? Array(r[col]).join(',') : r[col].to_s
          end
        end
        widths = columns.map.with_index do |col, idx|
          ([col.upcase] + string_rows.map { |cells| cells[idx] }).map(&:length).max
        end
        block << columns.map.with_index { |col, idx| col.upcase.ljust(widths[idx]) }.join(' | ')
        block << widths.map { |w| '-' * w }.join('-+-')
        string_rows.each do |cells|
          block << cells.map.with_index { |cell, idx| cell.ljust(widths[idx]) }.join(' | ')
        end
        block.join("\n")
      end
    end
  end
end
