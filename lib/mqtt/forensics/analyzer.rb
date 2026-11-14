# encoding: BINARY

require 'mqtt/forensics/capture'

module MQTT
  module Forensics
    # A single thing that happened on the wire, anchored to the Frame that
    # proves it. Every event carries the raw frame reference so a reader can
    # trace a conclusion back to the exact captured bytes.
    Event = Struct.new(:seq, :kind, :direction, :frame, :detail, :related) do
      def ref
        frame.nil? ? nil : frame.ref
      end
    end

    # A conclusion. severity is one of:
    #   :violation - behaviour that contradicts the MQTT 3.1.1 state machine
    #   :evidence  - abnormal but explainable by capture loss / unprovable
    #   :gap       - incompleteness in the capture, never an attack finding
    Finding = Struct.new(:severity, :code, :message, :refs, :status) do
      def to_a
        [severity, code, message, Array(refs).map(&:to_s), status]
      end
    end

    # Correlates reassembled frames into a connection/subscribe/publish/ack
    # timeline and flags deviations from the MQTT 3.1.1 protocol ordering.
    #
    # The analyser runs in two phases so its verdicts never depend on an
    # assumed cross-direction ordering:
    #   1. collect  - every frame is filed under its packet id / request slot
    #                 and appended to the timeline in wire order;
    #   2. evaluate - per-flow ordering, duplicate acks, unsolicited responses
    #                 and capture gaps are derived from the assembled state.
    #
    # It is deliberately conservative: when a missing packet could be
    # explained by a capture gap it records a :gap or :evidence item marked
    # 'unproven', rather than asserting an attack.
    class Analyzer
      # Packets the client is permitted to send. PUBREL/PUBCOMP appear because
      # the client acts as a QoS2 receiver (PUBREC then PUBCOMP) and as a QoS2
      # sender it emits PUBREL after PUBREC.
      CLIENT_TYPES = %w[CONNECT PUBLISH PUBACK PUBREC PUBREL PUBCOMP
                        SUBSCRIBE UNSUBSCRIBE PINGREQ DISCONNECT].freeze
      BROKER_TYPES = %w[CONNACK PUBLISH PUBACK PUBREC PUBREL PUBCOMP
                        SUBACK UNSUBACK PINGRESP].freeze

      CONNACK_CODES = {
        0x00 => 'Connection Accepted',
        0x01 => 'unacceptable protocol version',
        0x02 => 'identifier rejected',
        0x03 => 'broker unavailable',
        0x04 => 'bad user name or password',
        0x05 => 'not authorised'
      }.freeze

      SUBACK_FAILURE_CODES = [0x80].freeze

      def initialize(capture)
        @capture = capture

        @events = []
        @findings = []

        # QoS message flows. A flow is identified by the publisher direction
        # plus packet id. An acknowledgement always joins the flow owned by the
        # peer (the publisher); see #flow_for_ack.
        @flows = { :client => Hash.new { |h, k| h[k] = new_flow },
                   :broker => Hash.new { |h, k| h[k] = new_flow } }

        @sub_requests = {}   # id -> subscribe frame
        @sub_responses = {}  # id -> array of suback frames (duplicates detectable)
        @unsub_requests = {}
        @unsub_responses = {}
        @pingreqs = []
        @pingresps = []
        @connects = []
        @connacks = []
        @malformed = []
      end

      def analyze
        @capture.frames.each { |frame| collect(frame) }
        evaluate_connection
        evaluate_subscriptions
        evaluate_pings
        evaluate_flows
        evaluate_malformed
        order_timeline
        build_report
      end

      # Events are created during several passes, so assign the presentation
      # sequence afterwards. Each direction is internally wire-ordered by byte
      # offset; the two directions are interleaved round-robin for readability
      # without asserting a cross-direction order the data cannot prove.
      def order_timeline
        client_events = @events.select { |e| e.direction == :client }
        broker_events = @events.select { |e| e.direction == :broker }
        client_events.sort_by! { |e| e.frame.byte_offset }
        broker_events.sort_by! { |e| e.frame.byte_offset }
        ordered = interleave(client_events, broker_events)
        ordered.each_with_index { |event, idx| event.seq = idx + 1 }
        @events = ordered
      end

      def interleave(client_events, broker_events)
        out = []
        size = [client_events.size, broker_events.size].max
        size.times do |idx|
          out << client_events[idx] if idx < client_events.size
          out << broker_events[idx] if idx < broker_events.size
        end
        out
      end

      private

      def new_flow
        {
          :publish => nil, :puback => [], :pubrec => [], :pubrel => [], :pubcomp => [],
          :qos => nil, :dup => false, :publisher => nil
        }
      end

      def peer(direction)
        direction == :client ? :broker : :client
      end

      # ---- phase 1: collect ----------------------------------------------

      def collect(frame)
        if frame.parse_error?
          @malformed << frame
          record_event('MALFORMED', frame.direction, frame, frame.parse_error, [])
          return
        end

        packet = frame.packet
        check_direction_legal(frame)
        case packet.type_name
        when 'CONNECT'     then collect_connect(frame)
        when 'CONNACK'     then @connacks << frame
        when 'PUBLISH'     then collect_publish(frame)
        when 'PUBACK'      then flow_for_ack(frame)[:puback] << frame
        when 'PUBREC'      then flow_for_ack(frame)[:pubrec] << frame
        # PUBREL is sent by the publisher (the same endpoint that sent
        # PUBLISH), so it joins the sender's own flow rather than the peer's.
        when 'PUBREL'      then @flows[frame.direction][frame.packet.id][:pubrel] << frame
        when 'PUBCOMP'     then flow_for_ack(frame)[:pubcomp] << frame
        when 'SUBSCRIBE'   then collect_subscribe(frame)
        when 'SUBACK'      then (@sub_responses[frame.packet.id] ||= []) << frame
        when 'UNSUBSCRIBE' then @unsub_requests[frame.packet.id] = frame
        when 'UNSUBACK'    then (@unsub_responses[frame.packet.id] ||= []) << frame
        when 'PINGREQ'     then @pingreqs << frame
        when 'PINGRESP'    then @pingresps << frame
        when 'DISCONNECT'  then record_event('DISCONNECT', :client, frame, {}, [])
        else
          record_event(packet.type_name, frame.direction, frame, 'packet type not modelled', [])
        end
      end

      # An acknowledgement references the flow owned by the publisher, which is
      # the peer direction of whoever sent the acknowledgement.
      def flow_for_ack(frame)
        @flows[peer(frame.direction)][frame.packet.id]
      end

      def collect_connect(frame)
        @connects << frame
        p = frame.packet
        detail = {
          'protocol' => "#{p.protocol_name}/#{p.protocol_level}",
          'client_id' => p.client_id,
          'clean_session' => p.clean_session,
          'keep_alive' => p.keep_alive,
          'username' => p.username, # declared only, never treated as authenticated
          'has_password' => !p.password.nil?,
          'will' => p.will_topic.nil? ? nil : { 'topic' => p.will_topic, 'qos' => p.will_qos }
        }
        record_event('CONNECT', :client, frame, compact(detail), [])
      end

      def collect_publish(frame)
        p = frame.packet
        flow = @flows[frame.direction][p.id]
        flow[:publish] = frame if flow[:publish].nil?
        flow[:extra_publishes] ||= []
        flow[:extra_publishes] << frame unless flow[:publish] == frame
        flow[:qos] = p.qos
        flow[:dup] = true if p.duplicate
        flow[:publisher] = frame.direction
        detail = {
          'topic' => p.topic, 'qos' => p.qos, 'retain' => p.retain,
          'dup' => p.duplicate, 'packet_id' => p.qos.zero? ? nil : p.id,
          'payload_bytes' => p.payload.to_s.bytesize
        }
        record_event('PUBLISH', frame.direction, frame, compact(detail), [])
      end

      def collect_subscribe(frame)
        p = frame.packet
        @sub_requests[p.id] = frame
        record_event('SUBSCRIBE', :client, frame,
                     { 'packet_id' => p.id,
                       'filters' => p.topics.map { |t, q| { 'filter' => t, 'qos' => q } } }, [])
      end

      # ---- phase 2: evaluate ---------------------------------------------

      def check_direction_legal(frame)
        name = frame.packet.type_name
        legal = frame.direction == :client ? CLIENT_TYPES : BROKER_TYPES
        return if legal.include?(name)

        add_finding(:violation, 'WRONG_DIRECTION',
                    "#{name} observed from #{frame.direction} is not a legal packet for that endpoint " \
                    'per MQTT 3.1.1 direction rules.',
                    [frame.ref], 'proven')
      end

      def evaluate_connection
        @connacks.each do |frame|
          p = frame.packet
          note = CONNACK_CODES[p.return_code] || "unknown return code 0x%02X" % p.return_code
          record_event('CONNACK', :broker, frame,
                       { 'return_code' => p.return_code, 'result' => note,
                         'session_present' => p.session_present,
                         'authenticated' => p.return_code.zero? ?
                           'broker accepted (capture asserts no identity)' : 'rejected' },
                       @connects.empty? ? [] : [@connects.first.ref])
        end

        if @connects.size > 1
          add_finding(:violation, 'MULTIPLE_CONNECT',
                      'More than one CONNECT on a single transport connection; MQTT allows exactly one.',
                      @connects.map(&:ref), 'proven')
        end
        if @connacks.size > 1
          add_finding(:violation, 'MULTIPLE_CONNACK',
                      'More than one CONNACK on a single transport connection is illegal.',
                      @connacks.map(&:ref), 'proven')
        end
        if @connects.empty?
          if @events.empty?
            add_finding(:gap, 'EMPTY_CAPTURE',
                        'No decodable frames were present in any fragment; nothing can be concluded about a session.',
                        [], 'unproven')
          else
            add_finding(:gap, 'NO_CONNECT',
                        'Capture begins mid-session: no CONNECT packet is present. Client identity, ' \
                        'credentials and authorisation state predate the observed bytes and stay unknown.',
                        [], 'unproven')
          end
        end
        if !@connects.empty? && @connacks.empty?
          add_finding(:gap, 'NO_CONNACK',
                      'CONNECT has no CONNACK in the capture (broker response may be outside the window).',
                      @connects.map(&:ref), 'unproven')
        end
        if !@connacks.empty? && @connects.empty?
          add_finding(:evidence, 'CONNACK_WITHOUT_CONNECT',
                      'CONNACK observed with no CONNECT in the captured data. If CONNECT predates the ' \
                      'capture this is a gap; the response has no provable request here.',
                      @connacks.map(&:ref), 'unproven')
        end
        rejected = @connacks.reject { |f| f.packet.return_code.zero? }
        rejected.each do |frame|
          note = CONNACK_CODES[frame.packet.return_code] || 'unknown code'
          add_finding(:evidence, 'CONNECTION_REJECTED',
                      "Broker rejected CONNECT (#{note}). The CONNECT username is only a client " \
                      'declaration; no authenticated identity is established.',
                      [frame.ref], 'proven')
        end
      end

      def evaluate_subscriptions
        @sub_requests.each do |id, frame|
          responses = @sub_responses.fetch(id, [])
          if responses.empty?
            add_finding(:gap, 'SUBACK_MISSING',
                        "SUBSCRIBE id #{id} has no SUBACK within the capture.",
                        [frame.ref], 'unproven')
          end
        end

        @sub_responses.each do |id, frames|
          request = @sub_requests[id]
          frames.each do |frame|
            record_event('SUBACK', :broker, frame,
                         { 'packet_id' => id, 'return_codes' => frame.packet.return_codes },
                         request.nil? ? [] : [request.ref])
          end
          if request.nil?
            add_finding(:evidence, 'UNSOLICITED_SUBACK',
                        "SUBACK id #{id} has no matching SUBSCRIBE in the capture (unsolicited response " \
                        'or a capture gap hiding the request).',
                        frames.map(&:ref), 'unproven')
          end
          if frames.size > 1
            add_finding(:violation, 'DUPLICATE_ACK',
                        "Multiple SUBACK for subscribe id #{id}: a subscription is acknowledged once.",
                        frames.map(&:ref), 'proven')
          end
          failed = frames.flat_map { |f| f.packet.return_codes }.select { |rc| SUBACK_FAILURE_CODES.include?(rc) }
          next if failed.empty?

          refs = frames.map(&:ref) + (request.nil? ? [] : [request.ref])
          add_finding(:evidence, 'SUBSCRIBE_FAILURE',
                      "Broker returned failure code 0x80 for #{failed.size} filter(s) in SUBACK id #{id}.",
                      refs, 'proven')
        end

        evaluate_unsubscribes
      end

      def evaluate_unsubscribes
        @unsub_requests.each do |id, frame|
          p = frame.packet
          record_event('UNSUBSCRIBE', :client, frame,
                       { 'packet_id' => id, 'filters' => p.topics }, [])
          add_finding(:gap, 'UNSUBACK_MISSING',
                      "UNSUBSCRIBE id #{id} has no UNSUBACK within the capture.",
                      [frame.ref], 'unproven') if @unsub_responses.fetch(id, []).empty?
        end
        @unsub_responses.each do |id, frames|
          request = @unsub_requests[id]
          frames.each do |frame|
            record_event('UNSUBACK', :broker, frame, { 'packet_id' => id },
                         request.nil? ? [] : [request.ref])
          end
          if request.nil?
            add_finding(:evidence, 'UNSOLICITED_UNSUBACK',
                        "UNSUBACK id #{id} has no matching UNSUBSCRIBE in the capture.",
                        frames.map(&:ref), 'unproven')
          end
          if frames.size > 1
            add_finding(:violation, 'DUPLICATE_ACK',
                        "Multiple UNSUBACK for unsubscribe id #{id}.",
                        frames.map(&:ref), 'proven')
          end
        end
      end

      def evaluate_pings
        @pingreqs.each { |f| record_event('PINGREQ', :client, f, {}, []) }
        @pingresps.each { |f| record_event('PINGRESP', :broker, f, {}, []) }
        if @pingresps.size > @pingreqs.size
          extra = @pingresps.size - @pingreqs.size
          add_finding(:evidence, 'UNSOLICITED_PINGRESP',
                      "#{extra} PINGRESP #{extra == 1 ? 'has' : 'have'} no matching PINGREQ in the capture " \
                      '(request may be in a capture gap).',
                      @pingresps.map(&:ref), 'unproven')
        end
        return unless @pingreqs.size > @pingresps.size

        missing = @pingreqs.size - @pingresps.size
        add_finding(:gap, 'PINGRESP_MISSING',
                    "#{missing} PINGREQ #{missing == 1 ? 'has' : 'have'} no PINGRESP within the capture.",
                    @pingreqs.map(&:ref), 'unproven')
      end

      def evaluate_flows
        record_flow_events
        (@flows[:client].values + @flows[:broker].values).each do |flow|
          next if flow[:publish].nil? && !flow_with_acks_only?(flow)

          evaluate_one_flow(flow)
        end
      end

      def flow_with_acks_only?(flow)
        flow[:publish].nil? &&
          (flow[:puback].any? || flow[:pubrec].any? || flow[:pubrel].any? || flow[:pubcomp].any?)
      end

      def record_flow_events
        # PUBLISH events were recorded at collection; record acknowledgement
        # events grouped by flow for a readable timeline.
        @flows.each do |_dir, map|
          map.each do |_id, flow|
            pub = flow[:publish]
            flow[:puback].each { |f| record_event('PUBACK', f.direction, f, { 'packet_id' => f.packet.id }, pub.nil? ? [] : [pub.ref]) }
            flow[:pubrec].each { |f| record_event('PUBREC', f.direction, f, { 'packet_id' => f.packet.id }, pub.nil? ? [] : [pub.ref]) }
            flow[:pubrel].each { |f| record_event('PUBREL', f.direction, f, { 'packet_id' => f.packet.id }, pub.nil? ? [] : [pub.ref]) }
            flow[:pubcomp].each { |f| record_event('PUBCOMP', f.direction, f, { 'packet_id' => f.packet.id }, pub.nil? ? [] : [pub.ref]) }
          end
        end
      end

      def evaluate_one_flow(flow)
        id = flow[:publish] && flow[:publish].packet.id
        id ||= first_ack_id(flow)
        refs = flow_refs(flow)

        detect_duplicate_steps(flow)
        detect_unsolicited(flow, id)
        detect_publish_reuse(flow)
        return if flow[:publish].nil? # remaining checks need an observed publish

        case flow[:qos]
        when 1
          add_finding(:gap, 'QOS1_NO_ACK',
                      "QoS1 PUBLISH id #{id} has no PUBACK in the capture; delivery completion is unproven, " \
                      'not evidence of non-delivery.',
                      refs, 'unproven') if flow[:puback].empty?
        when 2
          evaluate_qos2(flow, id, refs)
        end
      end

      def detect_duplicate_steps(flow)
        %i[puback pubrec pubrel pubcomp].each do |step|
          frames = flow[step]
          next if frames.size <= 1

          add_finding(:violation, 'DUPLICATE_ACK',
                      "Repeated #{step.upcase} for packet id #{first_ack_id(flow)}: a QoS handshake step " \
                      'may occur at most once per packet id.',
                      frames.map(&:ref), 'proven')
        end
      end

      def detect_unsolicited(flow, id)
        return unless flow[:publish].nil?

        labels = []
        labels << 'PUBACK' if flow[:puback].any?
        labels << 'PUBREC' if flow[:pubrec].any?
        labels << 'PUBREL' if flow[:pubrel].any?
        labels << 'PUBCOMP' if flow[:pubcomp].any?
        add_finding(:evidence, 'UNSOLICITED_ACK',
                    "#{labels.join('/')} for packet id #{id} has no PUBLISH in the capture. Either an " \
                    'unsolicited acknowledgement or the PUBLISH lies in a capture gap.',
                    flow_refs(flow), 'unproven')
      end

      def detect_publish_reuse(flow)
        extras = flow[:extra_publishes] || []
        return if extras.empty?

        all = ([flow[:publish]] + extras).compact
        without_dup = all.reject { |f| f.packet.duplicate }
        if without_dup.size > 1
          add_finding(:violation, 'PUBLISH_ID_REUSE',
                      "Packet id #{flow[:publish].packet.id} reused by multiple PUBLISH with DUP=0; ids must " \
                      'be unique while a flow is outstanding.',
                      all.map(&:ref), 'proven')
        else
          add_finding(:evidence, 'PUBLISH_RETRANSMIT',
                      "PUBLISH id #{flow[:publish].packet.id} retransmitted with DUP=1 (allowed retry, not an attack).",
                      all.map(&:ref), 'proven')
        end
      end

      # QoS 2 (MQTT 3.1.1 4.3.3): publisher PUBLISH -> receiver PUBREC ->
      # publisher PUBREL -> receiver PUBCOMP. Cross-direction ordering cannot be
      # proven without a shared clock, so only same-direction byte offsets are
      # used to establish a definite ordering violation.
      def evaluate_qos2(flow, id, refs)
        publisher = flow[:publisher]
        receiver = peer(publisher)

        missing = []
        missing << 'PUBREC' if flow[:pubrec].empty?
        missing << 'PUBREL' if flow[:pubrel].empty?
        missing << 'PUBCOMP' if flow[:pubcomp].empty?
        unless missing.empty?
          add_finding(:gap, 'QOS2_INCOMPLETE',
                      "QoS2 flow id #{id} is missing #{missing.join(', ')} within the capture; an incomplete " \
                      'handshake may reflect capture boundaries, not protocol abuse.',
                      refs, 'unproven')
        end

        # Publisher's own stream: PUBLISH must precede PUBREL.
        publish_frame = flow[:publish]
        flow[:pubrel].each do |pubrel|
          next unless pubrel.direction == publisher
          next if publish_frame.nil?

          if pubrel.byte_offset < publish_frame.byte_offset
            add_finding(:violation, 'QOS2_ORDER',
                        "Publisher sent PUBREL for id #{id} before its own PUBLISH in the byte stream.",
                        [pubrel.ref, publish_frame.ref], 'proven')
          end
        end

        # Receiver's own stream: PUBREC must precede PUBCOMP.
        pubrec = flow[:pubrec].first
        pubcomp = flow[:pubcomp].first
        return if pubrec.nil? || pubcomp.nil?
        return unless pubrec.direction == receiver && pubcomp.direction == receiver

        if pubcomp.byte_offset < pubrec.byte_offset
          add_finding(:violation, 'QOS2_ORDER',
                      "Receiver sent PUBCOMP for id #{id} before its PUBREC in the same byte stream.",
                      [pubcomp.ref, pubrec.ref], 'proven')
        end
      end

      def evaluate_malformed
        @malformed.each do |frame|
          add_finding(:evidence, 'MALFORMED_FRAME',
                      "Undecodable #{frame.direction} frame at offset #{frame.byte_offset}: " \
                      "#{frame.parse_error}. Treat as possible capture corruption/truncation, not proof of attack.",
                      [frame.ref], 'unproven')
        end
      end

      # ---- helpers --------------------------------------------------------

      def first_ack_id(flow)
        frame = %i[puback pubrec pubrel pubcomp].map { |s| flow[s].first }.compact.first
        frame.nil? ? nil : frame.packet.id
      end

      def flow_refs(flow)
        ([flow[:publish]] +
          flow[:puback] + flow[:pubrec] + flow[:pubrel] + flow[:pubcomp] +
          (flow[:extra_publishes] || [])).compact.map(&:ref)
      end

      def event_recorded?(frame)
        @events.any? { |e| e.frame.equal?(frame) }
      end

      def record_event(kind, direction, frame, detail, related)
        return if event_recorded?(frame) # each frame appears once in the timeline

        @events << Event.new(nil, kind, direction, frame, detail, Array(related))
      end

      def add_finding(severity, code, message, refs, status)
        @findings << Finding.new(severity, code, message, Array(refs), status)
      end

      def compact(hash)
        hash.reject { |_k, v| v.nil? }
      end

      def build_report
        Report.new(@capture, @events, @findings,
                   :connection_count => @connects.size,
                   :connect_seen => !@connects.empty?,
                   :connack_seen => !@connacks.empty?,
                   :timestamps_available => @capture.timestamps?)
      end
    end
  end
end
