# frozen_string_literal: true

module ProxyDiagnostics
  # The fixed CONNECT response used by the in-memory transport
  CONNECT_RESPONSE = "HTTP/1.1 200 Connection established\r\n\r\n"

  # A header as it appeared in a channel, preserving wire casing
  Header = Struct.new(:name, :value) do
    # @return [String] normalized name used for comparisons
    def key
      ProxyDiagnostics.normalize(name)
    end
  end

  # A request head parsed from captured bytes
  class WireRequest
    # Parse one captured request
    #
    # @param raw [String] captured bytes
    # @param phase [Symbol] :connect or :tunnel
    # @return [WireRequest]
    def self.parse(raw, phase:)
      head = raw.split("\r\n\r\n", 2).first.to_s
      lines = head.split("\r\n")
      headline = lines.shift.to_s
      headers = lines.filter_map do |line|
        name, value = line.split(": ", 2)
        Header.new(name, value.to_s) if value
      end

      new(phase: phase, headline: headline, headers: headers)
    end

    attr_reader :phase
    attr_reader :headline
    attr_reader :headers

    def initialize(phase:, headline:, headers:)
      @phase = phase
      @headline = headline
      @headers = headers.freeze
    end

    # All values for a name, compared case-insensitively
    #
    # @param name [String]
    # @return [Array<String>]
    def values(name)
      key = ProxyDiagnostics.normalize(name)
      headers.filter_map { |header| header.value if header.key == key }
    end

    # First value for a name, compared case-insensitively
    #
    # @param name [String]
    # @return [String, nil]
    def header(name)
      values(name).first
    end

    # Original wire names in this request
    #
    # @return [Array<String>]
    def names
      headers.map(&:name)
    end
  end

  # Scripted transport: records writes by phase and replays fixed responses
  class Transport
    Write = Struct.new(:phase, :bytes)

    attr_reader :connected_host
    attr_reader :connected_port
    attr_reader :writes
    attr_reader :tls_host

    def initialize(connect_response: CONNECT_RESPONSE, tunnel_response:)
      @responses = { connect: connect_response.dup, tunnel: tunnel_response.dup }
      @writes = []
      @phase = :connect
      @closed = false
    end

    # The timeout class the client instantiates for the connection
    #
    # @return [Class]
    def timeout_class
      transport = self

      Class.new do
        define_method(:initialize) { |**_options| nil }
        define_method(:connect) do |_socket_class, host, port, **|
          transport.record_connection(host, port)
        end
        define_method(:write) { |data| transport.write(data) }
        define_method(:readpartial) { |size, buffer = nil| transport.readpartial(size, buffer) }
        define_method(:start_tls) { |host, _ssl_socket_class, _ssl_context| transport.start_tls(host) }
        define_method(:close) { transport.close }
        define_method(:closed?) { transport.closed? }
      end
    end

    def record_connection(host, port)
      @connected_host = host
      @connected_port = port
    end

    def write(data)
      writes << Write.new(phase, data.dup)
      data.bytesize
    end

    def readpartial(size, buffer = nil)
      data = @responses[phase]
      return :eof if data.nil? || data.empty?

      chunk = data.byteslice(0, size)
      @responses[phase] = data.byteslice(chunk.bytesize..) || +""
      buffer ? buffer.replace(chunk) : chunk
    end

    def start_tls(host)
      @tls_host = host
      @phase = :tunnel
    end

    def close
      @closed = true
    end

    def closed?
      @closed
    end

    # Bytes written during one phase
    #
    # @param phase [Symbol]
    # @return [String, nil]
    def bytes_for(phase)
      chunks = writes.filter_map { |write| write.bytes if write.phase == phase }
      return if chunks.empty?

      chunks.join
    end

    private

    attr_reader :phase
  end

  # Instrumenter that keeps every payload handed to start/finish
  class Recorder < HTTP::Features::Instrumentation::NullInstrumenter
    Event = Struct.new(:name, :phase, :payload, keyword_init: true)

    attr_reader :events

    def initialize
      super
      @events = []
    end

    def start(name, payload)
      events << Event.new(name: name, phase: :start, payload: payload.dup)
    end

    def finish(name, payload)
      events << Event.new(name: name, phase: :finish, payload: payload.dup)
    end
  end

  # A projected event payload
  ShareableEvent = Struct.new(:name, :phase, :payload, keyword_init: true) do
    # Projected headers as a Hash, with the first value for repeated names
    #
    # @return [Hash{String => String}]
    def headers
      payload[:headers].to_h { |header| [header.name, header.value] }
    end

    # All projected request values for a name, compared case-insensitively
    #
    # @param name [String]
    # @return [Array<String>]
    def values(name)
      key = ProxyDiagnostics.normalize(name)
      payload[:headers].filter_map { |header| header.value if header.key == key }
    end

    # Projected response headers as a Hash, if the event has a response
    #
    # @return [Hash{String => String}, nil]
    def response_headers
      response = payload[:response]
      return unless response

      response[:headers].to_h { |header| [header.name, header.value] }
    end
  end

  # Result of one captured exchange
  class Capture
    attr_reader :transport
    attr_reader :recorder
    attr_reader :policy
    attr_reader :response
    attr_reader :body

    def initialize(transport:, recorder:, policy:, response:, body:)
      @transport = transport
      @recorder = recorder
      @policy = policy
      @response = response
      @body = body
    end

    # @return [WireRequest, nil]
    def proxy_request
      @proxy_request ||= parse(:connect)
    end

    # @return [WireRequest, nil]
    def origin_request
      @origin_request ||= parse(:tunnel)
    end

    # @return [String, nil]
    def proxy_bytes
      transport.bytes_for(:connect)
    end

    # @return [String, nil]
    def origin_bytes
      transport.bytes_for(:tunnel)
    end

    # The raw payload of the main request finish event
    #
    # Unlike {#shareable_events}, this payload still holds the live Request and
    # Response objects, including proxy credentials. It models what an
    # instrumenter receives before projection.
    #
    # @return [Hash, nil]
    def raw_finished_payload
      event = recorder.events.find { |item| item.name == "request.http" && item.phase == :finish }
      event&.payload
    end

    # Project every recorded event through the policy
    #
    # @return [Array<ShareableEvent>]
    def shareable_events
      @shareable_events ||= recorder.events.map do |event|
        ShareableEvent.new(
          name:    event.name,
          phase:   event.phase,
          payload: project(event.payload)
        )
      end
    end

    # The finish event for the main request span, if any
    #
    # @return [ShareableEvent, nil]
    def finished_request_event
      shareable_events.find { |event| event.name == "request.http" && event.phase == :finish }
    end

    # Reconcile fields from all three channels by normalized name
    #
    # @return [Reconciler]
    def reconciler
      @reconciler ||= Reconciler.new(proxy_entries + origin_entries + event_entries)
    end

    private

    def parse(phase)
      raw = transport.bytes_for(phase)
      return if raw.nil? || raw.empty?

      WireRequest.parse(raw, phase: phase)
    end

    def project(payload)
      @policy.project(payload[:request], payload[:response])
    end

    def proxy_entries
      wire_entries(proxy_request, :proxy)
    end

    def origin_entries
      wire_entries(origin_request, :origin)
    end

    def event_entries
      finished = finished_request_event
      return [] unless finished

      finished.payload[:headers].map do |header|
        Reconciler::Entry.new(channel: :event, name: header.name, value: header.value)
      end
    end

    def wire_entries(request, channel)
      return [] unless request

      request.headers.map do |header|
        Reconciler::Entry.new(channel: channel, name: header.name, value: header.value)
      end
    end
  end

  # Group captured fields by normalized name across channels
  class Reconciler
    Entry = Struct.new(:channel, :name, :value) do
      # @return [String] normalized name
      def key
        ProxyDiagnostics.normalize(name)
      end
    end

    CaseVariant = Struct.new(:channel, :key, :spellings, keyword_init: true)

    attr_reader :entries

    def initialize(entries)
      @entries = entries.freeze
    end

    # Entries whose normalized name matches
    #
    # @param name [String, Symbol]
    # @return [Array<Entry>]
    def matching(name)
      key = ProxyDiagnostics.normalize(name)
      entries.select { |entry| entry.key == key }
    end

    # Channels in which the field appears, in capture order
    #
    # @param name [String, Symbol]
    # @return [Array<Symbol>]
    def channels(name)
      matching(name).map(&:channel).uniq
    end

    # Original spellings per channel
    #
    # @param name [String, Symbol]
    # @return [Hash{Symbol => Array<String>}]
    def spellings(name)
      matching(name).group_by(&:channel).transform_values { |group| group.map(&:name).uniq }
    end

    # Values per channel
    #
    # @param name [String, Symbol]
    # @return [Hash{Symbol => Array<String>}]
    def values(name)
      matching(name).group_by(&:channel).transform_values { |group| group.map(&:value).uniq }
    end

    # Fields repeated under different spellings within one channel
    #
    # @return [Array<CaseVariant>]
    def case_variant_duplicates
      entries.group_by { |entry| [entry.channel, entry.key] }.filter_map do |(channel, key), group|
        spellings = group.map(&:name).uniq
        next unless spellings.size > 1

        CaseVariant.new(channel: channel, key: key, spellings: spellings)
      end
    end
  end
end

module ProxyDiagnostics
  # Run one HTTPS request through the proxy using only memory
  #
  # @param policy [Policy]
  # @param headers [Hash] application request headers
  # @param proxy [Hash] raw proxy options, before policy constraint
  # @param uri [String] origin URI
  # @param tunnel_response [String] scripted origin response
  # @return [Capture]
  def self.capture(policy:, headers:, proxy:, uri:, tunnel_response: default_tunnel_response)
    recorder = Recorder.new
    transport = Transport.new(tunnel_response: tunnel_response)
    client = HTTP::Client.new(
      timeout_class:    transport.timeout_class,
      socket_class:     Object,
      ssl_socket_class: Object,
      headers:          headers,
      proxy:            policy.constrain_proxy(proxy),
      features:         { instrumentation: { instrumenter: recorder } }
    )
    response = client.get(uri)
    body = response.to_s

    Capture.new(transport: transport, recorder: recorder, policy: policy, response: response, body: body)
  ensure
    client&.close
  end

  # A scripted origin response with a JSON body
  #
  # @param body [String]
  # @param status [Integer]
  # @return [String]
  def self.default_tunnel_response(body: '{"ok":true}', status: 200)
    "HTTP/1.1 #{status} OK\r\n" \
      "Content-Type: application/json\r\n" \
      "Content-Length: #{body.bytesize}\r\n" \
      "Connection: close\r\n" \
      "\r\n#{body}"
  end
end
