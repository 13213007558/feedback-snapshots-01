# frozen_string_literal: true

module ProxyDiagnostics
  # One acceptance violation with a stable code and human-readable detail
  Violation = Struct.new(:code, :channel, :detail, keyword_init: true)

  # Check the three channels against a policy and expected sample values
  class Acceptance
    REQUIRED_PROXY = %w[Host User-Agent].freeze
    REQUIRED_ORIGIN = %w[Host User-Agent].freeze
    PROXY_ONLY = %w[Proxy-Authorization].freeze
    ORIGIN_ONLY = %w[Authorization Cookie].freeze

    def initialize(capture:, policy:, expected:)
      @capture = capture
      @policy = policy
      @expected = normalize_expected(expected)
    end

    # @return [Array<Violation>]
    def violations
      @violations ||=
        transport_violations + proxy_violations + origin_violations +
        event_violations + case_variant_violations
    end

    # @return [Array<Symbol>]
    def codes
      violations.map(&:code)
    end

    # Raise when any channel breaks its contract
    #
    # @return [void]
    # @raise [Minitest::Assertion] with every violation listed
    def verify!
      return if violations.empty?

      raise Minitest::Assertion, "proxy diagnostic acceptance failed:\n#{report}"
    end

    # Human-readable channel report, one violation per line
    #
    # @return [String]
    def report
      violations.map do |violation|
        format("  %s/%s: %s", violation.channel, violation.code, violation.detail)
      end.join("\n")
    end

    private

    def transport_violations
      checks = []
      transport = @capture.transport
      unless transport.connected_host == @expected[:proxy_address] &&
             transport.connected_port == @expected[:proxy_port]
        checks << violation(:proxy_endpoint_mismatch, :proxy,
                            "#{transport.connected_host}:#{transport.connected_port}")
      end
      return checks if transport.tls_host == @expected[:host]

      checks << violation(:tls_host_mismatch, :origin, transport.tls_host.inspect)
    end

    def proxy_violations
      request = @capture.proxy_request
      return [violation(:missing_proxy_request, :proxy)] unless request

      checks = []
      expected_line = "CONNECT #{@expected[:host]}:#{@expected[:port]} HTTP/1.1"
      checks << violation(:proxy_request_line, :proxy, request.headline) unless request.headline == expected_line

      required = REQUIRED_PROXY.dup
      required << "Proxy-Authorization" if @expected[:proxy_authenticated]
      required.each do |name|
        next if request.header(name)

        checks << violation(:missing_proxy_field, :proxy, name)
      end

      allowed = required.map { |name| ProxyDiagnostics.normalize(name) } + @policy.proxy_headers
      request.headers.each do |header|
        next if allowed.include?(header.key)

        checks << violation(:proxy_field_not_allowed, :proxy, header.name)
      end

      @expected[:origin_only].each do |name|
        next unless request.header(name)

        checks << violation(:proxy_received_origin_only_field, :proxy, name)
      end

      @expected[:proxy].each do |name, value|
        actual = request.header(name)
        next if actual == value

        checks << violation(:proxy_value_mismatch, :proxy, "#{name}=#{actual.inspect}")
      end

      checks
    end

    def origin_violations
      request = @capture.origin_request
      return [violation(:missing_origin_request, :origin)] unless request

      checks = []
      expected_line = "GET #{@expected[:target]} HTTP/1.1"
      checks << violation(:origin_request_line, :origin, request.headline) unless request.headline == expected_line

      REQUIRED_ORIGIN.each do |name|
        next if request.header(name)

        checks << violation(:missing_origin_field, :origin, name)
      end

      @expected[:origin].each do |name, value|
        actual = request.header(name)
        next if actual == value

        checks << violation(:origin_value_mismatch, :origin, "#{name}=#{actual.inspect}")
      end

      (PROXY_ONLY + @expected[:proxy_only]).each do |name|
        next unless request.header(name)

        checks << violation(:origin_received_proxy_only_field, :origin, name)
      end

      checks
    end

    def event_violations
      events = @capture.shareable_events
      return [violation(:missing_shareable_event, :event)] if events.empty?

      events.flat_map { |event| event_violations_for(event) }
    end

    def event_violations_for(event)
      payload = event.payload
      headers = payload[:headers]
      return [violation(:event_missing_headers, :event, event.name)] unless headers.is_a?(Array)

      checks = headers.filter_map do |header|
        next if @policy.shareable_headers.include?(header.key)

        violation(:event_field_not_allowed, :event, header.name)
      end

      names = headers.map(&:key)
      (@expected[:origin_only] + PROXY_ONLY + @expected[:proxy_only]).uniq.each do |name|
        next unless names.include?(ProxyDiagnostics.normalize(name))

        checks << violation(:event_leaked_channel_field, :event, name)
      end

      checks << violation(:event_kept_query, :event, payload[:uri]) if payload[:uri].to_s.include?("?")
      checks.concat(event_value_violations(headers))
      checks.concat(event_status_violations(event, payload))
      checks
    end

    def event_value_violations(headers)
      @expected[:event].filter_map do |name, value|
        actual = headers.find { |header| header.key == ProxyDiagnostics.normalize(name) }&.value
        next if actual == value

        violation(:event_value_mismatch, :event, "#{name}=#{actual.inspect}")
      end
    end

    def event_status_violations(event, payload)
      return [] unless event.name == "request.http" && event.phase == :finish

      status = payload.dig(:response, :status)
      return [] if status == @expected[:status]

      [violation(:event_status_mismatch, :event, status.inspect)]
    end

    def case_variant_violations
      @capture.reconciler.case_variant_duplicates.map do |duplicate|
        violation(:case_variant_duplicate, duplicate.channel,
                  "#{duplicate.key}: #{duplicate.spellings.join(', ')}")
      end
    end

    def normalize_expected(expected)
      {
        host:                expected.fetch(:host),
        port:                expected.fetch(:port),
        target:              expected.fetch(:target),
        status:              expected.fetch(:status),
        proxy_address:       expected.fetch(:proxy_address),
        proxy_port:          expected.fetch(:proxy_port),
        proxy_authenticated: expected.fetch(:proxy_authenticated, true),
        proxy:               normalize_values(expected.fetch(:proxy, {})),
        origin:              normalize_values(expected.fetch(:origin, {})),
        event:               normalize_values(expected.fetch(:event, {})),
        origin_only:         normalize_names(expected.fetch(:origin_only, ORIGIN_ONLY)),
        proxy_only:          normalize_names(expected.fetch(:proxy_only, []))
      }
    end

    def normalize_values(values)
      values.to_h { |name, value| [ProxyDiagnostics.normalize(name), value] }
    end

    def normalize_names(names)
      names.map { |name| ProxyDiagnostics.normalize(name) }
    end

    def violation(code, channel, detail = nil)
      Violation.new(code: code, channel: channel, detail: detail)
    end
  end
end
