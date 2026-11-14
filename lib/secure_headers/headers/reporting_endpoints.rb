# frozen_string_literal: true
require "uri"

module SecureHeaders
  class ReportingEndpointsConfigError < StandardError; end

  # Raised when a CSP report_to reference cannot be resolved in the same
  # request configuration that will be used to generate the Reporting-Endpoints
  # header.
  class ReportingEndpointReferenceError < ReportingEndpointsConfigError; end

  class ReportingEndpoints
    HEADER_NAME = "reporting-endpoints".freeze

    # Reporting endpoint names are Structured Headers dictionary keys. Restricting
    # them to that grammar keeps quotes, backslashes, separators, whitespace,
    # control characters and non-ASCII bytes out of both the Reporting-Endpoints
    # header and the report-to CSP directive.
    ENDPOINT_NAME_PATTERN = /\A[a-z][a-z0-9_.\-]*\z/.freeze

    class << self
      # Public: generate a Reporting-Endpoints header.
      #
      # The config should be a Hash of endpoint names to URLs.
      # Example: { "csp-endpoint" => "https://example.com/reports" }
      #
      # Returns nil if config is OPT_OUT or nil, or a header name and
      # formatted header value based on the config.
      def make_header(config = nil)
        return if config.nil? || config == OPT_OUT
        [HEADER_NAME, format_endpoints(normalized_endpoints(config))]
      end

      # Public: validates a Reporting-Endpoints configuration.
      #
      # URL values are validated as absolute HTTPS URLs and normalized. Non-ASCII
      # path, query, and fragment characters are percent-encoded so the emitted
      # header is valid ASCII while still addressing the intended resource.
      def validate_config!(config)
        case config
        when nil, OPT_OUT
          # valid
        when Hash
          normalized_endpoints(config)
        else
          raise TypeError.new("Must be a Hash of endpoint names to URLs. Found #{config.class}: #{config}")
        end
      end

      # Public: returns a normalized `name => URL` hash. Names are converted to
      # strings, duplicate names are rejected, and URLs are validated and
      # percent-encoded.
      def normalized_endpoints(config)
        unless config.is_a?(Hash)
          raise TypeError.new("Must be a Hash of endpoint names to URLs. Found #{config.class}: #{config}")
        end

        seen_names = {}
        config.each_pair.each_with_object({}) do |(raw_name, raw_url), endpoints|
          name = canonical_name!(raw_name)
          if seen_names.key?(name)
            raise ReportingEndpointsConfigError.new("Duplicate reporting endpoint name after normalization: #{name.inspect}")
          end
          seen_names[name] = true
          endpoints[name] = canonical_url!(raw_url)
        end
      end

      # Public: validates that every report_to reference in the given CSP
      # policies is defined in the same Reporting-Endpoints map.
      #
      # A single request configuration can contain an enforced and a report-only
      # policy. Both reference names from the same map, so a name always resolves
      # to exactly one explicit destination within that configuration.
      #
      # Returns the normalized endpoint map.
      def validate_references!(endpoints, policies)
        references = Array(policies).compact.each_with_object([]) do |policy, result|
          next if policy == OPT_OUT || policy.respond_to?(:opt_out?) && policy.opt_out?

          name = policy.directive_value(:report_to)
          next if name.nil? || name == OPT_OUT

          unless name.is_a?(String) && ENDPOINT_NAME_PATTERN.match?(name)
            raise ReportingEndpointsConfigError.new("report_to must be a valid reporting endpoint name, got: #{name.inspect}")
          end
          result << name
        end

        if references.empty?
          return {} if endpoints.nil? || endpoints == OPT_OUT
          return normalized_endpoints(endpoints)
        end

        if endpoints.nil? || endpoints == OPT_OUT
          raise ReportingEndpointReferenceError.new(
            "report_to references #{references.uniq.map(&:inspect).join(', ')} but reporting_endpoints is not configured"
          )
        end

        normalized = normalized_endpoints(endpoints)
        references.each do |name|
          unless normalized.key?(name)
            raise ReportingEndpointReferenceError.new(
              "report_to references undefined reporting endpoint #{name.inspect} (dangling reference)"
            )
          end
        end

        normalized
      end

      private

      def canonical_name!(raw_name)
        name = raw_name.is_a?(Symbol) ? raw_name.to_s : raw_name
        unless name.is_a?(String) && !name.empty?
          raise ReportingEndpointsConfigError.new("Endpoint name must be a non-empty string, got: #{raw_name.inspect}")
        end
        unless name.valid_encoding? && ENDPOINT_NAME_PATTERN.match?(name)
          raise ReportingEndpointsConfigError.new("Endpoint name must be a lowercase structured-header key, got: #{raw_name.inspect}")
        end
        name
      end

      def canonical_url!(raw_url)
        unless raw_url.is_a?(String) && !raw_url.empty?
          raise ReportingEndpointsConfigError.new("Endpoint URL must be a non-empty string, got: #{raw_url.inspect}")
        end
        unless raw_url.valid_encoding?
          raise ReportingEndpointsConfigError.new("Endpoint URL must be valid UTF-8, got: #{raw_url.inspect}")
        end
        unless raw_url.start_with?("https://")
          raise ReportingEndpointsConfigError.new("Endpoint URLs must use https, got: #{raw_url.inspect}")
        end
        if unsafe_url_character?(raw_url)
          raise ReportingEndpointsConfigError.new("Endpoint URL must not contain quotes, backslashes, whitespace, or control characters, got: #{raw_url.inspect}")
        end

        authority = raw_url.delete_prefix("https://").split(/[\/?#]/, 2).first
        if authority.nil? || authority.empty? || !authority.ascii_only? || authority.include?("%")
          raise ReportingEndpointsConfigError.new("Endpoint URL must contain an ASCII host, got: #{raw_url.inspect}")
        end

        encoded_url = encode_non_ascii(raw_url)
        begin
          uri = URI.parse(encoded_url)
        rescue URI::InvalidURIError
          raise ReportingEndpointsConfigError.new("Endpoint URL is not a valid absolute HTTPS URL, got: #{raw_url.inspect}")
        end

        unless uri.is_a?(URI::HTTPS) && uri.host && !uri.host.empty?
          raise ReportingEndpointsConfigError.new("Endpoint URL is not a valid absolute HTTPS URL, got: #{raw_url.inspect}")
        end

        encoded_url
      end

      # Reject raw bytes that could terminate the quoted URL, start another
      # header, or smuggle a separator into the Structured Headers value. C1
      # controls are rejected as well as their ASCII counterparts.
      def unsafe_url_character?(url)
        url.each_char.any? do |char|
          codepoint = char.ord
          codepoint <= 0x20 || codepoint == 0x7F || (codepoint >= 0x80 && codepoint <= 0x9F) ||
            char == '"' || char == "\\"
        end
      end

      # Percent-encode every non-ASCII character. Existing ASCII percent escapes
      # are left intact, and URI.parse still rejects malformed escapes.
      def encode_non_ascii(url)
        url.each_char.map do |char|
          if char.ord < 0x80
            char
          else
            char.bytes.map { |byte| format("%%%02X", byte) }.join
          end
        end.join
      end

      def format_endpoints(config)
        config.map do |name, url|
          %{#{name}="#{url}"}
        end.join(", ")
      end
    end
  end
end
