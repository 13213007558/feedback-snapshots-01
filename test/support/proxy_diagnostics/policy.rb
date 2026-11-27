# frozen_string_literal: true

module ProxyDiagnostics
  # Channel-scoped allowlists for proxy metadata and shareable events
  class Policy
    # @return [Array<String>] normalized names allowed at the proxy
    attr_reader :proxy_headers

    # @return [Array<String>] normalized names allowed in shareable events
    attr_reader :shareable_headers

    def initialize(proxy_headers:, shareable_headers:)
      @proxy_headers = normalize_all(proxy_headers)
      @shareable_headers = normalize_all(shareable_headers)
    end

    # Remove proxy headers that are not on the proxy allowlist
    #
    # Address, port, and credentials are untouched; only extra headers are
    # filtered. Header spelling is preserved.
    #
    # @param proxy [Hash]
    # @return [Hash]
    def constrain_proxy(proxy)
      return proxy unless proxy.key?(:proxy_headers)

      kept = select(proxy[:proxy_headers], proxy_headers)
      proxy.merge(proxy_headers: to_hash(kept))
    end

    # Project a request/response pair into a shareable event payload
    #
    # The projection carries no Request or Response object, no proxy
    # credentials, no URI userinfo, no query string, and no header that is
    # outside the shareable allowlist.
    #
    # @param request [HTTP::Request]
    # @param response [HTTP::Response, nil]
    # @return [Hash]
    def project(request, response = nil)
      payload = {
        verb:    request.verb,
        uri:     shareable_uri(request.uri),
        headers: select(request.headers, shareable_headers)
      }
      payload[:response] = response_projection(response) unless response.nil?
      payload
    end

    private

    def normalize_all(names)
      names.map { |name| ProxyDiagnostics.normalize(name) }.freeze
    end

    def select(headers, allowed)
      pairs = []
      headers.each do |name, value|
        next unless allowed.include?(ProxyDiagnostics.normalize(name))

        Array(value).each { |item| pairs << Header.new(name.to_s, item.to_s) }
      end
      pairs
    end

    def to_hash(pairs)
      pairs.each_with_object({}) do |header, hash|
        if hash.key?(header.name)
          hash[header.name] = Array(hash[header.name]) << header.value
        else
          hash[header.name] = header.value
        end
      end
    end

    def shareable_uri(uri)
      uri.omit(:user, :password, :query, :fragment).to_s
    end

    def response_projection(response)
      {
        status:  response.status.code,
        headers: select(response.headers, shareable_headers)
      }
    end
  end

  # A deliberately incomplete policy used by the preset regression
  #
  # It projects events onto the shareable allowlist but leaves the proxy
  # stage alone, so proxy-only fields still reach the wire.
  class EventOnlyPolicy < Policy
    def constrain_proxy(proxy)
      proxy
    end
  end
end
