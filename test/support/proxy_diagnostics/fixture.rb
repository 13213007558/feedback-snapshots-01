# frozen_string_literal: true

module ProxyDiagnostics
  # Ordinary test fields drawn from several sources.
  #
  # Each value carries its channel in a suffix, so a leak is obvious: a value
  # found in the wrong capture says where it came from. Names overlap between
  # sources ("X-Request-Id") while spellings differ in case, which exercises
  # case-insensitive reconciliation without collapsing distinct wire names.
  module Fixture
    PROXY_ADDRESS   = "proxy.internal.test"
    PROXY_PORT      = 8080
    PROXY_USER      = "proxy-user"
    PROXY_PASSWORD  = "proxy-password"
    ORIGIN_HOST     = "origin.internal.test"
    ORIGIN_PORT     = 443
    ORIGIN_TARGET   = "/v1/orders"
    ORIGIN_QUERY    = "access_token=origin-secret"
    RESPONSE_STATUS = 200

    # Fields only the origin may see
    ORIGIN_ONLY = {
      "Authorization" => "Bearer app-origin-token",
      "Cookie"        => "session=app-cookie"
    }.freeze

    # Fields intended for the proxy channel, spelled like the app's fields
    PROXY_EXTRA = {
      "X-Proxy-Route" => "egress-a",
      "X-Request-Id"  => "proxy-request-id",
      "X-Tenant"      => "tenant-proxy"
    }.freeze

    # Application headers. "x-request-id" is deliberately spelled in lower
    # case while the proxy field uses "X-Request-Id", and "X-Tenant" is
    # deliberately shared with a proxy field carrying a different value.
    APP_HEADERS = {
      "Accept"       => "application/json",
      "x-request-id" => "app-request-id",
      "X-Tenant"     => "tenant-app"
    }.merge(ORIGIN_ONLY).freeze

    # Response headers: two may be shared, two must stay in the exchange
    RESPONSE_HEADERS = {
      "Content-Type"       => "application/json",
      "X-Request-Id"       => "origin-request-id",
      "Set-Cookie"         => "server=origin-cookie",
      "Proxy-Authenticate" => 'Basic realm="proxy"'
    }.freeze

    # Allowlist for the proxy channel. It deliberately says nothing about
    # application credentials, so the policy must filter dynamically rather
    # than mirror whatever the proxy hash happens to carry.
    PROXY_ALLOWLIST = ["X-Proxy-Route", "X-Request-Id", "X-Tenant"].freeze

    # Allowlist for shareable events
    SHAREABLE_ALLOWLIST = ["Accept", "Content-Type", "X-Request-Id"].freeze

    # Build proxy options as the application would configure them
    #
    # @return [Hash]
    def self.proxy
      {
        proxy_address:  PROXY_ADDRESS,
        proxy_port:     PROXY_PORT,
        proxy_username: PROXY_USER,
        proxy_password: PROXY_PASSWORD,
        proxy_headers:  PROXY_EXTRA
      }
    end

    # Build proxy options with application credentials accidentally placed in
    # the extra proxy headers, modelling a misconfiguration the proxy-stage
    # constraint has to remove.
    #
    # @return [Hash]
    def self.leaky_proxy
      proxy.merge(proxy_headers: PROXY_EXTRA.merge(ORIGIN_ONLY))
    end

    # Build the origin URI
    #
    # @return [String]
    def self.uri
      "https://#{ORIGIN_HOST}#{ORIGIN_TARGET}?#{ORIGIN_QUERY}"
    end

    # Build a scripted origin response
    #
    # @return [String]
    def self.tunnel_response
      body = '{"orders":[]}'
      lines = ["HTTP/1.1 #{RESPONSE_STATUS} OK"]
      RESPONSE_HEADERS.each { |name, value| lines << "#{name}: #{value}" }
      lines << "Content-Length: #{body.bytesize}"
      lines << "Connection: close"
      "#{lines.join("\r\n")}\r\n\r\n#{body}"
    end

    # Build the policy under test
    #
    # @return [Policy]
    def self.policy
      Policy.new(proxy_headers: PROXY_ALLOWLIST, shareable_headers: SHAREABLE_ALLOWLIST)
    end

    # Build the preset regression policy: events only, proxy untouched
    #
    # @return [EventOnlyPolicy]
    def self.event_only_policy
      EventOnlyPolicy.new(proxy_headers: PROXY_ALLOWLIST, shareable_headers: SHAREABLE_ALLOWLIST)
    end

    # Expected values for each channel
    #
    # @return [Hash]
    def self.expectations
      {
        host:                ORIGIN_HOST,
        port:                ORIGIN_PORT,
        target:              "#{ORIGIN_TARGET}?#{ORIGIN_QUERY}",
        status:              RESPONSE_STATUS,
        proxy_address:       PROXY_ADDRESS,
        proxy_port:          PROXY_PORT,
        proxy_authenticated: true,
        proxy:               PROXY_EXTRA,
        origin:              APP_HEADERS,
        event:               { "Accept" => "application/json", "x-request-id" => "app-request-id" },
        origin_only:         ORIGIN_ONLY.keys,
        proxy_only:          ["X-Proxy-Route", "Proxy-Authenticate"]
      }
    end

    # Run the fixture through the in-memory capture
    #
    # @param policy [Policy]
    # @param proxy [Hash] proxy options, before the policy constrains them
    # @return [Capture]
    def self.capture(policy: self.policy, proxy: self.proxy)
      ProxyDiagnostics.capture(
        policy:          policy,
        headers:         APP_HEADERS,
        proxy:           proxy,
        uri:             uri,
        tunnel_response: tunnel_response
      )
    end
  end
end
