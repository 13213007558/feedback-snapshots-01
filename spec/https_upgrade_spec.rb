require_relative "spec_helper"
require "rack/builder"
require "stringio"
require "uri"

module HttpsUpgrade
  CANONICAL_HOST = "tickets.example.com"
  CANONICAL_PORT = 8443
  HTTP_PORT = 8080
  INTERNAL_HOST = "ticket-app.internal"
  INTERNAL_PORT = 9292
  TRUSTED_PROXY_ADDR = "10.42.0.10"
  CLIENT_ADDR = "203.0.113.7"

  PREFIXES = %w'/support /service-desk'.freeze
  TICKET_ROUTE_PATH = "/tickets/T-100%2042%2B1".freeze
  TICKET_QUERY = "tag=urgent&tag=vip%20mail".freeze
  TICKET_PATH = "#{TICKET_ROUTE_PATH}?#{TICKET_QUERY}".freeze
  REDIRECT_STATUSES = [301, 302, 303, 307, 308].freeze
  MAX_HOPS = 4

  TicketWrite = Struct.new(:verb, :scheme, :site, :mount, :remaining, :id, :query, :tag, :body)
  Hop = Struct.new(:verb, :uri, :status, :location, :site, :mount, :remaining, :writes, :body)

  # Rack 1.x returns the port as part of Request#host, while Rack 2+ does not.
  def self.site(request)
    request.host.to_s.sub(/:\d+\z/, "")
  end

  # Test-stack adapter for the trusted proxy.  Forwarding headers supplied by
  # the client are discarded.  Proxy transport metadata comes from the test
  # driver using a private environment key, and is only converted into
  # forwarding headers here, after the request has entered the stack.
  class TrustedProxyTransport
    FORWARDED_ENV_KEYS = %w[
      HTTP_FORWARDED
      HTTP_X_FORWARDED_FOR
      HTTP_X_FORWARDED_HOST
      HTTP_X_FORWARDED_PORT
      HTTP_X_FORWARDED_PROTO
      HTTP_X_FORWARDED_SCHEME
      HTTP_X_FORWARDED_SSL
    ].freeze

    def initialize(app)
      @app = app
    end

    def call(env)
      proxy = env.delete("test.proxy_transport")
      FORWARDED_ENV_KEYS.each{|key| env.delete(key)}

      if proxy
        env["REMOTE_ADDR"] = TRUSTED_PROXY_ADDR
        env["HTTP_X_FORWARDED_FOR"] = CLIENT_ADDR
        env["HTTP_X_FORWARDED_PROTO"] = proxy.fetch(:proto)
        env["HTTP_X_FORWARDED_HOST"] = proxy.fetch(:host)
        env["HTTP_X_FORWARDED_PORT"] = proxy[:port].to_s
      end

      @app.call(env)
    end
  end

  # Records the external site and mount information seen by each hop.  The
  # values are exposed as response headers so they remain available after the
  # response body has been consumed by the test driver.
  class MountRecorder
    def initialize(app, writes)
      @app = app
      @writes = writes
    end

    def call(env)
      request = Rack::Request.new(env)
      site = HttpsUpgrade.site(request)
      mount = env["SCRIPT_NAME"].to_s
      remaining = env["PATH_INFO"].to_s

      status, headers, body = @app.call(env)

      headers = headers.dup
      headers["x-hop-site"] = site
      headers["x-hop-mount"] = mount
      headers["x-hop-remaining"] = remaining
      headers["x-hop-writes"] = @writes.length.to_s

      [status, headers, body]
    end
  end

  class Harness
    attr_reader :writes

    def initialize
      @writes = []
      handler = build_handler
      gateway = Class.new(Roda)
      gateway.route{|r| r.run handler}
      writes = @writes

      @stack = Rack::Builder.new do
        # Translate proxy transport metadata before Lint validates the
        # environment, so Lint sees exactly what the application receives.
        use TrustedProxyTransport

        use Rack::Lint if ENV["LINT"]

        map(HttpsUpgrade::PREFIXES[0]) do
          use MountRecorder, writes
          run gateway
        end

        map(HttpsUpgrade::PREFIXES[1]) do
          use MountRecorder, writes
          run gateway
        end
      end.to_app
    end

    def request(method, uri, opts={})
      env = build_env(method, uri, opts[:transport], opts[:body], opts[:headers])
      status, response_headers, response_body = @stack.call(env)

      payload = String.new
      response_body.each{|chunk| payload << chunk}
      response_body.close if response_body.respond_to?(:close)

      Hop.new(
        method,
        uri.to_s,
        status,
        header(response_headers, "location"),
        header(response_headers, "x-hop-site"),
        header(response_headers, "x-hop-mount"),
        header(response_headers, "x-hop-remaining"),
        header(response_headers, "x-hop-writes").to_i,
        payload
      )
    end

    # Follow redirects using the actual Location and status returned by the
    # previous hop.  303 switches to GET.  301/302 switch POST to GET, matching
    # browser behavior.  307/308 retain the original method and request body.
    def follow(method, uri, opts={})
      hops = []
      current_method = method
      current_body = opts[:body]
      current_uri = uri

      loop do
        raise "too many redirects for #{uri}" if hops.length >= MAX_HOPS

        hop = request(current_method, current_uri, :transport=>opts[:transport], :body=>current_body)
        hops << hop
        break unless REDIRECT_STATUSES.include?(hop.status) && hop.location

        current_uri = URI.parse(hop.location)
        current_uri = uri.merge(current_uri) unless current_uri.absolute?

        case hop.status
        when 303
          current_method = "GET"
          current_body = nil
        when 301, 302
          if current_method == "POST"
            current_method = "GET"
            current_body = nil
          end
        end
      end

      hops
    end

    private

    def build_handler
      writes = @writes
      record = lambda do |r, id, request_body|
        writes << TicketWrite.new(
          r.request_method,
          r.scheme,
          HttpsUpgrade.site(r),
          r.script_name,
          r.path_info,
          id,
          r.query_string,
          r.GET["tag"],
          request_body
        )

        "ticket #{id}"
      end

      handler = Class.new(Roda)
      handler.plugin :head
      handler.plugin :host_authorization, [CANONICAL_HOST], :check_forwarded=>true
      handler.plugin :redirect_http_to_https, :host=>CANONICAL_HOST, :port=>CANONICAL_PORT

      handler.route do |r|
        check_host_authorization!

        r.get "health" do
          "healthy"
        end

        r.redirect_http_to_https

        r.get "tickets", String do |id|
          record.call(r, id, nil)
        end

        r.post "tickets", String do |id|
          record.call(r, id, r.body.read)
        end
      end

      handler
    end

    def build_env(method, uri, transport, body, headers)
      env = {
        "REQUEST_METHOD" => method,
        "SERVER_PROTOCOL" => "HTTP/1.1",
        "SCRIPT_NAME" => "",
        "PATH_INFO" => uri.path,
        "QUERY_STRING" => uri.query.to_s,
        "rack.input" => StringIO.new(body.to_s.b),
        "rack.errors" => StringIO.new
      }
      env["CONTENT_LENGTH"] = body.bytesize.to_s if body
      env["CONTENT_TYPE"] = "application/x-www-form-urlencoded" if method == "POST"

      if transport == :proxy
        env["SERVER_NAME"] = INTERNAL_HOST
        env["SERVER_PORT"] = INTERNAL_PORT.to_s
        env["HTTP_HOST"] = "#{INTERNAL_HOST}:#{INTERNAL_PORT}"
        env["rack.url_scheme"] = "http"
        env["HTTPS"] = "off"
        env["REMOTE_ADDR"] = TRUSTED_PROXY_ADDR
        env["test.proxy_transport"] = {:proto=>uri.scheme, :host=>authority(uri), :port=>uri.port}
      else
        env["SERVER_NAME"] = uri.host
        env["SERVER_PORT"] = uri.port.to_s
        env["HTTP_HOST"] = authority(uri)
        env["rack.url_scheme"] = uri.scheme
        env["HTTPS"] = uri.scheme == "https" ? "on" : "off"
        env["REMOTE_ADDR"] = CLIENT_ADDR
      end

      # Rack < 2.3 Lint requires these keys.
      if Rack.release < "2.3"
        env["rack.version"] = [1, 5]
        env["rack.multithread"] = env["rack.multiprocess"] = env["rack.run_once"] = false
      end

      env.merge!(headers) if headers
      env
    end

    def authority(uri)
      if uri.port && uri.port != uri.default_port
        "#{uri.host}:#{uri.port}"
      else
        uri.host
      end
    end

    def header(headers, name)
      key = headers.keys.find{|header| header.to_s.downcase == name}
      key && headers[key]
    end
  end
end

describe "HTTPS upgrade through mounted Roda delegation" do
  def canonical_host
    HttpsUpgrade::CANONICAL_HOST
  end

  def canonical_port
    HttpsUpgrade::CANONICAL_PORT
  end

  def prefixes
    HttpsUpgrade::PREFIXES
  end

  def ticket_route_path
    HttpsUpgrade::TICKET_ROUTE_PATH
  end

  def ticket_query
    HttpsUpgrade::TICKET_QUERY
  end

  def ticket_path
    HttpsUpgrade::TICKET_PATH
  end

  before do
    @harness = HttpsUpgrade::Harness.new
  end

  def external_uri(prefix, path: ticket_path, scheme: "http")
    port = scheme == "https" ? canonical_port : HttpsUpgrade::HTTP_PORT
    URI.parse("#{scheme}://#{canonical_host}:#{port}#{prefix}#{path}")
  end

  def upgraded_uri(prefix, path: ticket_path)
    external_uri(prefix, path: path, scheme: "https")
  end

  def interleaved_flows
    [
      [prefixes[0], :direct],
      [prefixes[1], :proxy],
      [prefixes[1], :direct],
      [prefixes[0], :proxy]
    ]
  end

  def expected_location(prefix, path: ticket_path)
    "https://#{canonical_host}:#{canonical_port}#{prefix}#{path}"
  end

  it "serves the health endpoint over HTTP under each mount for direct and proxied requests" do
    [[prefixes[0], :direct], [prefixes[1], :direct], [prefixes[0], :proxy], [prefixes[1], :proxy]].each do |prefix, transport|
      hops = @harness.follow("GET", external_uri(prefix, path: "/health"), :transport=>transport)

      hops.length.must_equal 1
      hop = hops.first
      hop.status.must_equal 200
      hop.body.must_equal "healthy"
      hop.site.must_equal canonical_host
      hop.mount.must_equal prefix
      hop.remaining.must_equal "/health"
      hop.writes.must_equal 0
    end

    @harness.writes.must_be_empty
  end

  it "upgrades GET with the default 301 status and delegates once with the original query" do
    interleaved_flows.each do |prefix, transport|
      before = @harness.writes.length
      hops = @harness.follow("GET", external_uri(prefix), :transport=>transport)

      hops.length.must_equal 2
      hops.count{|hop| HttpsUpgrade::REDIRECT_STATUSES.include?(hop.status)}.must_equal 1

      first, final = hops
      first.status.must_equal 301
      first.location.must_equal expected_location(prefix)
      first.site.must_equal canonical_host
      first.mount.must_equal prefix
      first.remaining.must_equal ticket_route_path
      first.writes.must_equal before

      location = URI.parse(first.location)
      location.scheme.must_equal "https"
      location.host.must_equal canonical_host
      location.port.must_equal canonical_port
      location.path.must_equal "#{prefix}#{ticket_route_path}"
      location.query.must_equal ticket_query

      final.status.must_equal 200
      final.location.must_be_nil
      final.body.must_equal "ticket T-100%2042%2B1"
      final.site.must_equal canonical_host
      final.mount.must_equal prefix
      final.remaining.must_equal ticket_route_path
      final.writes.must_equal before + 1

      write = @harness.writes.last
      write.verb.must_equal "GET"
      write.scheme.must_equal "https"
      write.site.must_equal canonical_host
      write.mount.must_equal prefix
      write.remaining.must_equal ticket_route_path
      write.id.must_equal "T-100%2042%2B1"
      write.query.must_equal ticket_query
      write.tag.must_equal "vip mail"
      write.body.must_be_nil
    end
  end

  it "upgrades HEAD with the default 301 status and delegates once without a body" do
    interleaved_flows.each do |prefix, transport|
      before = @harness.writes.length
      hops = @harness.follow("HEAD", external_uri(prefix), :transport=>transport)

      hops.length.must_equal 2
      first, final = hops
      first.status.must_equal 301
      first.location.must_equal expected_location(prefix)
      first.writes.must_equal before

      final.status.must_equal 200
      final.body.must_equal ""
      final.site.must_equal canonical_host
      final.mount.must_equal prefix
      final.remaining.must_equal ticket_route_path
      final.writes.must_equal before + 1

      write = @harness.writes.last
      write.verb.must_equal "HEAD"
      write.scheme.must_equal "https"
      write.mount.must_equal prefix
      write.remaining.must_equal ticket_route_path
      write.query.must_equal ticket_query
      write.tag.must_equal "vip mail"
      write.body.must_be_nil
    end
  end

  it "upgrades POST with 307 and preserves the method and body at the delegated app" do
    body = "note=one&note=two"
    interleaved_flows.each do |prefix, transport|
      before = @harness.writes.length
      hops = @harness.follow("POST", external_uri(prefix), :transport=>transport, :body=>body)

      hops.length.must_equal 2
      first, final = hops
      first.status.must_equal 307
      first.location.must_equal expected_location(prefix)
      first.writes.must_equal before

      final.status.must_equal 200
      final.body.must_equal "ticket T-100%2042%2B1"
      final.site.must_equal canonical_host
      final.mount.must_equal prefix
      final.remaining.must_equal ticket_route_path
      final.writes.must_equal before + 1

      write = @harness.writes.last
      write.verb.must_equal "POST"
      write.scheme.must_equal "https"
      write.mount.must_equal prefix
      write.remaining.must_equal ticket_route_path
      write.query.must_equal ticket_query
      write.tag.must_equal "vip mail"
      write.body.must_equal body
    end
  end

  it "sends proxy-terminated TLS requests directly to the delegated app under each mount" do
    [[prefixes[0], :proxy], [prefixes[1], :proxy], [prefixes[0], :direct], [prefixes[1], :direct]].each do |prefix, transport|
      before = @harness.writes.length
      hops = @harness.follow("GET", upgraded_uri(prefix), :transport=>transport)

      hops.length.must_equal 1
      hop = hops.first
      hop.status.must_equal 200
      hop.location.must_be_nil
      hop.body.must_equal "ticket T-100%2042%2B1"
      hop.site.must_equal canonical_host
      hop.mount.must_equal prefix
      hop.remaining.must_equal ticket_route_path
      hop.writes.must_equal before + 1

      write = @harness.writes.last
      write.verb.must_equal "GET"
      write.scheme.must_equal "https"
      write.site.must_equal canonical_host
      write.mount.must_equal prefix
      write.remaining.must_equal ticket_route_path
      write.query.must_equal ticket_query
      write.tag.must_equal "vip mail"
    end
  end

  it "ends at the host check for unregistered sites in both deployments and mounts" do
    ["/health", ticket_path].each do |path|
      interleaved_flows.each do |prefix, transport|
        before = @harness.writes.length
        uri = URI.parse("https://unregistered.example.com:#{canonical_port}#{prefix}#{path}")
        hop = @harness.request("GET", uri, :transport=>transport)

        hop.status.must_equal 403
        hop.location.must_be_nil
        hop.body.must_equal ""
        hop.site.must_equal "unregistered.example.com"
        hop.mount.must_equal prefix
        hop.remaining.must_equal URI.parse(path).path
        hop.writes.must_equal before
        @harness.writes.length.must_equal before
      end
    end
  end

  it "ignores client-supplied forwarding headers when deciding whether to upgrade" do
    headers = {
      "HTTP_X_FORWARDED_HOST" => canonical_host,
      "HTTP_X_FORWARDED_PORT" => canonical_port.to_s,
      "HTTP_X_FORWARDED_PROTO" => "https"
    }

    prefixes.each do |prefix|
      before = @harness.writes.length
      hop = @harness.request("GET", external_uri(prefix), :transport=>:direct, :headers=>headers)

      # The trusted proxy adapter strips these before the application sees
      # them, so the plain HTTP request is still upgraded and not served.
      hop.status.must_equal 301
      hop.location.must_equal expected_location(prefix)
      hop.writes.must_equal before
    end

    @harness.writes.must_be_empty
  end
end
