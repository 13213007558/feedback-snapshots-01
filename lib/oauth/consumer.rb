# frozen_string_literal: true

require "net/http"
require "net/https"
require "oauth/oauth"
require "oauth/client/net_http"
require "oauth/errors"
require "cgi"

module OAuth
  class Consumer
    # determine the certificate authority path to verify SSL certs
    if ENV["SSL_CERT_FILE"]
      if File.exist?(ENV["SSL_CERT_FILE"])
        CA_FILE = ENV["SSL_CERT_FILE"]
      else
        raise "The SSL CERT provided does not exist."
      end
    end

    unless defined?(CA_FILE)
      CA_FILES = %w[/etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt
                    /usr/share/curl/curl-ca-bundle.crt].freeze
      CA_FILES.each do |ca_file|
        if File.exist?(ca_file)
          CA_FILE = ca_file
          break
        end
      end
    end
    CA_FILE = nil unless defined?(CA_FILE)

    @@default_options = SnakyHash::SymbolKeyed.new(
      {
        # Signature method used by server. Defaults to HMAC-SHA1
        signature_method: "HMAC-SHA1",

        # default paths on site. These are the same as the defaults set up by the generators
        request_token_path: "/oauth/request_token",
        authenticate_path: "/oauth/authenticate",
        authorize_path: "/oauth/authorize",
        access_token_path: "/oauth/access_token",

        proxy: nil,
        # How do we send the oauth values to the server see
        # https://oauth.net/core/1.0/#consumer_req_param for more info
        #
        # Possible values:
        #
        #   :header - via the Authorize header (Default) ( option 1. in spec)
        #   :body - url form encoded in body of POST request ( option 2. in spec)
        #   :query_string - via the query part of the url ( option 3. in spec)
        scheme: :header,

        # Default http method used for OAuth Token Requests (defaults to :post)
        http_method: :post,

        # Add a custom ca_file for consumer
        # :ca_file       => '/etc/certs.pem'

        # Possible values:
        #
        # nil, false - no debug output
        # true - uses $stdout
        # some_value - uses some_value
        debug_output: nil,

        # Defaults to producing a body_hash as part of the signature but
        # can be disabled since it's not officially part of the OAuth 1.0
        # spec. Possible values are true and false
        body_hash_enabled: true,

        oauth_version: "1.0",

        # How token request redirects (3xx responses) are handled.
        #
        #   :allowlist - Follow redirects only to explicitly approved targets.
        #                The configured token endpoint itself is approved
        #                implicitly; entries in :redirect_allowlist approve
        #                additional targets. This is the default.
        #   :deny      - Never follow a token request redirect.
        #   :any       - Follow any target that passes the safety checks
        #                (no HTTPS downgrade, no loops, no unsafe method change).
        #
        # Regardless of policy, an HTTPS request is never downgraded to HTTP.
        redirect_policy: :allowlist,

        # Extra approved redirect destinations for :allowlist policy.
        # Entries may be absolute URLs (scheme, host, port and path are
        # checked) or Hashes with :scheme, :host, :port and :path keys.
        # A URL without a path (or with "/") approves any path on that
        # origin. A Hash with :path approves only that canonical path.
        redirect_allowlist: nil,

        # Maximum number of redirects followed for one token request.
        redirect_limit: 5
      }
    )

    attr_accessor :options, :key, :secret
    attr_writer   :site, :http

    # Status codes treated as redirects for token requests.
    TOKEN_REDIRECT_STATUSES = [301, 302, 303, 307, 308].freeze

    # An approved redirect destination.
    # A nil +path+ approves every path on the origin.
    RedirectTarget = Struct.new(:scheme, :host, :port, :path)

    # Create a new consumer instance by passing it a configuration hash:
    #
    #   @consumer = OAuth::Consumer.new(key, secret, {
    #     :site               => "http://term.ie",
    #     :scheme             => :header,
    #     :http_method        => :post,
    #     :request_token_path => "/oauth/example/request_token.php",
    #     :access_token_path  => "/oauth/example/access_token.php",
    #     :authorize_path     => "/oauth/example/authorize.php",
    #     :body_hash_enabled  => false
    #    })
    #
    # Start the process by requesting a token
    #
    #   @request_token = @consumer.get_request_token
    #   session[:request_token] = @request_token
    #   redirect_to @request_token.authorize_url
    #
    # When user returns create an access_token
    #
    #   @access_token = @request_token.get_access_token
    #   @photos=@access_token.get('/photos.xml')
    #
    def initialize(consumer_key, consumer_secret, options = {})
      @key    = consumer_key
      @secret = consumer_secret

      # ensure that keys are symbols
      snaky_options = SnakyHash::SymbolKeyed.new(options)
      @options = @@default_options.merge(snaky_options)
    end

    # The default http method
    def http_method
      @http_method ||= @options[:http_method] || :post
    end

    def debug_output
      @debug_output ||= case @options[:debug_output]
                        when nil, false
                        when true
                          $stdout
                        else
                          @options[:debug_output]
                        end
    end

    # The HTTP object for the site. The HTTP Object is what you get when you do Net::HTTP.new
    def http
      @http ||= create_http
    end

    # Contains the root URI for this site
    def uri(custom_uri = nil)
      if custom_uri
        @uri  = custom_uri
        @http = create_http # yike, oh well. less intrusive this way
      else # if no custom passed, we use existing, which, if unset, is set to site uri
        @uri ||= URI.parse(site)
      end
    end

    def get_access_token(request_token, request_options = {}, *arguments, &block)
      response = token_request(http_method, (access_token_url? ? access_token_url : access_token_path), request_token,
                               request_options, *arguments, &block)
      OAuth::AccessToken.from_hash(self, response)
    end

    # Makes a request to the service for a new OAuth::RequestToken
    #
    #  @request_token = @consumer.get_request_token
    #
    # To include OAuth parameters:
    #
    #  @request_token = @consumer.get_request_token \
    #    :oauth_callback => "http://example.com/cb"
    #
    # To include application-specific parameters:
    #
    #  @request_token = @consumer.get_request_token({}, :foo => "bar")
    #
    # TODO oauth_callback should be a mandatory parameter
    def get_request_token(request_options = {}, *arguments, &block)
      # if oauth_callback wasn't provided, it is assumed that oauth_verifiers
      # will be exchanged out of band
      request_options[:oauth_callback] ||= OAuth::OUT_OF_BAND unless request_options[:exclude_callback]

      response = if block
                   token_request(
                     http_method,
                     (request_token_url? ? request_token_url : request_token_path),
                     nil,
                     request_options,
                     *arguments,
                     &block
                   )
                 else
                   token_request(http_method, (request_token_url? ? request_token_url : request_token_path), nil,
                                 request_options, *arguments)
                 end
      OAuth::RequestToken.from_hash(self, response)
    end

    # Creates, signs and performs an http request.
    # It's recommended to use the OAuth::Token classes to set this up correctly.
    # request_options take precedence over consumer-wide options when signing
    #   a request.
    # arguments are POST and PUT bodies (a Hash, string-encoded parameters, or
    #   absent), followed by additional HTTP headers.
    #
    #   @consumer.request(:get,  '/people', @token, { :scheme => :query_string })
    #   @consumer.request(:post, '/people', @token, {}, @person.to_xml, { 'Content-Type' => 'application/xml' })
    #
    def request(http_method, path, token = nil, request_options = {}, *arguments)
      unless %r{^/}.match?(path)
        @http = create_http(path)
        _uri = URI.parse(path)
        path = "#{_uri.path}#{_uri.query ? "?#{_uri.query}" : ""}"
      end

      # override the request with your own, this is useful for file uploads which Net::HTTP does not do
      req = create_signed_request(http_method, path, token, request_options, *arguments)
      return nil if block_given? && (yield(req) == :done)

      rsp = http.request(req)
      check_for_problem_response!(rsp)
      rsp
    end

    # Creates and signs an http request.
    # It's recommended to use the Token classes to set this up correctly
    def create_signed_request(http_method, path, token = nil, request_options = {}, *arguments)
      request = create_http_request(http_method, path, *arguments)
      sign!(request, token, request_options)
      request
    end

    # Creates a request and parses the result as url_encoded. This is used internally for the RequestToken and AccessToken requests.
    #
    # Redirects returned by the token endpoint are handled according to the
    # +:redirect_policy+ option:
    #
    #   :allowlist (default) - only the configured token endpoint and entries
    #                          in +:redirect_allowlist+ may be followed
    #   :deny                - never follow a redirect
    #   :any                 - follow any target that passes the safety checks
    #
    # Every hop is checked independently, an HTTPS request is never
    # downgraded, and every followed hop is signed afresh for the new
    # request with a fresh nonce.
    def token_request(http_method, path, token = nil, request_options = {}, *arguments)
      request_options[:token_request] ||= true
      policy = token_redirect_policy(request_options)
      approved_targets = token_redirect_targets(path, request_options, policy)
      current_uri = token_request_initial_uri(path)
      request_method = http_method.to_s.downcase.to_sym
      request_arguments = arguments.dup
      body_position = token_redirect_body_position(request_method, request_arguments)
      visited = { token_redirect_uri_key(current_uri) => true }
      redirects_followed = 0
      redirect_limit = token_redirect_limit(request_options)

      loop do
        response = if redirects_followed.zero?
                     request(request_method, path, token, request_options, *request_arguments)
                   else
                     perform_redirected_token_request(request_method, current_uri, token, request_options,
                                                      request_arguments, body_position)
                   end
        status = response.code.to_i

        case status
        when (200..299)
          return (block_given? ? yield(response.body) : parse_token_response(response.body))
        when (300..399)
          unless TOKEN_REDIRECT_STATUSES.include?(status)
            raise OAuth::RedirectNotAllowed.new(response, nil, "unsupported redirect status #{status}")
          end

          location = token_redirect_location(response)
          target_uri = resolve_token_redirect(current_uri, location)
          check_token_redirect!(response, current_uri, target_uri, policy, approved_targets)

          if redirects_followed >= redirect_limit
            raise Net::HTTPRetriableError.new("too many redirects", response)
          end

          redirect_key = token_redirect_uri_key(target_uri)
          raise Net::HTTPRetriableError.new("redirect loop", response) if visited[redirect_key]

          visited[redirect_key] = true
          request_method, request_arguments = token_redirect_transition(status, request_method, request_arguments,
                                                                         response)
          current_uri = target_uri
          redirects_followed += 1
        when (400..499)
          raise OAuth::Unauthorized, response
        else
          response.error!
        end
      end
    end

    # Sign the Request object. Use this if you have an externally generated http request object you want to sign.
    def sign!(request, token = nil, request_options = {})
      request.oauth!(http, self, token, options.merge(request_options))
    end

    # Return the signature_base_string
    def signature_base_string(request, token = nil, request_options = {})
      request.signature_base_string(http, self, token, options.merge(request_options))
    end

    def site
      @options[:site].to_s
    end

    def request_endpoint
      return nil if @options[:request_endpoint].nil?

      @options[:request_endpoint].to_s
    end

    def scheme
      @options[:scheme]
    end

    def request_token_path
      @options[:request_token_path]
    end

    def authenticate_path
      @options[:authenticate_path]
    end

    def authorize_path
      @options[:authorize_path]
    end

    def access_token_path
      @options[:access_token_path]
    end

    # TODO: this is ugly, rewrite
    def request_token_url
      @options[:request_token_url] || (site + request_token_path)
    end

    def request_token_url?
      @options.key?(:request_token_url)
    end

    def authenticate_url
      @options[:authenticate_url] || (site + authenticate_path)
    end

    def authenticate_url?
      @options.key?(:authenticate_url)
    end

    def authorize_url
      @options[:authorize_url] || (site + authorize_path)
    end

    def authorize_url?
      @options.key?(:authorize_url)
    end

    def access_token_url
      @options[:access_token_url] || (site + access_token_path)
    end

    def access_token_url?
      @options.key?(:access_token_url)
    end

    def proxy
      @options[:proxy]
    end

    protected

    # Instantiates the http object
    def create_http(_url = nil)
      _url = request_endpoint unless request_endpoint.nil?

      our_uri = if _url.nil? || _url[0] =~ %r{^/}
                  URI.parse(site)
                else
                  your_uri = URI.parse(_url)
                  if your_uri.host.nil?
                    # If the _url is a path, missing the leading slash, then it won't have a host,
                    # and our_uri *must* have a host, so we parse site instead.
                    URI.parse(site)
                  else
                    your_uri
                  end
                end

      build_http(our_uri)
    end

    # Build a connection for an exact URI, ignoring +request_endpoint+.
    # Used for redirect hops, which must bind to the redirect target.
    def create_http_for_uri(uri)
      build_http(uri)
    end

    def build_http(our_uri)
      if proxy.nil?
        http_object = Net::HTTP.new(our_uri.host, our_uri.port)
      else
        proxy_uri = proxy.is_a?(URI) ? proxy : URI.parse(proxy)
        http_object = Net::HTTP.new(our_uri.host, our_uri.port, proxy_uri.host, proxy_uri.port, proxy_uri.user,
                                    proxy_uri.password)
      end

      http_object.use_ssl = (our_uri.scheme == "https")

      if @options[:no_verify]
        http_object.verify_mode = OpenSSL::SSL::VERIFY_NONE
      else
        ca_file = @options[:ca_file] || CA_FILE
        http_object.ca_file = ca_file if ca_file
        http_object.verify_mode = OpenSSL::SSL::VERIFY_PEER
        http_object.verify_depth = 5
      end

      http_object.read_timeout = http_object.open_timeout = @options[:timeout] || 60
      http_object.open_timeout = @options[:open_timeout] if @options[:open_timeout]
      http_object.ssl_version = @options[:ssl_version] if @options[:ssl_version]
      http_object.cert = @options[:ssl_client_cert] if @options[:ssl_client_cert]
      http_object.key = @options[:ssl_client_key] if @options[:ssl_client_key]
      http_object.set_debug_output(debug_output) if debug_output

      http_object
    end

    # create the http request object for a given http_method and path
    def create_http_request(http_method, path, *arguments)
      http_method = http_method.to_sym

      data = arguments.shift if %i[post put patch].include?(http_method)

      # if the base site contains a path, add it now
      # only add if the site host matches the current http object's host
      # (in case we've specified a full url for token requests)
      uri = URI.parse(site)
      path = uri.path + path if uri.path && uri.path != "/" && uri.host == http.address

      headers = arguments.first.is_a?(Hash) ? arguments.shift : {}
      build_http_request(http_method, path, data, headers)
    end

    # Create a request addressed at an exact target URI. Unlike
    # #create_http_request, this never prefixes the site's base path.
    def create_http_request_for_uri(http_method, target_uri, *arguments)
      http_method = http_method.to_sym

      data = arguments.shift if %i[post put patch].include?(http_method)
      headers = arguments.first.is_a?(Hash) ? arguments.shift : {}
      build_http_request(http_method, target_uri.request_uri, data, headers)
    end

    def build_http_request(http_method, path, data, headers)
      case http_method
      when :post
        request = Net::HTTP::Post.new(path, headers)
        request["Content-Length"] = "0" # Default to 0
      when :put
        request = Net::HTTP::Put.new(path, headers)
        request["Content-Length"] = "0" # Default to 0
      when :patch
        request = Net::HTTP::Patch.new(path, headers)
        request["Content-Length"] = "0" # Default to 0
      when :get
        request = Net::HTTP::Get.new(path, headers)
      when :delete
        request = Net::HTTP::Delete.new(path, headers)
      when :head
        request = Net::HTTP::Head.new(path, headers)
      else
        raise ArgumentError, "Don't know how to handle http_method: :#{http_method}"
      end

      if data.is_a?(Hash)
        request.body = OAuth::Helper.normalize(data)
        request.content_type = "application/x-www-form-urlencoded"
      elsif data
        if data.respond_to?(:read)
          request.body_stream = data
          if data.respond_to?(:length)
            request["Content-Length"] = data.length.to_s
          elsif data.respond_to?(:stat) && data.stat.respond_to?(:size)
            request["Content-Length"] = data.stat.size.to_s
          else
            raise ArgumentError, "Don't know how to send a body_stream that doesn't respond to .length or .stat.size"
          end
        else
          request.body = data.to_s
          request["Content-Length"] = request.body.length.to_s
        end
      end

      request
    end

    def marshal_dump(*_args)
      { key: @key, secret: @secret, options: @options }
    end

    def marshal_load(data)
      initialize(data[:key], data[:secret], data[:options])
    end

    ## Token request redirect handling

    def token_redirect_policy(request_options)
      policy = request_options.fetch(:redirect_policy, @options[:redirect_policy])
      policy = :allowlist if policy.nil?
      policy = policy.to_sym if policy.respond_to?(:to_sym)
      unless %i[allowlist deny any].include?(policy)
        raise ArgumentError, "Unknown redirect policy: #{policy.inspect}"
      end

      policy
    end

    def token_redirect_limit(request_options)
      limit = request_options.fetch(:redirect_limit, @options[:redirect_limit])
      limit = 5 if limit.nil?
      limit = Integer(limit)
      raise ArgumentError, "redirect_limit must be zero or greater" if limit.negative?

      limit
    end

    def token_redirect_allowlist(request_options)
      list = request_options.fetch(:redirect_allowlist, @options[:redirect_allowlist])
      case list
      when nil then []
      when Array then list
      else [list]
      end
    end

    # The URI actually addressed by the first token request.
    def token_request_initial_uri(path)
      path = path.to_s

      if path.match?(%r{\Ahttps?://}i)
        uri = URI.parse(path)
        uri.path = canonical_path(uri.path)
        return uri if request_endpoint.nil?

        path = uri.path
        path = "#{path}?#{uri.query}" if uri.query
      elsif path.start_with?("//")
        parsed = URI.parse("#{endpoint_scheme}:#{path}")
        return parsed if request_endpoint.nil?

        path = parsed.path
        path = "#{path}?#{parsed.query}" if parsed.query
      end

      origin = URI.parse("#{endpoint_scheme}://#{endpoint_authority}")
      request_path = path
      request_path = "/" if request_path.empty?
      request_path = "/#{request_path}" unless request_path.start_with?("/")

      if site_uri.path && site_uri.path != "/" && site_uri.host == http.address
        request_path = "#{site_uri.path}#{request_path}"
      end

      origin.merge(request_path)
    end

    def endpoint_scheme
      if http.respond_to?(:use_ssl?) && http.use_ssl?
        "https"
      else
        "http"
      end
    end

    def endpoint_authority
      address = http.address.to_s
      address = "[#{address}]" if address.include?(":") && !address.start_with?("[")
      "#{address}:#{http.port}"
    end

    def site_uri
      URI.parse(site)
    end

    def token_redirect_targets(path, request_options, policy)
      return [] unless policy == :allowlist

      initial = token_redirect_target_for_uri(token_request_initial_uri(path), allow_any_path: false)
      # Only the configured token endpoint itself (scheme, host, port and
      # path) is approved implicitly. Every other target, including a
      # different path on the same origin, needs an explicit entry.
      targets = [initial]

      token_redirect_allowlist(request_options).each do |entry|
        targets << token_redirect_target_for(entry)
      end
      targets.compact
    end

    def token_redirect_target_for(entry)
      case entry
      when RedirectTarget then entry
      when URI then token_redirect_target_for_uri(entry)
      when String then token_redirect_target_for_uri(URI.parse(entry))
      when Hash
        scheme = (entry[:scheme] || "https").to_s.downcase
        host = entry[:host].to_s.downcase
        raise ArgumentError, "redirect_allowlist entry needs :host" if host.empty?
        raise ArgumentError, "redirect_allowlist entry needs an http(s) :scheme" unless %w[http https].include?(scheme)

        port = entry[:port] ? Integer(entry[:port]) : token_redirect_default_port(scheme)
        target_path = entry[:path]
        unless target_path.nil?
          target_path = target_path.to_s
          target_path = "/#{target_path}" unless target_path.start_with?("/")
        end
        RedirectTarget.new(scheme, host, port, target_path && canonical_path(target_path))
      else
        raise ArgumentError, "Unsupported redirect_allowlist entry: #{entry.inspect}"
      end
    end

    # A URI entry with no path (none, or "/") approves every path on that
    # origin. When +allow_any_path+ is false, an entry without an explicit
    # path is treated as a concrete target instead.
    def token_redirect_target_for_uri(uri, allow_any_path: true)
      scheme = uri.scheme.to_s.downcase
      return nil unless %w[http https].include?(scheme)

      host = uri.host.to_s.downcase
      return nil if host.empty?

      port = uri.port || token_redirect_default_port(scheme)
      path = uri.path
      path = nil if allow_any_path && (path.nil? || path.empty? || path == "/")
      RedirectTarget.new(scheme, host, port, path && canonical_path(path))
    end

    def token_redirect_default_port(scheme)
      scheme == "https" ? 443 : 80
    end

    def token_redirect_location(response)
      locations = response.get_fields("location") || []
      if locations.empty?
        raise OAuth::RedirectNotAllowed.new(response, nil, "redirect response without a Location header")
      end
      if locations.length > 1
        raise OAuth::RedirectNotAllowed.new(response, nil, "redirect response with multiple Location headers")
      end

      location = locations.first.to_s
      if location.strip.empty?
        raise OAuth::RedirectNotAllowed.new(response, nil, "redirect response with a blank Location header")
      end
      if location.match?(/[\x00-\x20\x7f]/)
        raise OAuth::RedirectNotAllowed.new(response, nil, "redirect Location contains whitespace or control characters")
      end

      location
    end

    # Resolve a Location value against the URI of the request that returned it.
    def resolve_token_redirect(current_uri, location)
      begin
        target = URI.join(current_uri.to_s, location)
      rescue URI::InvalidURIError => e
        raise OAuth::RedirectNotAllowed.new(nil, location, "redirect target is not a valid URL: #{e.message}")
      end

      unless target.is_a?(URI::HTTP) && target.host && target.host != "" && target.path.to_s.start_with?("/")
        raise OAuth::RedirectNotAllowed.new(nil, location, "redirect target is not an absolute http(s) URL")
      end

      if target.userinfo
        raise OAuth::RedirectNotAllowed.new(nil, location, "redirect target must not contain credentials")
      end

      # Canonicalize the path that is both checked and requested, so no dot
      # segments are left for the server to interpret.
      target.path = canonical_path(target.path)
      target.fragment = nil if target.fragment
      target
    end

    def check_token_redirect!(response, current_uri, target_uri, policy, approved_targets)
      if policy == :deny
        raise OAuth::RedirectNotAllowed.new(response, target_uri.to_s, "token request redirects are disabled")
      end

      if current_uri.scheme.to_s.casecmp("https").zero? && !target_uri.scheme.to_s.casecmp("https").zero?
        raise OAuth::RedirectNotAllowed.new(response, target_uri.to_s, "HTTPS token endpoint cannot redirect to HTTP")
      end

      return if policy == :any

      approved = approved_targets.any? { |target| token_redirect_target_matches?(target, target_uri) }
      unless approved
        raise OAuth::RedirectNotAllowed.new(response, target_uri.to_s,
                                            "redirect target is not an approved token endpoint")
      end
    end

    def token_redirect_target_matches?(target, uri)
      scheme = uri.scheme.to_s.downcase
      return false unless target.scheme == scheme

      return false unless target.host == uri.host.to_s.downcase

      port = uri.port || token_redirect_default_port(scheme)
      return false unless target.port == port

      target.path.nil? || target.path == canonical_path(uri.path)
    end

    # Resolve dot segments so equivalent paths compare equal without
    # allowing an approved path to be escaped via "/../".
    def canonical_path(path)
      path = path.to_s
      path = "/" if path.empty?

      segments = path.split("/", -1)
      resolved = []
      segments.each_with_index do |segment, index|
        case segment
        when "."
          resolved << "" if index == segments.length - 1
        when ".."
          resolved.pop if resolved.length > 1
          resolved << "" if index == segments.length - 1
        else
          resolved << segment
        end
      end
      result = resolved.join("/")
      result = "/#{result}" unless result.start_with?("/")
      result = "/" if result.empty?
      result
    end

    def token_redirect_uri_key(uri)
      scheme = uri.scheme.to_s.downcase
      host = uri.host.to_s.downcase
      port = uri.port || token_redirect_default_port(scheme)
      "#{scheme}://#{host}:#{port}#{canonical_path(uri.path)}?#{uri.query}"
    end

    # Determine the method and body for the next hop.
    #
    # 303 always switches to GET and drops the body. 301 and 302 switch a
    # POST to GET, matching long-standing browser behavior. 307 and 308
    # preserve the method and body. Changing away from a method with a body
    # drops the body, since replaying it under GET would be meaningless.
    def token_redirect_transition(status, request_method, request_arguments, response)
      target_method = request_method

      if status == 303
        target_method = :get unless request_method == :head
      elsif [301, 302].include?(status) && request_method == :post
        target_method = :get
      end

      arguments = request_arguments.dup
      if token_redirect_body_method?(request_method) && !arguments.empty?
        data = arguments.first
        if token_redirect_body?(data)
          if target_method != request_method
            # A method change (e.g. POST to GET) cannot carry the body.
            arguments.shift
          elsif !token_redirect_replayable_body?(data)
            raise OAuth::RedirectNotAllowed.new(response, nil,
                                                "redirect requires replaying a body that cannot be rewound")
          end
        end
      end

      [target_method, arguments]
    end

    def token_redirect_body_method?(http_method)
      %i[post put patch].include?(http_method)
    end

    def token_redirect_body?(data)
      data.is_a?(Hash) || data.is_a?(String) || data.respond_to?(:read)
    end

    def token_redirect_replayable_body?(data)
      return false if data.nil?
      return true if data.is_a?(Hash) || data.is_a?(String)

      # IO bodies can only be replayed when their position is known and
      # can be restored.
      data.respond_to?(:rewind) && data.respond_to?(:pos) && data.respond_to?(:pos=)
    end

    def token_redirect_rewind_body!(data, original_position)
      return if original_position.nil? || !token_redirect_body_stream?(data)

      data.pos = original_position
    end

    def token_redirect_body_position(http_method, arguments)
      return nil unless token_redirect_body_method?(http_method) && !arguments.empty?

      data = arguments.first
      return nil unless token_redirect_body_stream?(data)

      data.pos
    rescue IOError
      nil
    end

    def token_redirect_body_stream?(data)
      !data.is_a?(Hash) && !data.is_a?(String) && token_redirect_replayable_body?(data)
    end

    def perform_redirected_token_request(http_method, target_uri, token, request_options, arguments, body_position)
      data = token_redirect_body_method?(http_method) ? arguments.first : nil
      token_redirect_rewind_body!(data, body_position)

      # Send exactly to the checked target and sign exactly for it.
      # The consumer's site and connection are not modified, so unrelated
      # requests keep using the configured endpoint.
      # Clear :request_endpoint so the signature is built against the hop
      # connection (the exact target host, port and scheme), not against the
      # consumer's configured proxy/canonical endpoint.
      hop_options = request_options.merge(:request_endpoint => nil)
      # A redirect hop must carry a new nonce; never replay the caller's.
      hop_options[:nonce] = nil

      hop_http = create_http_for_uri(target_uri)
      req = create_http_request_for_uri(http_method, target_uri, *arguments)
      # Sign against the hop connection, so scheme, host and port in the
      # signature base string are those of the request actually sent.
      req.oauth!(hop_http, self, token, options.merge(hop_options))
      response = hop_http.request(req)
      check_for_problem_response!(response)
      response
    end

    def check_for_problem_response!(rsp)
      # check for an error reported by the Problem Reporting extension
      # (https://wiki.oauth.net/ProblemReporting)
      # note: a 200 may actually be an error; check for an oauth_problem key to be sure
      headers = rsp.to_hash["www-authenticate"]
      return if headers.nil?

      oauth_headers = headers.grep(/^OAuth /)
      return unless oauth_headers.any? && oauth_headers.first.include?("oauth_problem")

      params = OAuth::Helper.parse_header(oauth_headers.first)
      raise OAuth::Problem.new(params.delete("oauth_problem"), rsp, params)
    end

    def parse_token_response(body)
      # symbolize keys
      # TODO this could be considered unexpected behavior; symbols or not?
      # TODO this also drops subsequent values from multi-valued keys
      CGI.parse(body).each_with_object({}) do |(k, v), h|
        h[k.strip.to_sym] = v.first
        h[k.strip]        = v.first
      end
    end
  end
end
