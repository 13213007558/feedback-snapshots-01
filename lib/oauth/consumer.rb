# frozen_string_literal: true

require "net/http"
require "net/https"
require "oauth/oauth"
require "oauth/client/net_http"
require "oauth/client/clock_correction"
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

        oauth_version: "1.0"
      }
    )

    attr_accessor :options, :key, :secret
    attr_writer   :site, :http
    attr_reader   :last_clock_correction_outcome

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
    def request(http_method, path, token = nil, request_options = {}, *arguments, &block)
      if clock_correction_config(request_options)
        return request_with_clock_correction(http_method, path, token, request_options, *arguments,
                                             &block)
      end

      path = normalize_request_path!(path)

      # override the request with your own, this is useful for file uploads which Net::HTTP does not do
      req = create_signed_request(http_method, path, token, request_options, *arguments)
      return nil if block_given? && (yield(req) == :done)

      rsp = http.request(req)
      # check for an error reported by the Problem Reporting extension
      # (https://wiki.oauth.net/ProblemReporting)
      # note: a 200 may actually be an error; check for an oauth_problem key to be sure
      problem = problem_for_response(rsp)
      raise problem if problem

      rsp
    end

    # Perform a request with the opt-in, bounded timestamp correction flow.
    #
    # The business request (method, path, body and idempotency header) is kept
    # unchanged. Only +oauth_timestamp+ and +oauth_nonce+ are regenerated for a
    # retry, and only after a trusted same-service +timestamp_refused+ response.
    #
    # The result is exposed through #last_clock_correction_outcome so the
    # caller can decide whether a manual retry is appropriate when the request
    # outcome is unknown.
    def request_with_clock_correction(http_method, path, token = nil, request_options = {}, *arguments, &block)
      path = normalize_request_path!(path)

      config = clock_correction_config(request_options)
      correction = OAuth::Client::ClockCorrection.new(config, offsets: clock_correction_offsets)
      target_origin = request_origin
      replayable = replayable_request_body?(http_method, arguments.first)

      build_request = lambda do |attempt_options|
        rewind_request_body(arguments.first)
        signing_options = request_options.reject do |key, _value|
          %i[clock_correction].include?(key.to_sym)
        end
        req = create_signed_request(http_method, path, token, signing_options.merge(attempt_options), *arguments)
        if block && (yield(req) == :done)
          OAuth::Client::ClockCorrection::HALT
        else
          req
        end
      end

      transport = lambda do |req|
        http.request(req)
      end

      @last_clock_correction_outcome = correction.execute(
        target_origin: target_origin,
        http_method: http_method,
        build_request: build_request,
        transport: transport,
        problem_for: ->(rsp) { problem_for_response(rsp) },
        replayable_body: replayable
      )

      outcome = @last_clock_correction_outcome
      return nil if outcome.result == :halted

      if outcome.succeeded?
        outcome.response
      else
        raise_correction_failure(outcome)
      end
    end

    # Creates and signs an http request.
    # It's recommended to use the Token classes to set this up correctly
    def create_signed_request(http_method, path, token = nil, request_options = {}, *arguments)
      request = create_http_request(http_method, path, *arguments)
      sign!(request, token, request_options)
      request
    end

    # Creates a request and parses the result as url_encoded. This is used internally for the RequestToken and AccessToken requests.
    def token_request(http_method, path, token = nil, request_options = {}, *arguments)
      request_options[:token_request] ||= true
      response = request(http_method, path, token, request_options, *arguments)
      case response.code.to_i

      when (200..299)
        if block_given?
          yield response.body
        else
          # symbolize keys
          # TODO this could be considered unexpected behavior; symbols or not?
          # TODO this also drops subsequent values from multi-valued keys
          CGI.parse(response.body).each_with_object({}) do |(k, v), h|
            h[k.strip.to_sym] = v.first
            h[k.strip]        = v.first
          end
        end
      when (300..399)
        # Parse redirect to follow
        uri = URI.parse(response["location"])
        our_uri = URI.parse(site)

        # Guard against infinite redirects
        response.error! if uri.path == path && our_uri.host == uri.host

        if uri.path == path && our_uri.host != uri.host
          options[:site] = "#{uri.scheme}://#{uri.host}"
          @http = create_http
        end

        token_request(http_method, uri.path, token, request_options, arguments)
      when (400..499)
        raise OAuth::Unauthorized, response
      else
        response.error!
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

    def clock_correction_offsets
      @clock_correction_offsets ||= {}
    end

    protected

    def normalize_request_path!(path)
      return path if %r{^/}.match?(path)

      @http = create_http(path)
      _uri = URI.parse(path)
      "#{_uri.path}#{_uri.query ? "?#{_uri.query}" : ""}"
    end

    def request_origin
      scheme = http.respond_to?(:use_ssl?) && http.use_ssl? ? "https" : "http"
      default_port = scheme == "https" ? 443 : 80
      port = http.respond_to?(:port) ? http.port : nil
      port_suffix = port && port != default_port ? ":#{port}" : ""
      "#{scheme}://#{http.address.to_s.downcase}#{port_suffix}"
    end

    def clock_correction_config(request_options)
      requested = request_options.is_a?(Hash) ? request_options[:clock_correction] : nil
      return nil if requested == false

      consumer_config = @options[:clock_correction]
      return nil if consumer_config == false

      base = case consumer_config
             when nil then {}
             when true then {enabled: true}
             else consumer_config.to_h
             end
      extra = case requested
              when nil then {}
              when true then {enabled: true}
              else requested.to_h
              end
      config = base.merge(extra)
      return nil if config.empty? || config[:enabled] == false

      config
    end

    def replayable_request_body?(http_method, data)
      return true unless OAuth::Client::ClockCorrection::WRITE_METHODS.include?(http_method.to_sym)
      return true if data.nil? || data.is_a?(Hash) || data.is_a?(String)
      return data.respond_to?(:rewind) if data.respond_to?(:read)

      true
    end

    def rewind_request_body(data)
      data.rewind if data.respond_to?(:rewind)
    end

    def problem_for_response(response)
      return nil unless response.respond_to?(:to_hash)

      headers = response.to_hash["www-authenticate"]
      return nil if headers.nil?

      header = headers.grep(/^OAuth /).first
      return nil if header.nil? || !header.include?("oauth_problem")

      params = OAuth::Helper.parse_header(header)
      OAuth::Problem.new(params.delete("oauth_problem"), response, params)
    end

    def raise_correction_failure(outcome)
      raise outcome.error if outcome.error
      raise outcome.problem if outcome.problem

      raise OAuth::ClockCorrectionError.new("Clock correction failed: #{outcome.result}", outcome)
    end

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
  end
end
