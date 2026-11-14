# frozen_string_literal: true
module SecureHeaders
  class Middleware
    # Header names that can carry more than one independent policy. Rack
    # represents these as an Array of values so every policy is emitted on its
    # own header line rather than being concatenated.
    MULTI_VALUE_HEADERS = [
      ContentSecurityPolicyConfig::HEADER_NAME,
      ContentSecurityPolicyReportOnlyConfig::HEADER_NAME,
    ].freeze

    def initialize(app)
      @app = app
    end

    # merges the hash of headers into the current header set.
    def call(env)
      req = Rack::Request.new(env)
      status, headers, response = @app.call(env)

      # Rack::Headers is available in Rack 3.x and later
      # So we should pull the headers into that structure if possible
      if defined?(Rack::Headers)
        headers = Rack::Headers[headers]
      end

      config = SecureHeaders.config_for(req)
      flag_cookies!(headers, override_secure(env, config.cookies)) unless config.cookies == OPT_OUT
      apply_headers!(headers, SecureHeaders.header_hash_for(req))
      [status, headers, response]
    end

    private

    # Merges generated headers into the response. CSP headers are combined with
    # any values already supplied by the upstream app instead of replacing
    # them; everything else keeps the historical overwrite behavior.
    def apply_headers!(headers, generated)
      generated.each do |name, value|
        if MULTI_VALUE_HEADERS.include?(name)
          merge_multi_value_header(headers, name, value)
        else
          headers[name] = value
        end
      end
    end

    # Preserves upstream header values while appending the secure_headers
    # policy/policies. Existing String values are normalized into an Array only
    # when more than one value results, matching Rack's multi-value header
    # representation and keeping single-policy responses unchanged.
    def merge_multi_value_header(headers, name, generated_value)
      existing = headers[name]
      combined =
        if existing.nil?
          Array(generated_value)
        else
          Array(existing) + Array(generated_value)
        end

      headers[name] = combined.length == 1 ? combined.first : combined
    end

    # inspired by https://github.com/tobmatth/rack-ssl-enforcer/blob/6c014/lib/rack/ssl-enforcer.rb#L183-L194
    def flag_cookies!(headers, config)
      cookies = headers["Set-Cookie"]
      return unless cookies

      cookies_array = cookies.is_a?(Array) ? cookies : cookies.split("\n")
      secured_cookies = cookies_array.map { |cookie| SecureHeaders::Cookie.new(cookie, config).to_s }
      headers["Set-Cookie"] = cookies.is_a?(Array) ? secured_cookies : secured_cookies.join("\n")
    end

    # disable Secure cookies for non-https requests
    def override_secure(env, config = {})
      if scheme(env) != "https" && config != OPT_OUT
        config[:secure] = OPT_OUT
      end

      config
    end

    # derived from https://github.com/tobmatth/rack-ssl-enforcer/blob/6c014/lib/rack/ssl-enforcer.rb#L119
    def scheme(env)
      if env["HTTPS"] == "on" || env["HTTP_X_SSL_REQUEST"] == "on"
        "https"
      elsif env["HTTP_X_FORWARDED_PROTO"]
        env["HTTP_X_FORWARDED_PROTO"].split(",")[0]
      else
        env["rack.url_scheme"]
      end
    end
  end
end
