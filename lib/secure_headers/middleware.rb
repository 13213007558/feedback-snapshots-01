# frozen_string_literal: true
module SecureHeaders
  class Middleware
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
      headers.merge!(SecureHeaders.header_hash_for(req))
      [status, headers, response]
    end

    private

    # inspired by https://github.com/tobmatth/rack-ssl-enforcer/blob/6c014/lib/rack/ssl-enforcer.rb#L183-L194
    def flag_cookies!(headers, config)
      cookies = headers["Set-Cookie"]
      return unless cookies

      if cookies.is_a?(Array)
        # Preserve one header field per cookie. Non-String entries are left
        # untouched rather than dropped or merged.
        headers["Set-Cookie"] = cookies.map do |cookie|
          cookie.is_a?(String) ? SecureHeaders::Cookie.new(cookie, config).to_s : cookie
        end
      else
        # Legacy Rack allowed multiple cookies in a single String separated by
        # newlines. Keep them separate and normalize the line separator.
        # Splitting bytewise keeps invalid byte sequences from raising; each
        # cookie is handed to the parser with its original encoding.
        encoding = cookies.encoding
        secured_cookies = cookies.b.split("\n".b).map do |cookie|
          cookie = cookie.delete_suffix("\r".b)
          SecureHeaders::Cookie.new(cookie.force_encoding(encoding), config).to_s
        end
        headers["Set-Cookie"] = secured_cookies.join("\n")
      end
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
