# frozen_string_literal: true

module Faraday
  # Shared helpers for the disclosure policy configured on a connection.
  #
  # Both the Logger middleware and {Faraday::Error} use these helpers so the
  # two failure channels apply the same rules without modifying the response
  # object returned to the caller.
  module Disclosure
    module_function

    # Finds the disclosure policy attached to a response, an Env, or an
    # exception carrying one of them.
    #
    # @param source [Faraday::Response, Faraday::Env, nil]
    # @return [DisclosureOptions, nil]
    def policy_for(source)
      env = env_from(source)
      return unless env

      policy = env[:disclosure]
      request = env.request
      policy ||= request.disclosure if request.respond_to?(:disclosure)
      return policy if policy.nil? || policy.is_a?(DisclosureOptions)

      DisclosureOptions.from(policy)
    end

    # Builds a response that contains only the selected response and request
    # fields. The original response is never modified.
    #
    # @param source [Faraday::Response, Faraday::Env]
    # @param policy [DisclosureOptions]
    # @return [Faraday::Response]
    def sanitize_response(source, policy)
      env = env_from(source)
      return source unless env

      Faraday::Response.new(sanitize_env(env, policy))
    end

    # Builds an Env containing only the selected response and request fields.
    #
    # @param env [Faraday::Env]
    # @param policy [DisclosureOptions]
    # @return [Faraday::Env]
    def sanitize_env(env, policy)
      sanitized = Faraday::Env.new
      sanitized.status = env.status
      sanitized.reason_phrase = env.reason_phrase
      sanitized.response_headers = {}
      sanitized.response_headers.update(env.response_headers) if policy.error_detail?(:response_headers)

      if policy.error_detail?(:response_body)
        sanitized.response_body = response_body(env)
      end

      if request_disclosable?(env, policy)
        sanitized.method = env.method if policy.request_attribute?(:method)
        sanitized.url = sanitized_url(env, policy)
        sanitized[:params] = request_params(env) if policy.request_attribute?(:params)
        sanitized.request_headers = env.request_headers&.dup if policy.request_attribute?(:headers)
        sanitized.request_body = env.request_body if policy.request_attribute?(:body)
      end

      sanitized
    end

    # Returns the response body of an Env. For a nil-status response the
    # adapter may have stored the response body in the request slot, so keep
    # the historical fallback.
    #
    # @param env [Faraday::Env]
    # @return [Object, nil]
    def response_body(env)
      return env.response_body unless env.response_body.nil?

      env.body
    end

    # Returns the URL to expose for the selected request attributes.
    #
    # @param env [Faraday::Env]
    # @param policy [DisclosureOptions]
    # @return [URI, nil]
    def request_url(env, policy)
      return unless env.url

      return env.url if policy.request_attribute?(:url)
      return Utils.URI(env.url.path) if policy.request_attribute?(:url_path)

      nil
    end

    # Returns the URL to keep on a sanitized Env. The query string is only
    # kept through the separate params attribute, so a params-only policy does
    # not leak the path.
    #
    # @param env [Faraday::Env]
    # @param policy [DisclosureOptions]
    # @return [URI, nil]
    def sanitized_url(env, policy)
      return unless env.url
      return env.url if policy.request_attribute?(:url)
      return Utils.URI(env.url.path) if policy.request_attribute?(:url_path)

      nil
    end

    # Returns the query parameters of the request, decoded with its encoder.
    #
    # @param env [Faraday::Env]
    # @return [Hash, nil]
    def request_params(env)
      return env[:params] unless env.url

      encoder = env.request.respond_to?(:params_encoder) && env.request.params_encoder
      encoder ||= Utils.default_params_encoder
      encoder.decode(env.url.query) || env[:params]
    end

    # Whether request attributes may be included at all. The legacy
    # `include_request: false` marker stays authoritative when present.
    #
    # @param env [Faraday::Env]
    # @param policy [DisclosureOptions]
    # @return [Boolean]
    def request_disclosable?(env, policy)
      policy.request_policy? && env[:include_request] != false
    end

    # Builds a status message using only the request attributes selected by the
    # policy.
    #
    # @param status [Integer, nil]
    # @param method [Symbol, nil]
    # @param url [URI, String, nil]
    # @return [String]
    def status_message(status, method, url)
      parts = []
      parts << method.to_s.upcase if method
      parts << url.to_s if url

      return "the server responded with status #{status}" if parts.empty?

      "the server responded with status #{status} for #{parts.join(' ')}"
    end

    # Duck-typed so this module can be required independently of the
    # Response and Env classes.
    def env_from(source)
      return unless source

      if source.respond_to?(:finished?) && source.respond_to?(:env)
        source.env if source.finished?
      elsif source.respond_to?(:status) && source.respond_to?(:request_headers)
        source
      end
    end
    private_class_method :env_from
  end
end
