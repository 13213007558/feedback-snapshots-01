# frozen_string_literal: true

module Faraday
  class Request
    # Request middleware for the Authorization HTTP header
    class Authorization < Faraday::Middleware
      KEY = 'Authorization'

      # @param app [#call]
      # @param type [String, Symbol] Type of Authorization
      # @param params [Array<String, Proc, #call>] parameters to build the Authorization header.
      #   If the type is `:basic`, then these can be a login and password pair.
      #   Otherwise, a single value is expected that will be appended after the type.
      #   This value can be a proc or an object responding to `.call`, in which case
      #   it will be invoked on each request.
      # @param only [Array<String, Regexp>] targets the credentials may be sent to.
      #   When given, the Authorization header is only added when the request's
      #   final URL (the one handed to the adapter) matches one of them. A String
      #   containing a host matches by origin (`scheme://host:port`, comparing the
      #   components rather than a raw prefix) plus its path prefix, while a String
      #   without a host matches a path prefix. A Regexp is matched against the
      #   full URL. Omit it to send the header to every host.
      def initialize(app, type, *params, only: nil)
        @type = type
        @params = params
        @only = Array(only)
        super(app)
      end

      # @param env [Faraday::Env]
      def on_request(env)
        return unless authorized_target?(env.url)
        return if env.request_headers[KEY]

        env.request_headers[KEY] = header_from(@type, env, *@params)
      end

      private

      # Decide whether the credentials are allowed to be sent to the given URL.
      # When no targets are configured, every URL is allowed so existing
      # behaviour is preserved.
      #
      # @param url [URI] the final URL handed to the adapter
      # @return [Boolean]
      def authorized_target?(url)
        return true if @only.empty?

        @only.any? { |target| target_match?(target, url) }
      end

      # @param target [String, Regexp] an approved origin/URL prefix or pattern
      # @param url [URI] the final URL handed to the adapter
      # @return [Boolean]
      def target_match?(target, url)
        return target.match?(url.to_s) if target.is_a?(Regexp)

        target_uri = Utils.URI(target)
        return url.path.start_with?(target) if target_uri.host.nil?

        same_origin?(target_uri, url) && url.path.start_with?(target_uri.path)
      end

      # @param target_uri [URI] an approved absolute target
      # @param url [URI] the final URL handed to the adapter
      # @return [Boolean]
      def same_origin?(target_uri, url)
        target_uri.scheme == url.scheme &&
          target_uri.host == url.host &&
          target_uri.port == url.port
      end

      # @param type [String, Symbol]
      # @param env [Faraday::Env]
      # @param params [Array]
      # @return [String] a header value
      def header_from(type, env, *params)
        if type.to_s.casecmp('basic').zero? && params.size == 2
          Utils.basic_header_from(*params)
        elsif params.size != 1
          raise ArgumentError, "Unexpected params received (got #{params.size} instead of 1)"
        else
          value = params.first
          if (value.is_a?(Proc) && value.arity == 1) || (value.respond_to?(:call) && value.method(:call).arity == 1)
            value = value.call(env)
          elsif value.is_a?(Proc) || value.respond_to?(:call)
            value = value.call
          end
          "#{type} #{value}"
        end
      end
    end
  end
end

Faraday::Request.register_middleware(authorization: Faraday::Request::Authorization)
