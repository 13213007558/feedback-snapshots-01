# frozen_string_literal: true

module HTTP
  class Request
    # Proxy-related methods for HTTP requests
    module Proxy
      # Merges proxy headers into the request headers
      #
      # @example
      #   request.include_proxy_headers
      #
      # @return [void]
      # @api public
      def include_proxy_headers
        headers.merge!(proxy[:proxy_headers]) if proxy.key?(:proxy_headers)
        include_proxy_authorization_header if using_authenticated_proxy?
      end

      # Compute and add the Proxy-Authorization header
      #
      # @example
      #   request.include_proxy_authorization_header
      #
      # @return [void]
      # @api public
      def include_proxy_authorization_header
        headers[Headers::PROXY_AUTHORIZATION] = proxy_authorization_header
      end

      # Build the Proxy-Authorization header value
      #
      # @example
      #   request.proxy_authorization_header
      #
      # @return [String]
      # @api public
      def proxy_authorization_header
        digest = encode64(format("%s:%s", proxy.fetch(:proxy_username), proxy.fetch(:proxy_password)))
        "Basic #{digest}"
      end

      # Setup tunnel through proxy for SSL request
      #
      # @example
      #   request.connect_using_proxy(socket)
      #
      # @return [void]
      # @api public
      def connect_using_proxy(socket)
        Writer.new(socket, nil, proxy_connect_headers, proxy_connect_header).connect_through_proxy
      end

      # Stream the request through a proxy, confirming the proxy is ready
      # before the body is consumed
      #
      # Sends the headers with an `Expect: 100-continue` header, then yields
      # so the caller can check the proxy's interim response. The body is
      # only streamed when the block returns a truthy value, so one-shot
      # body streams are never consumed when the proxy refuses the request.
      #
      # @example
      #   request.stream_with_proxy_handshake(socket) { proxy_ready? }
      #
      # @return [Boolean] whether the body was streamed
      # @api public
      def stream_with_proxy_handshake(socket)
        include_proxy_headers if using_proxy? && !@uri.https?
        headers[Headers::EXPECT] ||= "100-continue"

        writer = Writer.new(socket, body, headers, headline)
        writer.stream_headers

        return false unless yield

        writer.stream_body
        true
      end

      # Compute HTTP request header SSL proxy connection
      #
      # @example
      #   request.proxy_connect_header
      #
      # @return [String]
      # @api public
      def proxy_connect_header
        "CONNECT #{host}:#{port} HTTP/#{version}"
      end

      # Headers to send with proxy connect request
      #
      # @example
      #   request.proxy_connect_headers
      #
      # @return [HTTP::Headers]
      # @api public
      def proxy_connect_headers
        connect_headers = Headers.coerce(
          Headers::HOST       => headers[Headers::HOST],
          Headers::USER_AGENT => headers[Headers::USER_AGENT]
        )

        connect_headers[Headers::PROXY_AUTHORIZATION] = proxy_authorization_header if using_authenticated_proxy?
        connect_headers.merge!(proxy[:proxy_headers]) if proxy.key?(:proxy_headers)
        connect_headers
      end
    end
  end
end
