# frozen_string_literal: true

require "cgi"
require "digest/sha1"
require "stringio"
require "uri"

require "oauth/errors/error"
require "oauth/helper"
require "oauth/request_proxy/net_http"

module OAuth
  module Client
    # Optional guard wrapper around a signed Net::HTTPGenericRequest.
    #
    # Business code frequently mutates a request after #oauth! has signed it:
    # appending query parameters, replacing the body, or setting a Content-Type.
    # Any of those silently invalidates the signature, because the signature is
    # computed over the method, the request target, the signed parameters and
    # (via oauth_body_hash) the exact body bytes.
    #
    # SignedRequest pins a fingerprint of everything the signature binds, at
    # the moment of signing, and re-checks it before the request goes on the
    # wire:
    #
    # * +method+       - the HTTP method (GET, POST, ...)
    # * +target+       - the request path, including the query string
    # * +parameters+   - every parameter participating in the signature
    #                    (query params, form body params, OAuth header params)
    # * +content_type+ - the Content-Type, but only while a body is present,
    #                    because it decides whether the body is signed as form
    #                    parameters or covered by oauth_body_hash
    # * +body+         - the exact body bytes, when they are covered by
    #                    oauth_body_hash (non form-urlencoded bodies and
    #                    body_stream bodies)
    #
    # Everything else - most notably transport headers unrelated to the
    # signature such as Accept, User-Agent or Connection - may change freely.
    #
    # When a bound component has changed, #perform refuses to send and raises
    # SignatureInvalidatedError. The request can then be explicitly re-signed
    # with #resign!, which always uses a fresh nonce and timestamp (unless
    # explicitly overridden) - the old nonce is never silently reused.
    #
    # A SignedRequest is single-use: after #perform, it must be re-signed
    # before it can be performed again, so a retry after a signature failure
    # is always an explicit, freshly-signed request.
    #
    # Streaming bodies (body_stream) are buffered once into a rewindable
    # StringIO, so the fingerprint can be re-read and the stream re-sent any
    # number of times.
    #
    #   request = Net::HTTP::Post.new("/test")
    #   request.body = "data"
    #   request.content_type = "text/ascii"
    #   signed = OAuth::Client::SignedRequest.new(request, http: http, consumer: consumer, token: token)
    #   signed["Accept"] = "application/json" # allowed: unrelated to the signature
    #   signed.perform                        # => sends via http
    #
    # Alternatively, sign first and wrap afterwards:
    #
    #   request.oauth!(http, consumer, token)
    #   signed = OAuth::Client::SignedRequest.new(request, http: http)
    class SignedRequest
      # Raised when a signature-bound component of the request changed after
      # signing. Carries the list of changed components in #changes.
      class SignatureInvalidatedError < OAuth::Error
        attr_reader :changes

        def initialize(changes)
          @changes = changes
          super("request was modified after signing (#{changes.join(', ')}): " \
                "revert the change or call #resign! to re-sign with a fresh nonce")
        end
      end

      # Raised when a SignedRequest is performed twice without an intervening
      # #resign!, which would silently reuse the old nonce.
      class AlreadyPerformedError < OAuth::Error
        def initialize
          super("this signed request was already performed: " \
                "call #resign! to retry with a fresh nonce and timestamp")
        end
      end

      # Components of the request bound by the OAuth signature.
      BOUND_COMPONENTS = %i[method target parameters content_type body].freeze

      attr_reader :request

      # Wrap +request+, a Net::HTTPGenericRequest.
      #
      # With <tt>consumer:</tt> (and <tt>http:</tt>) the request is signed via
      # #oauth! first, using any remaining options (nonce:, timestamp:,
      # scheme:, ...). Without <tt>consumer:</tt> the request must already be
      # signed, otherwise an ArgumentError is raised.
      def initialize(request, http: nil, consumer: nil, token: nil, **sign_options)
        @request = request
        @http = http
        @consumer = consumer
        @token = token
        @sign_options = sign_options
        @performed = false

        if consumer
          raise ArgumentError, "http is required to sign the request" unless http

          request.oauth!(http, consumer, token, sign_options)
        elsif !self.class.signed?(request)
          raise ArgumentError, "request is not signed: call #oauth! first, or pass :consumer and :http to sign"
        end

        capture_fingerprint!
      end

      # Whether the request carries OAuth signature material.
      def self.signed?(request)
        return true if request["Authorization"].to_s.start_with?("OAuth")
        return true if request.path.to_s.include?("oauth_signature=")
        return true if request.body.to_s.include?("oauth_signature=")

        false
      end

      # Read a header of the wrapped request.
      def [](key)
        request[key]
      end

      # Set a header of the wrapped request. Headers other than Content-Type
      # (on requests with a body) are transport concerns unrelated to the
      # signature and may change freely after signing.
      def []=(key, value)
        request[key] = value
      end

      # Names of the signature-bound components that changed since signing
      # (or since the last #resign!). Empty when the signature still matches.
      def changes
        current = current_fingerprint
        BOUND_COMPONENTS.select { |component| @fingerprint[component] != current[component] }
      end

      # Whether the request still matches the signature.
      def valid?
        changes.empty?
      end

      # Raise SignatureInvalidatedError if a signature-bound component changed.
      def verify!
        found = changes
        raise SignatureInvalidatedError, found unless found.empty?

        true
      end

      # Verify the fingerprint and send the request through +http+ (defaults
      # to the http object given at wrap time). Returns http.request's response.
      def perform(http = nil)
        http ||= @http
        raise ArgumentError, "an http object is required to perform the request" unless http
        raise AlreadyPerformedError if @performed

        verify!
        @performed = true
        http.request(request)
      end

      # Explicitly re-sign the (possibly modified) request and re-pin the
      # fingerprint. A fresh nonce and timestamp are generated unless passed
      # explicitly, so the old nonce is never silently reused.
      def resign!(http: nil, **overrides)
        unless @consumer
          raise ArgumentError, "cannot re-sign: wrap with :consumer (and :http) to enable #resign!"
        end

        @http = http if http
        raise ArgumentError, "cannot re-sign: no http object known, pass http:" unless @http

        clear_oauth_params!
        @sign_options = @sign_options.merge(overrides)
        @sign_options[:nonce] = overrides.fetch(:nonce) { OAuth::Helper.generate_key }
        @sign_options[:timestamp] = overrides.fetch(:timestamp) { OAuth::Helper.generate_timestamp }
        request.oauth!(@http, @consumer, @token, @sign_options)
        capture_fingerprint!
        self
      end

      private

      def capture_fingerprint!
        @fingerprint = current_fingerprint
        @performed = false
      end

      def current_fingerprint
        {
          method: request.method.to_s,
          target: request.path.to_s,
          parameters: signed_parameters,
          content_type: body_carrier? ? request.content_type.to_s.downcase : nil,
          body: bound_body_digest
        }
      end

      def signed_parameters
        params = OAuth::RequestProxy.proxy(request).parameters
        params.keys.sort.map { |key| [key, Array(params[key]).map(&:to_s).sort] }
      end

      def body_carrier?
        !request.body.nil? || !request.body_stream.nil?
      end

      # Digest of the exact body bytes, but only when those bytes are covered
      # by the signature (oauth_body_hash): non form-urlencoded string bodies
      # and all body_stream bodies. Form bodies are bound via their parameters.
      def bound_body_digest
        if request.body_stream
          Digest::SHA1.hexdigest(buffer_stream!)
        elsif request.body && !form_url_encoded?
          Digest::SHA1.hexdigest(request.body)
        end
      end

      # Read the body stream and replace it with a rewindable StringIO, so the
      # fingerprint can be re-read and the body re-sent any number of times.
      def buffer_stream!
        stream = request.body_stream
        stream.rewind if stream.equal?(@installed_buffer)
        bytes = stream.read
        @installed_buffer = StringIO.new(bytes)
        request.body_stream = @installed_buffer
        bytes
      end

      def form_url_encoded?
        request.content_type.to_s.downcase.start_with?("application/x-www-form-urlencoded")
      end

      # Remove stale OAuth material before re-signing, so old parameters do
      # not leak into the new signature base string.
      def clear_oauth_params!
        request.delete("Authorization") if request["Authorization"].to_s.start_with?("OAuth")

        uri = URI.parse(request.path)
        if uri.query
          kept = reject_oauth_pairs(uri.query.split("&"))
          uri.query = kept.empty? ? nil : kept.join("&")
          request.instance_variable_set(:@path, uri.to_s)
        end

        return unless form_url_encoded? && request.body.to_s.include?("oauth_")

        body = reject_oauth_pairs(request.body.split("&")).join("&")
        request.body = body
        request.content_length = body.bytesize
      end

      def reject_oauth_pairs(pairs)
        pairs.reject { |pair| OAuth::Helper.unescape(pair.split("=", 2).first.to_s).start_with?("oauth_") }
      end
    end
  end
end
