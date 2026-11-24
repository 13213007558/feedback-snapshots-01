# frozen_string_literal: true

require "digest"
require "time"

module HTTP
  module Features
    class Caching < Feature
      # A cached response entry with freshness logic
      class Entry
        # Response headers that carry credentials (or credentials for the
        # client) and must not be persisted in the shared cache
        CREDENTIAL_HEADERS = %w[
          Authorization
          Proxy-Authorization
          Cookie
          Set-Cookie
        ].freeze

        # Request headers whose values are credentials and must be hashed
        # before being stored as part of a variant key
        SENSITIVE_VARY_HEADERS = %w[
          Authorization
          Proxy-Authorization
          Cookie
        ].freeze

        # The HTTP status code
        #
        # @example
        #   entry.status # => 200
        #
        # @return [Integer] the HTTP status code
        # @api public
        attr_reader :status

        # The HTTP version
        #
        # @example
        #   entry.version # => "1.1"
        #
        # @return [String] the HTTP version
        # @api public
        attr_reader :version

        # The response headers
        #
        # @example
        #   entry.headers
        #
        # @return [HTTP::Headers] the response headers
        # @api public
        attr_reader :headers

        # The proxy headers from the original response
        #
        # @example
        #   entry.proxy_headers
        #
        # @return [HTTP::Headers] the proxy headers
        # @api public
        attr_reader :proxy_headers

        # The response body as a string
        #
        # @example
        #   entry.body # => "<html>...</html>"
        #
        # @return [String] the response body
        # @api public
        attr_reader :body

        # The URI of the original request
        #
        # @example
        #   entry.request_uri
        #
        # @return [HTTP::URI] the request URI
        # @api public
        attr_reader :request_uri

        # When the response was stored
        #
        # @example
        #   entry.stored_at
        #
        # @return [Time] when the response was stored
        # @api public
        attr_reader :stored_at

        # The access scope this entry belongs to
        #
        # @example
        #   entry.scope # => :public
        #
        # @return [Symbol, String] the access scope (defaults to `:public`)
        # @api public
        attr_reader :scope

        # The variant key derived from the request headers selected by `Vary`
        #
        # @example
        #   entry.vary_key # => { "Accept-Language" => "en" }
        #
        # @return [Hash{String => String}] selected request header values
        # @api public
        attr_reader :vary_key

        # The request ETag used to build the conditional request that produced
        # this entry, when it was stored after a 304 revalidation
        #
        # @example
        #   entry.revalidated_with # => '"abc123"'
        #
        # @return [String, nil] the validator seen on the revalidating request
        # @api public
        attr_reader :revalidated_with

        # The access scope the entry was revalidated under
        #
        # @example
        #   entry.revalidated_scope # => :"user:42"
        #
        # @return [Symbol, String, nil]
        # @api public
        attr_reader :revalidated_scope

        # Create a new cache entry
        #
        # @example
        #   Entry.new(status: 200, version: "1.1", headers: headers,
        #             proxy_headers: proxy_headers, body: "hello",
        #             request_uri: uri, stored_at: Time.now)
        #
        # @param status [Integer]
        # @param version [String]
        # @param headers [HTTP::Headers]
        # @param proxy_headers [HTTP::Headers]
        # @param body [String]
        # @param request_uri [HTTP::URI]
        # @param stored_at [Time]
        # @param scope [Symbol, String] access scope (defaults to `:public`)
        # @param vary_key [Hash{String => String}] selected request headers
        # @param revalidated_with [String, nil] request ETag used to revalidate
        # @param revalidated_scope [Symbol, String, nil] scope used to revalidate
        # @return [Entry]
        # @api public
        def initialize(status:, version:, headers:, proxy_headers:, body:, request_uri:, stored_at:,
                       scope: :public, vary_key: {}, revalidated_with: nil, revalidated_scope: nil)
          @status            = status
          @version           = version
          @headers           = headers
          @proxy_headers     = proxy_headers
          @body              = body
          @request_uri       = request_uri
          @stored_at         = stored_at
          @scope             = scope
          @vary_key          = vary_key
          @revalidated_with  = revalidated_with
          @revalidated_scope = revalidated_scope
        end

        # Whether the cached response is still fresh
        #
        # @example
        #   entry.fresh? # => true
        #
        # @return [Boolean]
        # @api public
        def fresh?
          return false if no_cache?

          ttl = max_age
          return age < ttl if ttl

          expires = expires_at
          return Time.now < expires if expires

          false
        end

        # Reset the stored_at time to now (after successful revalidation)
        #
        # @example
        #   entry.revalidate!
        #
        # @param etag [String, nil] request ETag accepted by the 304
        # @param scope [Symbol, String, nil] access scope used to revalidate
        # @return [Time]
        # @api public
        def revalidate!(etag: nil, scope: nil)
          @revalidated_with  = etag
          @revalidated_scope = scope
          @stored_at = Time.now
        end

        # Merge response headers from a 304 revalidation into the stored entry
        #
        # @example
        #   entry.update_headers!(response.headers)
        #
        # @param response_headers [HTTP::Headers]
        # @return [void]
        # @api public
        def update_headers!(response_headers)
          response_headers.each { |name, value| @headers[name] = value }
        end

        # Whether this entry may satisfy a lookup for the given access scope
        #
        # Public entries can be shared with any caller. Scoped entries are
        # only returned to the exact scope that stored them.
        #
        # @param candidate [Symbol, String] the requesting access scope
        # @return [Boolean]
        # @api public
        def visible_to?(candidate)
          scope == :public || scope == candidate
        end

        # Whether this entry's variant key matches the given request headers
        #
        # @param request_headers [HTTP::Headers]
        # @return [Boolean]
        # @api public
        def variant_matches?(request_headers)
          vary_key.all? do |name, expected|
            self.class.summarize(name, request_headers[name]) == expected
          end
        end

        # The request header names selected by the response's `Vary` header
        #
        # @return [Array<String>]
        # @api public
        def vary_names
          String(headers[Headers::VARY])
            .split(",")
            .map { |name| normalize_vary_name(name) }
            .reject(&:empty?)
        end

        # Summarize a request header value for use in a variant key
        #
        # Credentials are one-way hashed so the shared store does not retain
        # usable bearer tokens or cookies, while still distinguishing callers.
        #
        # @param name [String] header name
        # @param value [String, Array<String>, nil] header value(s)
        # @return [String, nil]
        # @api public
        def self.summarize(name, value)
          return if value.nil?

          value = Array(value).join(", ")
          if SENSITIVE_VARY_HEADERS.any? { |header| header.casecmp?(name) }
            "sha256:#{Digest::SHA256.hexdigest(value)}"
          else
            value
          end
        end

        # A copy of the response headers safe to persist in a shared store
        #
        # @return [HTTP::Headers]
        # @api public
        def self.sanitize_headers(headers)
          sanitized = headers.dup
          CREDENTIAL_HEADERS.each { |name| sanitized.delete(name) }
          sanitized
        end

        private

        # Normalize a `Vary` field name for canonical header lookup
        # @return [String]
        # @api private
        def normalize_vary_name(name)
          name = name.strip
          Headers.normalizer.call(name)
        rescue HeaderError
          name.downcase
        end

        # Age of the entry in seconds
        # @return [Float]
        # @api private
        def age
          Float(Integer(headers[Headers::AGE], exception: false) || 0) + (Time.now - stored_at)
        end

        # max-age value from Cache-Control, if present
        # @return [Integer, nil]
        # @api private
        def max_age
          match = String(headers[Headers::CACHE_CONTROL]).match(/max-age=(\d+)/)
          return unless match

          Integer(match[1])
        end

        # Expiration time from Expires header
        # @return [Time, nil]
        # @api private
        def expires_at
          Time.httpdate(String(headers[Headers::EXPIRES]))
        rescue ArgumentError
          nil
        end

        # Whether the Cache-Control includes no-cache
        # @return [Boolean]
        # @api private
        def no_cache?
          String(headers[Headers::CACHE_CONTROL]).downcase.include?("no-cache")
        end
      end
    end
  end
end
