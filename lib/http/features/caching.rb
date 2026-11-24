# frozen_string_literal: true

require "digest"
require "time"

require "http/features/caching/entry"
require "http/features/caching/in_memory_store"

module HTTP
  module Features
    # HTTP caching feature that stores and reuses responses according to
    # RFC 7234. Only GET and HEAD responses are cached. Supports
    # `Cache-Control`, `Expires`, `ETag`, and `Last-Modified` for freshness
    # checks and conditional revalidation.
    #
    # Responses can be partitioned by an optional access scope and by the
    # request headers selected by the response's `Vary` header. Publicly
    # shareable responses remain reusable across callers, while restricted
    # responses are only served to the scope that stored them. Responses are
    # keyed before storage so credentials are never persisted.
    #
    # @example Basic usage with in-memory cache
    #   HTTP.use(:caching).get("https://example.com/")
    #
    # @example With a shared store across requests
    #   store = HTTP::Features::Caching::InMemoryStore.new
    #   client = HTTP.use(caching: { store: store })
    #   client.get("https://example.com/")
    #
    # @example Partitioning restricted responses by access scope
    #   scope = ->(request) { request.headers["Authorization"] }
    #   client = HTTP.use(caching: { store: store, access_scope: scope })
    #
    class Caching < Feature
      CACHEABLE_METHODS = Set.new(%i[get head]).freeze
      private_constant :CACHEABLE_METHODS

      # The cache store instance
      #
      # @example
      #   feature.store
      #
      # @return [#lookup, #store] the cache store
      # @api public
      attr_reader :store

      # The access scope mapping, when configured
      #
      # @example
      #   feature.access_scope
      #
      # @return [#call, nil] maps a request to an access scope
      # @api public
      attr_reader :access_scope

      # Initializes the Caching feature
      #
      # @example
      #   Caching.new(store: InMemoryStore.new)
      #
      # @param store [#lookup, #store] cache store instance
      # @param access_scope [#call, nil] maps a request to an access scope; a
      #   nil scope uses the default `:public` scope
      # @return [Caching]
      # @api public
      def initialize(store: InMemoryStore.new, access_scope: nil)
        @store = store
        @access_scope = access_scope
      end

      # Wraps the HTTP exchange with caching logic
      #
      # Checks the cache before making a request. Returns a cached response
      # if fresh; otherwise adds conditional headers and revalidates. Stores
      # cacheable responses for future use.
      #
      # @example
      #   feature.around_request(request) { |req| perform_exchange(req) }
      #
      # @param request [HTTP::Request]
      # @yield Executes the HTTP exchange
      # @yieldreturn [HTTP::Response]
      # @return [HTTP::Response]
      # @api public
      def around_request(request)
        return yield(request) unless cacheable_request?(request)

        scope = persisted_scope(scope_for(request), request)
        entry = lookup(request, scope)

        return yield(request) unless entry

        return build_cached_response(entry, request) if entry.fresh?

        conditional_request = add_conditional_headers(request, entry)
        response = yield(conditional_request)

        if response.status.not_modified?
          return revalidate_entry(entry, response, request, conditional_request, scope)
        end

        response
      end

      # Stores cacheable responses in the cache
      #
      # @example
      #   feature.wrap_response(response)
      #
      # @param response [HTTP::Response]
      # @return [HTTP::Response]
      # @api public
      def wrap_response(response)
        return response unless cacheable_request?(response.request)
        return response unless cacheable_response?(response)

        store_and_freeze_response(response)
      end

      private

      # Look up an entry, keeping compatibility with stores that only accept a
      # request
      # @return [Entry, nil]
      # @api private
      def lookup(request, scope)
        return store.lookup(request) unless scope_configured?

        store.lookup(request, scope: scope)
      end

      # Revalidate a cached entry with a 304 response
      #
      # The approval that produced the conditional request is checked again
      # here. If it was withdrawn while the request was in flight, the late
      # 304 is not allowed to refresh the entry, so the stored representation
      # keeps its previous freshness state and the caller gets an explicit
      # result instead of a silently reused body.
      #
      # @param request [HTTP::Request] original request from the caller
      # @param conditional_request [HTTP::Request] request sent to revalidate
      # @param scope [Symbol, String] access scope of the original request
      # @return [HTTP::Response]
      # @api private
      def revalidate_entry(entry, response, request, conditional_request, scope)
        unless approved?(conditional_request, entry, scope)
          return Response.new(
            status:        304,
            version:       response.version,
            headers:       response.headers,
            proxy_headers: response.proxy_headers,
            body:          "",
            request:       request
          )
        end

        entry.update_headers!(Entry.sanitize_headers(response.headers))
        entry.revalidate!(etag: conditional_request.headers[Headers::IF_NONE_MATCH],
                           scope:    scope)
        build_cached_response(entry, request)
      end

      # Store response in cache and return a new response with eagerly-read body
      # @return [HTTP::Response]
      # @api private
      def store_and_freeze_response(response)
        body_string = String(response)
        store.store(response.request, build_entry(response, body_string))

        Response.new(
          status:        response.code,
          version:       response.version,
          headers:       response.headers,
          proxy_headers: response.proxy_headers,
          body:          body_string,
          request:       response.request
        )
      end

      # Build a cache entry from a response
      # @return [Entry]
      # @api private
      def build_entry(response, body_string)
        Entry.new(
          status:        response.code,
          version:       response.version,
          headers:       Entry.sanitize_headers(response.headers),
          proxy_headers: response.proxy_headers,
          body:          body_string,
          request_uri:   response.uri,
          stored_at:     now,
          scope:         persisted_scope(scope_for(response.request), response.request),
          vary_key:      vary_key(response)
        )
      end

      # Check whether this request method is cacheable
      # @return [Boolean]
      # @api private
      def cacheable_request?(request)
        CACHEABLE_METHODS.include?(request.verb)
      end

      # Check whether this response is cacheable
      # @return [Boolean]
      # @api private
      def cacheable_response?(response)
        return false if response.status < 200
        return false if response.status >= 400

        directives = parse_cache_control(response.headers)
        return false if directives.include?("no-store")
        return false if vary_names(response).include?("*")
        return false if restricted?(response) && (!scope_configured? || scope_for(response.request) == :public)

        freshness_info?(response, directives)
      end

      # Whether the response is restricted to a single caller
      #
      # A `public` directive explicitly makes the response shareable and wins
      # over any credential-based restriction. Otherwise, `private` responses
      # and responses that vary on credentials must not be shared.
      # @return [Boolean]
      # @api private
      def restricted?(response)
        directives = parse_cache_control(response.headers)
        return false if directives.include?("public")
        return true if directives.include?("private")

        vary_names(response).any? { |name| Entry::SENSITIVE_VARY_HEADERS.any? { |h| h.casecmp?(name) } }
      end

      # The access scope selected for a request
      #
      # @param request [HTTP::Request]
      # @return [Symbol, String]
      # @api private
      def scope_for(request)
        return :public unless scope_configured?

        @access_scope.call(request) || :public
      end

      # Whether an access scope mapping was configured
      # @return [Boolean]
      # @api private
      def scope_configured?
        !@access_scope.nil?
      end

      # Convert a resolved scope to the value persisted in the store
      #
      # A raw credential must not be stored as an access scope. When a scope
      # is the value of a credential header, it is one-way hashed before use.
      #
      # @param scope [Symbol, String]
      # @param request [HTTP::Request]
      # @return [Symbol, String]
      # @api private
      def persisted_scope(scope, request)
        return scope if scope.is_a?(Symbol) || scope.nil?

        credential_scope?(scope, request) ? "sha256:#{Digest::SHA256.hexdigest(scope)}" : scope
      end

      # Whether a resolved scope looks like a credential value
      # @return [Boolean]
      # @api private
      def credential_scope?(scope, request)
        %w[Authorization Proxy-Authorization Cookie].any? do |name|
          request.headers[name] == scope
        end
      end

      # Whether the conditional request is still approved for the entry
      #
      # A late 304 must not be applied once the scope that authorized the
      # conditional request has changed. Publicly shareable entries remain
      # valid for any caller.
      #
      # @return [Boolean]
      # @api private
      def approved?(conditional_request, entry, scope)
        return true if entry.scope == :public
        return true unless scope_configured?

        persisted_scope(scope_for(conditional_request), conditional_request) == entry.scope
      end

      # Whether the response carries enough information to determine freshness
      # @return [Boolean]
      # @api private
      def freshness_info?(response, directives)
        return true if directives.any? { |d| d.start_with?("max-age=") }
        return true if response.headers.include?(Headers::EXPIRES)
        return true if response.headers.include?(Headers::ETAG)

        response.headers.include?(Headers::LAST_MODIFIED)
      end

      # Parse Cache-Control header into a list of directives
      # @return [Array<String>]
      # @api private
      def parse_cache_control(headers)
        String(headers[Headers::CACHE_CONTROL]).downcase.split(",").map(&:strip)
      end

      # Build the variant key for a response from the request headers selected
      # by the response's `Vary` header
      #
      # A response explicitly marked `public` is shareable across callers, so
      # credential headers are left out of its variant key to keep it a hit for
      # every identity.
      # @return [Hash{String => String, nil}]
      # @api private
      def vary_key(response)
        names = vary_names(response)
        names -= Entry::SENSITIVE_VARY_HEADERS if shareable?(response)
        names.to_h do |name|
          [name, Entry.summarize(name, response.request.headers[name])]
        end
      end

      # Whether the response is explicitly marked as shareable
      # @return [Boolean]
      # @api private
      def shareable?(response)
        parse_cache_control(response.headers).include?("public")
      end

      # Request header names selected by the response's `Vary` header
      # @return [Array<String>]
      # @api private
      def vary_names(response)
        String(response.headers[Headers::VARY])
          .split(",")
          .map { |name| normalize_vary_name(name) }
          .reject(&:empty?)
      end

      # Normalize a `Vary` field name so it can be looked up in request headers
      # @return [String]
      # @api private
      def normalize_vary_name(name)
        name = name.strip
        Headers.normalizer.call(name)
      rescue HeaderError
        name.downcase
      end

      # Add conditional headers from a cached entry to the request
      # @return [HTTP::Request]
      # @api private
      def add_conditional_headers(request, entry)
        headers = request.headers.dup
        headers.delete(Headers::IF_NONE_MATCH)
        headers.delete(Headers::IF_MODIFIED_SINCE)

        etag = entry.headers[Headers::ETAG]
        last_modified = entry.headers[Headers::LAST_MODIFIED]
        headers[Headers::IF_NONE_MATCH] = etag if etag
        headers[Headers::IF_MODIFIED_SINCE] = last_modified if last_modified

        Request.new(
          verb:    request.verb,
          uri:     request.uri,
          headers: headers,
          proxy:   request.proxy,
          body:    request.body,
          version: request.version
        )
      end

      # Build a response from a cached entry
      # @return [HTTP::Response]
      # @api private
      def build_cached_response(entry, request)
        Response.new(
          status:        entry.status,
          version:       entry.version,
          headers:       entry.headers,
          proxy_headers: entry.proxy_headers,
          body:          entry.body,
          request:       request
        )
      end

      # Current time (extracted for testability)
      # @return [Time]
      # @api private
      def now
        Time.now
      end

      HTTP::Options.register_feature(:caching, self)
    end
  end
end
