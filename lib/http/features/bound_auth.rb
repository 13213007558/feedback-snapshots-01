# frozen_string_literal: true

require "set"

module HTTP
  module Features
    # Opt-in authorization that is bound to specific business resources and
    # attached only to read-only requests.
    #
    # A gateway hands the client an authorization material (for example a
    # signed token or an API key) together with the resources it is valid for.
    # This feature rewrites every outgoing request so that:
    #
    # * its target is one of the approved resources, possibly reached through
    #   an approved path alias (a resource migration the gateway already
    #   consented to),
    # * it keeps a safe, read-only verb (`GET` or `HEAD`) with no request
    #   body, and
    # * the material is attached at the location the gateway indicated
    #   (an {#ATTACH_HEADER header} or an {#ATTACH_QUERY query parameter}).
    #
    # Requests that cannot be proven to target an approved resource, or that
    # are not read-only, are rejected before anything is sent. The approval is
    # therefore verifiable on the request that actually goes over the wire,
    # including any default query parameters the client adds, and keeps
    # working when an approved resource moves to an approved alias.
    #
    # @example Attach a bearer token to a single resource
    #   feature = HTTP::Features::BoundAuth.new(
    #     material: "token-123",
    #     resources: ["https://api.example.com/v1/orders/42"],
    #     attach: { in: :header, name: "Authorization", scheme: "Bearer" }
    #   )
    #
    # @example Allow an approved resource migration through a path alias
    #   feature = HTTP::Features::BoundAuth.new(
    #     material: "token-123",
    #     resources: ["https://api.example.com/v1/orders/42"],
    #     aliases: { "https://api.example.com/v2/orders/42" =>
    #                  "https://api.example.com/v1/orders/42" },
    #     attach: { in: :query, name: "access_token" }
    #   )
    class BoundAuth < Feature
      # Material is sent in an HTTP header.
      ATTACH_HEADER = :header

      # Material is sent as a query string parameter.
      ATTACH_QUERY = :query

      # Where an authorization material may be attached.
      ATTACH_LOCATIONS = [ATTACH_HEADER, ATTACH_QUERY].freeze

      # Read-only HTTP verbs this feature is willing to send.
      READ_ONLY_VERBS = Set.new(%i[get head]).freeze

      # Default location used when `attach` does not specify one.
      DEFAULT_ATTACH = { in: ATTACH_HEADER, name: Headers::AUTHORIZATION }.freeze

      # Error raised when a request cannot be authorized under the binding.
      class BindingError < RequestError; end

      # The authorization material supplied by the gateway.
      #
      # @example
      #   feature.material # => "token-123"
      #
      # @return [String]
      # @api public
      attr_reader :material

      # Approved resource URIs, normalized for comparison.
      #
      # @example
      #   feature.resources
      #
      # @return [Array<HTTP::URI>]
      # @api public
      attr_reader :resources

      # Approved path aliases mapping a migration location to its resource.
      #
      # @example
      #   feature.aliases
      #
      # @return [Hash{HTTP::URI => HTTP::URI}]
      # @api public
      attr_reader :aliases

      # The rule describing where the material is attached.
      #
      # @example
      #   feature.attach # => {in: :header, name: "Authorization", scheme: "Bearer"}
      #
      # @return [Hash{Symbol => Object}]
      # @api public
      attr_reader :attach

      # Initializes the BoundAuth feature
      #
      # @example
      #   BoundAuth.new(
      #     material: "token-123",
      #     resources: ["https://example.com/orders/42"],
      #     aliases: { "https://example.com/v2/orders/42" =>
      #                  "https://example.com/orders/42" },
      #     attach: { in: :header, name: "Authorization", scheme: "Bearer" }
      #   )
      #
      # @param material [#to_s] the authorization material from the gateway
      # @param resources [Array<#to_s>] URIs the material is valid for
      # @param aliases [Hash{#to_s => #to_s}] approved migration locations
      #   mapped to the resource they stand in for
      # @param attach [Hash] where to attach the material
      # @option attach [Symbol] :in (:header) `:header` or `:query`
      # @option attach [#to_s] :name header or query parameter name
      # @option attach [#to_s, nil] :scheme optional auth scheme prefix
      #   (e.g. `"Bearer"`) used for header attachment
      # @return [BoundAuth]
      # @raise [BindingError] if the configuration is invalid
      # @api public
      def initialize(material:, resources:, aliases: {}, attach: {})
        @material         = String(material)
        @resources        = Array(resources).map { |uri| normalize_resource(uri) }.freeze
        @aliases          = normalize_aliases(aliases)
        @alias_resources  = @aliases.transform_keys { |location| resource_identity(location) }
        @attach           = prepare_attach(attach)
        @hops             = []
        @blocked          = []
        validate!
      end

      # Rewrites a request so the authorization is verifiable on the wire
      #
      # Rejects non-read-only requests and anything outside the approved
      # resources (or their approved aliases), then returns a bodyless
      # read-only request with the material attached at the configured
      # location.
      #
      # @example
      #   feature.wrap_request(request)
      #
      # @param request [HTTP::Request] the request as built by the client
      # @return [HTTP::Request] the authorized, read-only request
      # @raise [BindingError] if the request cannot be authorized
      # @api public
      def wrap_request(request)
        ensure_read_only!(request)
        resource = resolve_resource(request.uri)
        authorized = rebuild(request)

        record_hop(authorized, resource)
        authorized
      end

      # Record of every request this feature attached material to
      #
      # Each entry describes one hop: the request that was actually sent, the
      # approved resource it was bound to, and the category of material that
      # was attached.
      #
      # @example
      #   feature.hops
      #
      # @return [Array<Hash{Symbol => Object}>]
      # @api public
      def hops
        @hops.dup
      end

      # Record of requests that were stopped before anything was sent
      #
      # Each entry pairs the rejected request (when one existed) with the
      # reason it was not sent.
      #
      # @example
      #   feature.blocked
      #
      # @return [Array<Hash{Symbol => Object}>]
      # @api public
      def blocked
        @blocked.dup
      end

      # Category of the authorization material
      #
      # Derived from the configured auth scheme, falling back to the generic
      # `"token"` category. Used to describe what each hop carried.
      #
      # @example
      #   feature.material_category # => "bearer"
      #
      # @return [String]
      # @api public
      def material_category
        attach[:scheme] ? String(attach[:scheme]).downcase : "token"
      end

      private

      # Reject verbs that are not safe and read-only
      #
      # @param request [HTTP::Request]
      # @return [void]
      # @raise [BindingError]
      # @api private
      def ensure_read_only!(request)
        return if READ_ONLY_VERBS.include?(request.verb)

        block!(request, "non read-only verb: #{request.verb}")
      end

      # Resolve a request URI to its approved resource
      #
      # @param uri [HTTP::URI] the actual request URI, with default params
      # @return [HTTP::URI] the matching approved resource
      # @raise [BindingError] when no approval covers the URI
      # @api private
      def resolve_resource(uri)
        resource_for(uri) || @alias_resources.fetch(resource_identity(uri)) { block_uri!(uri) }
      end

      # Find the approved resource matching a URI, ignoring its query string
      #
      # Only the origin and path identify a resource; the query string (which
      # may carry client default parameters) is intentionally not part of the
      # binding.
      #
      # @param uri [HTTP::URI]
      # @return [HTTP::URI, nil]
      # @api private
      def resource_for(uri)
        resources.find { |resource| same_resource?(resource, uri) }
      end

      # Whether two URIs identify the same business resource
      #
      # @param left [HTTP::URI]
      # @param right [HTTP::URI]
      # @return [Boolean]
      # @api private
      def same_resource?(left, right)
        resource_identity(left) == resource_identity(right)
      end

      # The query-independent identity of a resource
      #
      # @param uri [HTTP::URI]
      # @return [Array(String, String)] the origin and path
      # @api private
      def resource_identity(uri)
        [uri.origin, uri.path]
      end

      # Rebuild the request as an authorized, read-only request
      #
      # The (already validated) read-only verb is preserved and any request
      # body is dropped. The target URI, including the alias path and any
      # default query parameters, is kept so the server sees the request the
      # client actually intended to send.
      #
      # @param request [HTTP::Request] the original request
      # @return [HTTP::Request]
      # @api private
      def rebuild(request)
        uri     = request.uri.dup
        headers = request.headers.dup

        attach_material(uri, headers)

        Request.new(
          verb:           request.verb,
          uri:            uri,
          headers:        headers,
          proxy:          request.proxy,
          body:           nil,
          version:        request.version,
          uri_normalizer: request.uri_normalizer
        )
      end

      # Attach the material at the configured location
      #
      # @param uri [HTTP::URI] mutated when attaching to the query
      # @param headers [HTTP::Headers] mutated when attaching to a header
      # @return [void]
      # @api private
      def attach_material(uri, headers)
        if attach[:in] == ATTACH_QUERY
          append_query_param(uri, attach[:name], material)
        else
          headers.set(attach[:name], header_value)
        end
      end

      # Build the header value, prefixing the auth scheme when configured
      #
      # @return [String]
      # @api private
      def header_value
        attach[:scheme] ? "#{attach[:scheme]} #{material}" : material
      end

      # Append a parameter to a URI's query string without dropping others
      #
      # @param uri [HTTP::URI]
      # @param name [#to_s]
      # @param value [#to_s]
      # @return [void]
      # @api private
      def append_query_param(uri, name, value)
        existing = ::URI.decode_www_form(uri.query || "")
        existing << [String(name), String(value)]
        uri.query = ::URI.encode_www_form(existing)
      end

      # Record a hop that carried material
      #
      # @param request [HTTP::Request] the request actually sent
      # @param resource [HTTP::URI] the approved resource it was bound to
      # @return [void]
      # @api private
      def record_hop(request, resource)
        @hops << {
          request:           request,
          verb:              request.verb,
          uri:               request.uri.dup,
          resource:          resource,
          material_category: material_category,
          attached_in:       attach[:in],
          attached_name:     attach[:name]
        }
      end

      # Stop and record a request that failed read-only validation
      #
      # @param request [HTTP::Request]
      # @param reason [String]
      # @raise [BindingError]
      # @api private
      def block!(request, reason)
        @blocked << { request: request, uri: request.uri.dup, reason: reason }
        raise BindingError, "refusing to send #{request.verb.upcase} #{request.uri}: #{reason}"
      end

      # Stop and record a URI that has no matching approval
      #
      # @param uri [HTTP::URI]
      # @raise [BindingError]
      # @api private
      def block_uri!(uri)
        @blocked << { request: nil, uri: uri.dup, reason: "no approved resource or alias" }
        raise BindingError, "no approved resource or alias for #{uri}"
      end

      # Normalize a resource URI for stable comparison
      #
      # @param uri [#to_s]
      # @return [HTTP::URI]
      # @api private
      def normalize_resource(uri)
        HTTP::URI.parse(uri.to_s).normalize
      end

      # Normalize the alias mapping and freeze it
      #
      # @param aliases [Hash{#to_s => #to_s}]
      # @return [Hash{HTTP::URI => HTTP::URI}]
      # @api private
      def normalize_aliases(aliases)
        aliases.each_with_object({}) do |(location, resource), hash|
          hash[normalize_resource(location)] = normalize_resource(resource)
        end.freeze
      end

      # Validate and freeze the attachment rule
      #
      # @param attach [Hash]
      # @return [Hash{Symbol => Object}]
      # @raise [BindingError]
      # @api private
      def prepare_attach(attach)
        rule = DEFAULT_ATTACH.merge(attach)
        location = rule[:in]

        unless ATTACH_LOCATIONS.include?(location)
          raise BindingError, "unsupported attach location: #{location.inspect}"
        end
        raise BindingError, "attach name is required" if rule[:name].nil?

        name = String(rule[:name])
        raise BindingError, "attach name is required" if name.empty?

        rule.merge(
          in:     location,
          name:   name,
          scheme: rule[:scheme] ? String(rule[:scheme]) : nil
        ).freeze
      end

      # Validate the overall configuration
      #
      # @return [void]
      # @raise [BindingError]
      # @api private
      def validate!
        raise BindingError, "material is required" if material.empty?
        raise BindingError, "at least one resource is required" if resources.empty?

        resource_identities = resources.map { |resource| resource_identity(resource) }

        aliases.each do |location, resource|
          next if resource_identities.include?(resource_identity(resource))

          raise BindingError, "alias #{location} points to unapproved resource #{resource}"
        end
      end

      HTTP::Options.register_feature(:bound_auth, self)
    end
  end
end
