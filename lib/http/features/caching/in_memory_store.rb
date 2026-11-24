# frozen_string_literal: true

module HTTP
  module Features
    class Caching < Feature
      # Simple in-memory cache store backed by a Hash
      #
      # Cache keys are derived from the request method and URI. Each key holds
      # the variants stored for that resource, so a cache entry can be scoped
      # to an access scope and to the request headers selected by `Vary`.
      #
      # @example
      #   store = InMemoryStore.new
      #   store.store(request, entry)
      #   store.lookup(request) # => entry
      #
      class InMemoryStore
        # Create a new empty in-memory store
        #
        # @example
        #   store = InMemoryStore.new
        #
        # @return [InMemoryStore]
        # @api public
        def initialize
          @cache = {}
        end

        # Look up a cached entry for a request
        #
        # Returns the most recent exact-scope entry whose variant key matches
        # the request headers, falling back to a shared public entry. Scoped
        # entries are never returned to a different scope.
        #
        # @example
        #   store.lookup(request) # => Entry or nil
        #
        # @param request [HTTP::Request]
        # @param scope [Symbol, String] access scope of the caller
        # @return [Entry, nil]
        # @api public
        def lookup(request, scope: :public)
          entries = @cache[cache_key(request)]
          return unless entries

          exact = entries.reverse_each.find do |entry|
            entry.scope == scope && entry.variant_matches?(request.headers)
          end
          return exact if exact

          entries.reverse_each.find do |entry|
            entry.scope == :public &&
              entry.visible_to?(scope) &&
              entry.variant_matches?(request.headers)
          end
        end

        # Store a cache entry for a request
        #
        # @example
        #   store.store(request, entry)
        #
        # @param request [HTTP::Request]
        # @param entry [Entry]
        # @return [Entry]
        # @api public
        def store(request, entry)
          key = cache_key(request)
          entries = (@cache[key] ||= [])
          entries.delete_if { |existing| same_variant?(existing, entry) }
          entries << entry
        end

        private

        # Whether two entries occupy the same scope and variant slot
        # @return [Boolean]
        # @api private
        def same_variant?(left, right)
          left.scope == right.scope && left.vary_key == right.vary_key
        end

        # Compute the cache key for a request
        # @return [String]
        # @api private
        def cache_key(request)
          format("%s %s", request.verb, request.uri)
        end
      end
    end
  end
end
