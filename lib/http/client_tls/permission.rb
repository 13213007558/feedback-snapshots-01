# frozen_string_literal: true

require "http/errors"
require "http/uri"

module HTTP
  module ClientTLS
    # Restricts the origins that may receive the configured client
    # certificate (mTLS) handshake material.
    #
    # An allowlist of origins is derived from deployment convention: only
    # those origins are permitted to complete a TLS handshake while the
    # client certificate is configured. Requests aimed at any other origin
    # are rejected with an explanatory {HTTP::ClientCertificateError}
    # before any connection is opened.
    #
    # @example
    #   permission = HTTP::ClientTLS::Permission.new(
    #     ["https://billing.internal", "https://vault.internal:8443"]
    #   )
    #   permission.verify!(HTTP::URI.parse("https://billing.internal/v1")) # => true
    #
    class Permission
      # Origins allowed to receive the client certificate
      #
      # @example
      #   permission.allowed_origins # => ["https://billing.internal"]
      #
      # @return [Array<String>] normalized allowed origins
      attr_reader :allowed_origins

      # Builds a permission policy from origin strings or URIs
      #
      # @param origins [Array<String, HTTP::URI>, String, HTTP::URI] origins
      #   permitted to receive the client certificate
      # @return [Permission]
      def initialize(origins)
        @allowed_origins = Array(origins).map { |origin| HTTP::URI.parse(origin).origin }.freeze
      end

      # Whether the given URI targets an allowed origin
      #
      # @example
      #   permission.allowed?(HTTP::URI.parse("https://billing.internal/v1"))
      #
      # @param uri [HTTP::URI] the URI of the upcoming request
      # @return [Boolean]
      def allowed?(uri)
        allowed_origins.include?(uri.origin)
      end

      # Raises unless the given URI targets an allowed origin
      #
      # @example
      #   permission.verify!(uri)
      #
      # @param uri [HTTP::URI] the URI of the upcoming request
      # @raise [ClientCertificateError] when the origin is not allowlisted
      # @return [void]
      def verify!(uri)
        return if allowed?(uri)

        raise ClientCertificateError,
              "Client certificate is not authorized for #{uri.origin}; " \
              "allowed origins: #{allowed_origins.join(', ')}"
      end
    end
  end
end
