# frozen_string_literal: true

module OAuth
  module Signature
    # Immutable record of a signature verification attempt, delivered to the
    # host's audit callback.
    #
    # On success it carries the exact consumer secret version that verified the
    # request. On failure it carries no information about which part of the key
    # was correct, so audit logs cannot become a side channel.
    class AuditEvent
      # @return [Symbol] +:success+ or +:failure+
      attr_reader :result
      # @return [Object, nil] version of the consumer secret that matched
      attr_reader :consumer_version
      # @return [String] the request's consumer key
      attr_reader :consumer_key
      # @return [String, nil] the request's token
      attr_reader :token
      # @return [String] the signature method used by the request
      attr_reader :signature_method
      # @return [Array<Object>] versions considered before a decision was made
      attr_reader :considered_versions
      # @return [Symbol, nil] machine-readable failure category, nil on success
      attr_reader :error

      def initialize(result:, consumer_key:, token:, signature_method:, considered_versions:,
                     consumer_version: nil, error: nil)
        @result = result
        @consumer_version = consumer_version
        @consumer_key = consumer_key
        @token = token
        @signature_method = signature_method
        @considered_versions = considered_versions.dup.freeze
        @error = error
        freeze
      end

      # @return [Boolean]
      def success?
        result == :success
      end

      # @return [Boolean]
      def failure?
        !success?
      end

      def to_h
        {
          result: result,
          consumer_version: consumer_version,
          consumer_key: consumer_key,
          token: token,
          signature_method: signature_method,
          considered_versions: considered_versions,
          error: error
        }
      end
    end
  end
end
