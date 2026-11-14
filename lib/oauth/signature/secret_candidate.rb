# frozen_string_literal: true

module OAuth
  module Signature
    # A versioned, time-bounded candidate for a consumer secret.
    #
    # Instances are returned by a host's credentials resolver and describe one
    # version of a consumer's secret. Validity is evaluated against an injected
    # clock so that overlapping windows, revocations and expiries can be
    # reasoned about deterministically.
    class SecretCandidate
      # @return [Object] opaque identifier of this secret version, handed to audit on a match
      attr_reader :version
      # @return [String, OpenSSL::PKey::PKey, OpenSSL::X509::Certificate] the secret material
      attr_reader :secret
      # @return [Time, nil] earliest time at which this version is valid
      attr_reader :valid_from
      # @return [Time, nil] time after which this version is no longer valid
      attr_reader :expires_at
      # @return [Time, nil] time at which this version was revoked, nil when active
      attr_reader :revoked_at

      # @param version [Object] identifier of the secret version (e.g. +"v1"+, +1+)
      # @param secret [String, Object] the secret material
      # @param valid_from [Time, nil] defaults to always valid in the past
      # @param expires_at [Time, nil] defaults to never expiring
      # @param revoked_at [Time, nil] set to a time to revoke the version
      def initialize(version:, secret:, valid_from: nil, expires_at: nil, revoked_at: nil)
        @version = version
        @secret = secret
        @valid_from = coerce_time(valid_from)
        @expires_at = coerce_time(expires_at)
        @revoked_at = coerce_time(revoked_at)
      end

      # A revoked version must be excluded immediately, regardless of any
      # remaining validity window.
      #
      # @return [Boolean]
      def revoked?
        !revoked_at.nil?
      end

      # @param now [Time] the server's current time
      # @return [Boolean] whether this version may still be used at +now+
      def valid_at?(now)
        return false if revoked?
        return false unless valid_from.nil? || now >= valid_from
        return false unless expires_at.nil? || now < expires_at

        true
      end

      # Build a candidate from a plain mapping, for convenience in resolvers.
      #
      # @param attributes [Hash]
      # @return [SecretCandidate]
      def self.[](attributes)
        new(**attributes)
      end

      private

      # Accept +Time+-like objects and integer epoch seconds alike.
      def coerce_time(value)
        return nil if value.nil?
        return value.to_time if value.respond_to?(:to_time)

        Time.at(value)
      end
    end

    # The outcome of a credentials lookup: one token secret paired with the
    # finite set of consumer secret versions that may verify a request.
    #
    # The token secret lives at a different identity layer (the token) than
    # the consumer secret (the application), so it is resolved exactly once
    # and never combined as a cartesian product with consumer candidates.
    class Credentials
      # @return [String, nil] the single token secret for the request's token
      attr_reader :token_secret
      # @return [Array<SecretCandidate>] candidate consumer secret versions
      attr_reader :consumer_candidates

      # @param consumer_candidates [SecretCandidate, Array<SecretCandidate>]
      # @param token_secret [String, nil]
      def initialize(consumer_candidates, token_secret = nil)
        @consumer_candidates = Array(consumer_candidates).dup.freeze
        @token_secret = token_secret
        freeze
      end

      # Candidates that are neither revoked nor outside their validity window.
      #
      # @param now [Time] the server's current time
      # @return [Array<SecretCandidate>]
      def active_candidates(now)
        consumer_candidates.reject { |candidate| candidate.revoked? || !candidate.valid_at?(now) }
      end
    end
  end
end
