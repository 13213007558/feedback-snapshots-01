# frozen_string_literal: true

require "oauth/signature"
require "oauth/signature/errors"
require "oauth/signature/clock"
require "oauth/signature/secret_candidate"
require "oauth/signature/audit_event"
require "oauth/helper"
require "oauth/request_proxy/base"
require "base64"

module OAuth
  module Signature
    class Base
      include OAuth::Helper

      attr_accessor :options
      attr_reader :token_secret, :consumer_secret, :request,
                  :credentials, :matched_consumer_version, :last_audit_event

      def self.implements(signature_method = nil)
        return @implements if signature_method.nil?

        @implements = signature_method
        OAuth::Signature.available_methods[@implements] = self
      end

      def initialize(request, options = {}, &block)
        raise TypeError unless request.is_a?(OAuth::RequestProxy::Base)

        @request = request
        @options = options
        @clock = options[:clock] || Clock.new
        @audit = options[:audit]
        @matched_consumer_version = nil
        @last_audit_event = nil

        ## consumer secret was determined beforehand

        @static_consumer_secret = options[:consumer].secret if options[:consumer]

        # presence of :consumer_secret option will override any Consumer that's provided
        @static_consumer_secret = options[:consumer_secret] if options[:consumer_secret]

        ## token secret was determined beforehand

        @static_token_secret = options[:token].secret if options[:token]

        # presence of :token_secret option will override any Token that's provided
        @static_token_secret = options[:token_secret] if options[:token_secret]

        @consumer_secret = @static_consumer_secret
        @token_secret = @static_token_secret

        @credentials = resolve_credentials(block)
      end

      def signature
        Base64.encode64(digest).chomp.delete("\n")
      end

      def ==(other)
        check = signature.bytesize ^ other.bytesize
        signature.bytes.zip(other.bytes) { |x, y| check |= x ^ y.to_i }
        check.zero?
      end

      # Verify the request signature.
      #
      # Backwards-compatible boolean interface: returns +true+ on a unique
      # match and +false+ for every failure, without revealing which part of
      # the signing key was correct. The audit callback still fires.
      def verify
        verify!
        true
      rescue OAuth::Signature::Error
        false
      end

      # Verify the request signature, raising structured errors on failure.
      #
      # @raise [SignatureMethodRejected] the message selected a disallowed algorithm
      # @raise [AmbiguousSignatureError] several valid versions matched at once
      # @raise [VerificationError] no admissible version matched
      # @return [Boolean] +true+ when exactly one version matches
      def verify!
        enforce_signature_method!

        now = clock_now
        active = credentials.active_candidates(now)
        considered = active.map(&:version)

        matches = find_matching_candidates(active)

        case matches.size
        when 1
          winner = matches.first
          @matched_consumer_version = winner.version
          audit(:success, considered, winner.version)
          true
        when 0
          @matched_consumer_version = nil
          audit(:failure, considered, nil, error: :no_match)
          raise VerificationError
        else
          @matched_consumer_version = nil
          versions = matches.map(&:version)
          audit(:failure, considered, nil, error: :ambiguous)
          raise AmbiguousSignatureError.new(versions)
        end
      ensure
        @consumer_secret = @static_consumer_secret
        @token_secret = @static_token_secret
      end

      def signature_base_string
        request.signature_base_string
      end

      def body_hash
        raise_instantiation_error
      end

      private

      def token
        request.token
      end

      def consumer_key
        request.consumer_key
      end

      def nonce
        request.nonce
      end

      def clock_now
        @clock.respond_to?(:now) ? @clock.now : Time.now
      end

      # The token secret is resolved once and held fixed while each consumer
      # secret version is tried: the two secrets live at different identity
      # layers, so they must never be combined as a cartesian product.
      def find_matching_candidates(candidates)
        candidates.select do |candidate|
          @consumer_secret = candidate.secret
          @token_secret = credentials.token_secret
          self == request.signature
        end
      end

      def enforce_signature_method!
        allowed = options[:allowed_signature_methods]
        return if allowed.nil?

        permitted = Array(allowed).map { |method| method.to_s.downcase }
        requested = request.signature_method.to_s.downcase
        return if permitted.include?(requested)

        audit(:failure, credentials.consumer_candidates.map(&:version), nil,
              error: :signature_method_rejected)
        raise SignatureMethodRejected.new(request.signature_method)
      end

      def resolve_credentials(block)
        return static_credentials unless block.is_a?(Proc)

        # consumer secret and token secret need to be looked up based on pieces of the request
        result = block.call(block.arity == 1 ? request : [token, consumer_key, nonce, request.timestamp])

        case result
        when Credentials
          apply_credentials(result)
        when Array
          # legacy resolver contract: [token_secret, consumer_secret]
          if result.size == 2
            @static_token_secret = result[0]
            @static_consumer_secret = result[1]
            Credentials.new([SecretCandidate.new(version: nil, secret: result[1])], result[0])
          else
            static_credentials
          end
        else
          static_credentials
        end
      end

      def apply_credentials(resolved)
        @static_token_secret = resolved.token_secret
        @token_secret = resolved.token_secret
        resolved
      end

      def static_credentials
        candidates = if @static_consumer_secret.nil?
                       []
                     else
                       [SecretCandidate.new(version: nil, secret: @static_consumer_secret)]
                     end
        Credentials.new(candidates, @static_token_secret)
      end

      def audit(result, considered, version, error: nil)
        return unless @audit.respond_to?(:call)

        @last_audit_event = AuditEvent.new(
          result: result,
          consumer_key: consumer_key,
          token: token,
          signature_method: request.signature_method,
          considered_versions: considered,
          consumer_version: version,
          error: error
        )
        @audit.call(@last_audit_event)
      end

      def secret
        "#{escape(consumer_secret)}&#{escape(token_secret)}"
      end

      def digest
        raise_instantiation_error
      end

      def raise_instantiation_error
        raise NotImplementedError, "Cannot instantiate #{self.class.name} class directly."
      end
    end
  end
end
