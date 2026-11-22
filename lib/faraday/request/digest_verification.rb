# frozen_string_literal: true

require 'digest'

module Faraday
  class Request
    # Request middleware that confirms the body actually about to be sent
    # corresponds to a previously approved version of it.
    #
    # Place this last among the request middleware, directly before the adapter,
    # so it runs after every middleware that encodes or replaces the request
    # body (such as {Faraday::Request::Json} and
    # {Faraday::Request::UrlEncoded}). It computes the digest of the *final*
    # body and compares it against the approved digest, aborting the request
    # before the adapter is reached when the two do not correspond.
    #
    # == What can be verified
    #
    # - Small, in-memory bodies that respond to +#to_str+ are digested
    #   directly.
    # - Ordinary streaming uploads whose body responds to +#read+ are read in
    #   chunks and digested. When the body also responds to +#rewind+ it is
    #   rewound afterwards so the adapter can still send it.
    # - A stream that cannot be rewound cannot be verified without consuming
    #   the bytes the adapter needs, so it raises
    #   {Faraday::UnverifiableBodyError}. Bodies that are neither strings nor
    #   readable streams are likewise unverifiable.
    #
    # == Options
    #
    # +:approved_digest+ may be a String digest or any object responding to
    # +#call(env)+ that returns one (or +nil+). Returning +nil+ means the
    # request has no approved digest, so verification is skipped and the
    # middleware stays a transparent pass-through.
    #
    # @example Verifying JSON-encoded uploads
    #   approved = Digest::SHA256.hexdigest('{"name":"YK"}')
    #
    #   conn = Faraday.new do |builder|
    #     builder.request :json
    #     builder.request :digest_verification, approved_digest: approved
    #     builder.adapter :test do |stub|
    #       stub.post('/uploads') { [200, {}, ''] }
    #     end
    #   end
    #
    #   conn.post('/uploads', { name: 'YK' }, 'Content-Type' => 'application/json')
    class DigestVerification < Faraday::Middleware
      DEFAULT_OPTIONS = {
        approved_digest: nil,
        algorithm: Digest::SHA256
      }.freeze

      READ_CHUNK_SIZE = 16 * 1024

      # @param app [#call] the next middleware or adapter in the stack.
      # @param options [Hash] middleware options.
      # @option options [String, #call, nil] :approved_digest the digest the
      #   final body must match, or a callable returning it. +nil+ disables
      #   verification.
      # @option options [Class, #new] :algorithm (Digest::SHA256) a Digest
      #   class/instance responding to +#new+ and +#digest+, used to hash the
      #   final body.
      def initialize(app, options = {})
        super
        @approved_digest = @options[:approved_digest]
        @algorithm = @options[:algorithm]
      end

      # Verifies the final request body before handing the request to the
      # adapter.
      #
      # @param env [Faraday::Env] the request environment.
      #
      # @raise [Faraday::DigestMismatchError] if the body digest differs from
      #   the approved digest.
      # @raise [Faraday::UnverifiableBodyError] if an approved digest exists
      #   but the body cannot be digested reliably.
      # @return [Faraday::Response] the response from the rest of the stack.
      def call(env)
        verify!(env)
        app.call(env)
      end

      private

      def verify!(env)
        approved = resolve_approved_digest(env)
        return if approved.nil? || approved.to_s.empty?

        digest = digest_body(env.body)
        return if matching_digest?(digest, approved.to_s)

        raise Faraday::DigestMismatchError, mismatch_message(env)
      end

      def resolve_approved_digest(env)
        if @approved_digest.respond_to?(:call)
          @approved_digest.call(env)
        else
          @approved_digest
        end
      end

      # @return [#hexdigest, #digest] a digest instance already fed the body.
      def digest_body(body)
        digest = @algorithm.new
        case body
        when nil
          raise Faraday::UnverifiableBodyError,
                'cannot verify a request without a body against an approved digest'
        when ->(value) { value.respond_to?(:to_str) }
          digest.update(body.to_str)
        when ->(value) { value.respond_to?(:read) }
          digest_stream(body, digest)
        else
          raise Faraday::UnverifiableBodyError,
                "request body of type #{body.class} cannot be digested for verification"
        end
        digest
      end

      def digest_stream(stream, digest)
        unless stream.respond_to?(:rewind)
          raise Faraday::UnverifiableBodyError,
                "stream of type #{stream.class} is not rewindable, so its body " \
                'cannot be verified without consuming it before sending'
        end

        stream.rewind
        while (chunk = stream.read(READ_CHUNK_SIZE))
          break if chunk.empty?

          digest.update(chunk)
        end
        stream.rewind
      end

      # The approved digest may be provided as a hex string (case and
      # surrounding whitespace insensitive) or as the raw binary digest.
      def matching_digest?(digest, approved)
        candidate = approved.strip
        candidate = candidate.downcase if candidate.ascii_only?

        secure_compare(digest.hexdigest, candidate) ||
          secure_compare(digest.digest, approved)
      end

      # Constant-time comparison that avoids leaking the digest through timing.
      def secure_compare(left, right)
        return false unless left.bytesize == right.bytesize

        left_bytes = left.bytes
        right_bytes = right.bytes
        result = 0
        left_bytes.each_with_index { |byte, index| result |= byte ^ right_bytes[index] }
        result.zero?
      end

      def mismatch_message(env)
        method = env[:method] ? env[:method].to_s.upcase : 'UNKNOWN'
        url = env[:url] || 'unknown URL'
        "digest of the final request body for #{method} #{url} does not match " \
          'the approved digest; the request was blocked before being sent'
      end
    end
  end
end

Faraday::Request.register_middleware(
  digest_verification: Faraday::Request::DigestVerification
)
