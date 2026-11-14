# frozen_string_literal: true

module OAuth
  module Signature
    # Base class for errors raised while verifying a request signature.
    class Error < OAuth::Error
    end

    # A signature could not be verified against any admissible secret version.
    #
    # The message is deliberately generic: it never reveals which part of the
    # signing key (consumer secret versus token secret), or which secret
    # version, may have been guessed correctly.
    class VerificationError < Error
      DEFAULT_MESSAGE = "OAuth signature verification failed"

      def initialize(message = DEFAULT_MESSAGE)
        super
      end
    end

    # More than one currently valid secret version produces a signature that
    # matches the request, so the winning version is ambiguous and the request
    # must be rejected rather than guessed at.
    class AmbiguousSignatureError < Error
      DEFAULT_MESSAGE = "OAuth signature matched multiple secret versions"

      attr_reader :versions

      def initialize(versions, message = DEFAULT_MESSAGE)
        @versions = versions
        super("#{message}: #{versions.map(&:inspect).join(", ")}")
      end
    end

    # The request selected a signature method the server has not allowed.
    # The server, not message parameters, decides which algorithms are legal.
    class SignatureMethodRejected < Error
      def initialize(signature_method)
        super("OAuth signature method not allowed: #{signature_method.inspect}")
      end
    end
  end
end
