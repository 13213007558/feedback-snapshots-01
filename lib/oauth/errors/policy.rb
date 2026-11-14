# frozen_string_literal: true

require "oauth/errors/error"

module OAuth
  # Base class for all signature method policy violations raised while
  # verifying a request. These are distinct from +OAuth::UnknownSignatureMethod+
  # so callers can tell an unauthorized method apart from a missing plugin.
  class SignaturePolicyError < OAuth::Error
  end

  # The request did not declare exactly one +oauth_signature_method+.
  class AmbiguousSignatureMethod < SignaturePolicyError
    def initialize(method_or_methods)
      super("Request must provide exactly one oauth_signature_method, got: " \
            "#{Array(method_or_methods).inspect}")
    end
  end

  # The declared method is not in the verifier's allow list, or no plugin is
  # registered for it. The credential resolver is never invoked in this case.
  class UnauthorizedSignatureMethod < SignaturePolicyError
    attr_reader :method, :allowed_methods

    def initialize(method, allowed_methods)
      @method = method
      @allowed_methods = allowed_methods
      super("Signature method #{method.inspect} is not permitted by this " \
            "verifier. Allowed methods: #{Array(allowed_methods).inspect}")
    end
  end

  # The resolved credential is not usable with the declared method, e.g. an
  # HMAC secret presented where an RSA key is expected.
  class IncompatibleCredential < SignaturePolicyError
    def initialize(method, key_type)
      super("Resolved credential of type #{key_type.inspect} is not " \
            "compatible with signature method #{method.inspect}")
    end
  end
end
