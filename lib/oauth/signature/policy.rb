# frozen_string_literal: true

require "oauth/errors/policy"

module OAuth
  module Signature
    # A verifier-level allow list of signature methods.
    #
    # The global {OAuth::Signature.available_methods} registry grows every time
    # a signature extension is loaded. A service that simply asks "is this
    # method registered?" therefore silently widens the set of methods it
    # accepts whenever a new plugin ships. A +Policy+ inverts that default:
    # only the exact methods explicitly allowed here are accepted, regardless
    # of how many plugins are registered globally.
    #
    # Method names are matched exactly after the same normalization the
    # registry uses (lower case). +PLAINTEXT+ is never accepted unless it is
    # explicitly included, so it stays opt-in for legacy compatibility only.
    class Policy
      # @return [Array<String>] normalized, allowed method names
      attr_reader :allowed_methods

      # @param allowed_methods [Array<String>] exact method names to accept,
      #   e.g. <code>%w[hmac-sha1 rsa-sha1]</code>
      # @param registry [Hash] method name => signature class plugin map;
      #   defaults to the global registry but can be injected for testing
      def initialize(*allowed_methods, registry: OAuth::Signature.available_methods)
        methods = allowed_methods.flatten.map { |name| normalize(name) }
        raise ArgumentError, "A signature policy must allow at least one method" if methods.empty?
        if methods.size != methods.uniq.size
          raise ArgumentError, "Duplicate methods in signature policy: #{methods.inspect}"
        end

        @allowed_methods = methods.freeze
        @registry = registry
      end

      # Whether +method+ is on this policy's allow list. This deliberately
      # ignores the registry: a method must be explicitly allowed, not merely
      # installed.
      def allows?(method)
        allowed_methods.include?(normalize(method))
      end

      # Validate the signature method declared by +request+ and resolve the
      # plugin that implements it. Raises a policy error without ever touching
      # the caller's credential resolver.
      #
      # @return [Class] the signature implementation class
      # @raise [AmbiguousSignatureMethod] if the request does not carry
      #   exactly one +oauth_signature_method+
      # @raise [UnauthorizedSignatureMethod] if the method is missing, not
      #   allowed, or has no registered implementation
      def plugin_for!(request)
        declared = request.oauth_signature_methods
        if declared.empty? || declared.any?(&:empty?)
          raise AmbiguousSignatureMethod, declared
        end
        if declared.uniq.size != 1
          raise AmbiguousSignatureMethod, declared
        end

        method = normalize(declared.first)
        unless allows?(method)
          raise UnauthorizedSignatureMethod.new(method, allowed_methods)
        end

        plugin = registry[method]
        unless plugin
          # The method was explicitly allowed but no extension implements it.
          # Do not fall through to another method.
          raise UnauthorizedSignatureMethod.new(method, allowed_methods)
        end

        plugin
      end

      # Confirm a resolved +consumer_secret+ is usable with +plugin+. This
      # prevents an HMAC shared secret from being interpreted as an RSA key
      # (or vice versa).
      #
      # @raise [IncompatibleCredential] if the credential is the wrong family
      def validate_credential!(plugin, consumer_secret)
        return if plugin.compatible_credential?(consumer_secret)

        raise IncompatibleCredential.new(plugin.implements, plugin.key_type)
      end

      private

      attr_reader :registry

      def normalize(name)
        name.to_s.downcase
      end
    end
  end
end
