# frozen_string_literal: true

require "oauth/request_proxy"
require "oauth/signature/policy"

module OAuth
  module Signature
    # Strict, policy-driven signature verification.
    #
    # A Verifier binds one {OAuth::Signature::Policy} to the verification of a
    # request. Unlike the global {OAuth::Signature.verify} helper, which
    # accepts any registered method, a Verifier only succeeds for the small
    # set of methods its policy allows.
    #
    # Order of operations matters:
    #
    # 1. The declared method is checked against the policy. If it is missing,
    #    duplicated, forbidden, or unimplemented, verification fails *before*
    #    the credential resolver block is invoked.
    # 2. The credential resolver is called exactly once for an allowed method.
    # 3. The resolved credential is checked for compatibility with the method
    #    (an HMAC secret is never treated as an RSA key).
    # 4. The method's own plugin verifies the signature.
    #
    # Any failure raises and is never retried with a different method, so a
    # plugin that raises cannot cause a silent fallback to another algorithm.
    class Verifier
      # @return [OAuth::Signature::Policy]
      attr_reader :policy

      # @param policy [OAuth::Signature::Policy] the method allow list
      def initialize(policy)
        raise TypeError, "Expected an OAuth::Signature::Policy" unless policy.is_a?(Policy)

        @policy = policy
      end

      # Build a verifier from an inline allow list.
      def self.new_with_methods(*allowed_methods)
        new(Policy.new(*allowed_methods))
      end

      # Strictly verify +request+.
      #
      # @param request the request (or request proxy) to verify
      # @param options [Hash] options passed through to the signature plugin
      # @yield credential resolver, see {OAuth::Signature::Base#initialize}
      # @return [Boolean] true when the signature is valid
      # @raise [SignaturePolicyError] for any policy violation
      def verify(request, options = {}, &block)
        signature = build(request, options, &block)
        signature.verify
      end

      # Construct the policy-checked signature object without comparing the
      # signature yet. The credential resolver is only called once the method
      # has passed the policy.
      def build(request, options = {}, &block)
        proxy = OAuth::RequestProxy.proxy(request, options)

        # Fails fast on forbidden/ambiguous methods; the resolver (block) and
        # any pre-resolved credentials are not consulted yet.
        plugin = policy.plugin_for!(proxy)

        secrets = resolve_secrets(proxy, block)
        options = apply_secrets(options, secrets)

        credential = options[:consumer_secret]
        credential = options[:consumer].secret if credential.nil? && options[:consumer]
        policy.validate_credential!(plugin, credential)

        # Delegate entirely to the single allowed plugin. Any error it raises
        # propagates; there is no retry against another method.
        plugin.new(proxy, options)
      end

      private

      # Run the caller's credential resolver, mirroring Base#initialize's
      # block contract, but only after the method was authorized.
      def resolve_secrets(proxy, block)
        return nil unless block

        args = block.arity == 1 ? proxy : [proxy.token, proxy.consumer_key, proxy.nonce, proxy.timestamp]
        block.call(args)
      end

      # Fold resolver output back into options without mutating the caller's
      # hash. Mirrors Base#initialize: only a two-element array carries secrets.
      def apply_secrets(options, secrets)
        return options unless secrets.is_a?(Array) && secrets.size == 2

        options = options.dup
        options[:token_secret] = secrets[0]
        options[:consumer_secret] = secrets[1]
        options
      end
    end
  end
end
