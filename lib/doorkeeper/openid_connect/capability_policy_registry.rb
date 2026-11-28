# frozen_string_literal: true

module Doorkeeper
  module OpenidConnect
    # Holds the capability policy of each registration space.
    #
    # A space is identified by the route helper prefix its mount declares
    # (`use_doorkeeper_openid_connect as: :admins` sets `admins_`); the default
    # mount's prefix is the empty string. The prefix is a route default on the
    # discovery and registration endpoints, and is derived from the request
    # path on the OAuth endpoints (`/admins/oauth/token` -> `admins_`), so a
    # request is always evaluated against the policy of the mount that
    # received it rather than whichever mount happened to be configured last.
    class CapabilityPolicyRegistry
      DEFAULT_PREFIX = ""

      def initialize
        @policies = {}
      end

      # Registers one space's policy. Re-running `configure` replaces the
      # policies it declares, but policies for spaces it does not mention stay
      # in place: an unrelated mount is not silently widened or removed when
      # an initializer is reloaded.
      def register(policy)
        @policies[policy.prefix] = policy
      end

      def register_all(policies)
        Array(policies).each { |policy| register(policy) }
      end

      def [](prefix)
        @policies[CapabilityPolicy.prefix_for(prefix)]
      end

      def keys
        @policies.keys
      end

      # The default space always has a policy, even when the host application
      # never declared one: absence means "inherit every global setting". This
      # keeps single-mount installations and every code path that asks for
      # "the current space" total, with no nil checks scattered around.
      def default_policy
        self[DEFAULT_PREFIX] || CapabilityPolicy.new(name: DEFAULT_PREFIX)
      end

      # Resolves the space a request belongs to from its path, falling back to
      # the default space for requests outside a known namespace (single-mount
      # installations, Doorkeeper's own RFC 8414 endpoint, ...).
      def for_request(request)
        prefix = request.path_parameters[:route_helper_prefix].presence
        prefix ||= prefix_for_path(request.path.to_s)
        self[prefix] || default_policy
      end

      # The route helper prefix for a raw namespace name or an already
      # prefixed value: nil -> "", :admins -> "admins_".
      def self.prefix_for(name)
        CapabilityPolicy.prefix_for(name)
      end

      private

      def prefix_for_path(path)
        @policies.keys.reject(&:empty?).each do |prefix|
          namespace = prefix.chomp("_")
          return prefix if path.start_with?("/#{namespace}/")
        end

        DEFAULT_PREFIX
      end
    end
  end
end
