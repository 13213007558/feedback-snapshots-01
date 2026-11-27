# frozen_string_literal: true

module Doorkeeper
  module OpenidConnect
    class UserInfo
      include ActiveModel::Validations

      def initialize(access_token)
        @access_token = access_token
      end

      def claims
        # NOTE: `sub` is merged last so a custom claim block cannot override
        # the canonical subject identifier (which would defeat pairwise /
        # subject-type guarantees). `resource_owner` is passed through so the
        # access token's owner is resolved once for both the custom claims and
        # `sub`, instead of twice.
        ClaimsBuilder.generate(@access_token, :user_info, resource_owner).merge(
          sub: subject,
        )
      end

      def as_json(*_)
        claims.reject { |_, value| value.nil? || value == "" }
      end

      # Public so callers (e.g. the userinfo endpoint) can check whether the
      # token still resolves to an end user before generating claims; the
      # memoization keeps that check and the claim generation to one lookup.
      def resource_owner
        @resource_owner ||= Doorkeeper::OpenidConnect.configuration.resource_owner_from_access_token.call(@access_token)
      end

      private

      def subject
        # Same resolution as `IdToken#subject`, from the binding pinned on the
        # same access token, so one partner sees one identifier in both the ID
        # Token and the UserInfo response. The token endpoint already rejects a
        # record whose binding no longer matches its client before a refreshed
        # token carrying a stale policy can reach this endpoint.
        SubjectIdentifier.identifier_for(
          resource_owner,
          application,
          record: @access_token,
        )
      end

      def application
        @application ||= @access_token.application
      end
    end
  end
end
