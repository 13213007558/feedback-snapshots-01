# frozen_string_literal: true

require "digest"
require "openssl"

module Doorkeeper
  module OpenidConnect
    # Computes OpenID Connect subject identifiers and pins the policy a grant
    # or access token was issued under.
    #
    # Two subject identifier types are supported (OIDC Core 1.0 §8):
    #
    # - `public` — every client sees the same value for one end user, namely
    #   what the configured `subject` block returns. This is the historical
    #   behaviour and remains the default.
    # - `pairwise` — each partner sees a different, uncorrelatable value for the
    #   same end user. The value is an HMAC, keyed by `pairwise_subject_salt`,
    #   over the local subject and the partner's sector identifier.
    #
    # The policy in force when an authorization is issued is recorded on the
    # access grant and carried onto every access token it mints (including
    # refresh tokens). The `sub` claim in an ID Token and the `sub` returned by
    # UserInfo are then derived from that recorded policy, not from whatever the
    # client is configured for at read time. Consequently:
    #
    # - a partner's ID Token and UserInfo always identify the same person;
    # - refreshing an existing authorization never hands one partner the
    #   identifier minted for another, even after the deployment migrates;
    # - an authorization whose recorded policy no longer matches its client is
    #   rejected with an explicit re-authorization requirement instead of being
    #   silently reinterpreted.
    #
    # Records written before the binding columns existed carry no policy. They
    # keep working while the client remains `public` (the identifier is
    # unchanged) but can never be reused for a `pairwise` client.
    module SubjectIdentifier
      PUBLIC = "public"
      PAIRWISE = "pairwise"

      # Names of the columns the binding migration adds. `oidc_subject` holds
      # the literal identifier the record must present; the other three describe
      # the policy that produced it and let a later request detect a change
      # without re-deriving (or being able to re-derive) the identifier.
      SUBJECT_COLUMN = "oidc_subject"
      TYPE_COLUMN = "oidc_subject_type"
      SECTOR_COLUMN = "oidc_subject_sector"
      FINGERPRINT_COLUMN = "oidc_subject_fingerprint"
      BINDING_COLUMNS = [
        SUBJECT_COLUMN,
        TYPE_COLUMN,
        SECTOR_COLUMN,
        FINGERPRINT_COLUMN,
      ].freeze

      # One immutable subject policy: the type, the sector/fingerprint that
      # scope a pairwise identifier, and the concrete identifier a record must
      # present. `fingerprint` identifies the policy itself, so two bindings
      # with the same fingerprint are interchangeable even though the end user
      # (and therefore `subject`) differs.
      Binding = Struct.new(:subject_type, :sector, :fingerprint, :subject, keyword_init: true) do
        def public?
          subject_type == PUBLIC
        end

        def pairwise?
          subject_type == PAIRWISE
        end
      end

      class << self
        # The subject a record must present, resolved in issuance order:
        #
        # 1. the identifier pinned on the access token (set at grant issuance
        #    and copied through refresh), when the binding columns exist;
        # 2. otherwise the value derived from the client's *current* policy.
        #
        # Path 2 keeps installations that have not run the migration on the
        # historical behaviour, and covers flows that never persist a grant
        # (e.g. the resource-owner password grant) on those installations.
        def identifier_for(resource_owner, application, record: nil)
          stored = read(record)
          return stored.subject if stored

          binding_for(application, resource_owner).subject
        end

        # The policy in force for one client/end-user right now. Raises
        # InvalidConfiguration for an unknown type, a type that is not
        # advertised, or a pairwise policy missing its salt or binding columns.
        def binding_for(application, resource_owner)
          type = resolved_type(application)
          local_subject = local_subject_for(resource_owner, application)

          if type == PAIRWISE
            assert_binding_columns!
            salt = pairwise_salt
            sector = sector_for(application)
            fingerprint = fingerprint_for(PAIRWISE, sector, salt)
            subject = pairwise_subject(local_subject, sector, salt)
          else
            sector = nil
            fingerprint = fingerprint_for(PUBLIC, client_fingerprint_for(application), nil)
            subject = local_subject
          end

          Binding.new(
            subject_type: type,
            sector: sector,
            fingerprint: fingerprint,
            subject: subject,
          )
        end

        # Reconstructs the policy a stored record was issued under from its
        # binding columns, or nil when the record has none.
        def read(record)
          return if record.nil? || !stores_binding?(record)

          subject = record.read_attribute(SUBJECT_COLUMN)
          return if subject.blank?

          Binding.new(
            subject_type: record.read_attribute(TYPE_COLUMN) || PUBLIC,
            sector: record.read_attribute(SECTOR_COLUMN),
            fingerprint: record.read_attribute(FINGERPRINT_COLUMN),
            subject: subject.to_s,
          )
        end

        # Pins a freshly computed binding onto a persisted grant or access
        # token. A no-op when the installation has not run the binding
        # migration, so upgrading the gem before migrating preserves the
        # previous behaviour.
        def stamp(record, binding)
          return record unless record && binding
          return record unless record.respond_to?(:persisted?) && record.persisted?
          return record unless stores_binding?(record)

          record.update_columns(
            SUBJECT_COLUMN => binding.subject,
            TYPE_COLUMN => binding.subject_type,
            SECTOR_COLUMN => binding.sector,
            FINGERPRINT_COLUMN => binding.fingerprint,
          )
          record
        end

        # Copies the binding from the record an exchange consumes (`source`) to
        # the access token it creates (`record`). A source without a binding —
        # issued before the migration — is left untouched; `problem_for` has
        # already limited that case to a `public` client, whose current policy
        # yields the same identifier.
        def inherit(record, source)
          return record if record.nil?

          stored = read(source)
          return record if stored.nil?

          stamp(record, stored)
        end

        # Raises ReauthorizationRequired when `record` may no longer be used
        # with the client that authenticated the request. `application` is that
        # authenticated client, not whatever the record happens to reference.
        def enforce!(record, application, resource_owner = nil)
          problem = problem_for(record, application, resource_owner)
          raise Errors::ReauthorizationRequired if problem

          true
        end

        # Returns nil when the record may be used, or
        # `:reauthorization_required` when it must not. A record without a
        # binding is acceptable only for a `public` client: a pairwise client
        # can never safely reuse an identifier that was minted (and possibly
        # shared) under the old public policy.
        def problem_for(record, application, resource_owner = nil)
          stored = read(record)
          current = binding_for(application, resource_owner_for(record, resource_owner))

          if stored.nil?
            current.public? ? nil : :reauthorization_required
          elsif stored.fingerprint == current.fingerprint
            nil
          else
            :reauthorization_required
          end
        end

        def stores_binding?(record)
          return false unless record.respond_to?(:class)

          BINDING_COLUMNS.all? { |column| record.class.column_names.include?(column) }
        rescue StandardError
          false
        end

        private

        def resource_owner_for(record, fallback)
          return fallback if fallback

          return unless record.respond_to?(:resource_owner_id)

          configuration.resource_owner_from_access_token.call(record)
        rescue StandardError
          nil
        end

        def local_subject_for(resource_owner, application)
          configuration.subject.call(resource_owner, application).to_s
        end

        def pairwise_subject(local_subject, sector, salt)
          ::OpenSSL::HMAC.hexdigest(
            "SHA256",
            salt,
            ["pairwise-v1", sector, local_subject].join("\0"),
          )
        end

        # A stable digest of the policy inputs. The salt is part of the digest
        # for pairwise bindings, so rotating it invalidates existing records;
        # the client fingerprint is part of public bindings, so transferring a
        # registration to another owner is detected even though `sub` is the
        # same for every public client.
        def fingerprint_for(type, discriminator, salt)
          ::Digest::SHA256.hexdigest(
            ["oidc-subject-v1", type, discriminator, salt].map(&:to_s).join("\0"),
          )
        end

        def resolved_type(application)
          value = setting_value(configuration.subject_type, application)
          type = value.to_s
          type = PUBLIC if type == ""

          unless [PUBLIC, PAIRWISE].include?(type)
            raise Errors::InvalidConfiguration,
                  I18n.t(
                    "doorkeeper.openid_connect.errors.messages.subject_type_invalid",
                    subject_type: value.inspect,
                  )
          end

          advertised = Array(configuration.subject_types_supported).map(&:to_s)
          unless advertised.include?(type)
            raise Errors::InvalidConfiguration,
                  I18n.t(
                    "doorkeeper.openid_connect.errors.messages.subject_type_not_advertised",
                    subject_type: type,
                    supported: advertised.join(", "),
                  )
          end

          type
        end

        # Defaults to the partner identity behind the registration, so distinct
        # clients always get distinct sectors even when they share a redirect
        # host. A configured `pairwise_sector_identifier` lets one partner group
        # several registrations under a single sector (OIDC Core §8.1).
        def sector_for(application)
          override = configuration.pairwise_sector_identifier
          unless override.nil?
            value = setting_value(override, application)
            return value.to_s if value.present?
          end

          client_fingerprint_for(application)
        end

        def client_fingerprint_for(application)
          override = configuration.subject_client_fingerprint
          return setting_value(override, application).to_s unless override.nil?
          return "" if application.nil?

          [application.uid, application.try(:owner_type), application.try(:owner_id)]
            .compact
            .join(":")
        end

        def pairwise_salt
          value = configuration.pairwise_subject_salt
          value = value.call if value.respond_to?(:call)
          if value.blank?
            message_key = "pairwise_subject_salt_not_configured"
            raise Errors::InvalidConfiguration, I18n.t(i18n_message(message_key))
          end

          value.to_s
        end

        def assert_binding_columns!
          models = [
            Doorkeeper.config.access_grant_model,
            Doorkeeper.config.access_token_model,
          ]
          migrated = models.all? do |model|
            BINDING_COLUMNS.all? { |column| model.column_names.include?(column) }
          end
          return if migrated

          message_key = "subject_binding_migration_missing"
          raise Errors::InvalidConfiguration, I18n.t(i18n_message(message_key))
        end

        def i18n_message(key)
          "doorkeeper.openid_connect.errors.messages.#{key}"
        end

        def setting_value(setting, application)
          return setting unless setting.respond_to?(:call)

          setting.arity.zero? ? setting.call : setting.call(application)
        end

        def configuration
          Doorkeeper::OpenidConnect.configuration
        end
      end
    end
  end
end
