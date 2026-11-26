"""End-to-end coverage for an approved backend (provider) rename.

The in-memory test storage stands in for the real persistence layer. Two local
OAuth2 providers return the same email address and display name, which lets the
tests prove that ownership is established from the stable provider-scoped
identifier rather than those mutable claims.
"""

from __future__ import annotations

from typing import Any

import unittest
from unittest.mock import patch

from social_core.backends.oauth import BaseOAuth2
from social_core.exceptions import (
    AuthAssociationError,
    AuthConfigurationError,
)
from social_core.pipeline.partial import partial
from social_core.renaming import (
    ALREADY_RENAMED,
    RENAMED,
    TARGET_CONFLICT,
    _migrate_one,
    approved_backend_renames,
    get_renamed_social_auth,
    legacy_provider_names,
    migrate_backend_renames,
    pending_rename_providers,
    resolve_backend_name,
)
from social_core.utils import (
    PARTIAL_TOKEN_SESSION_NAME,
    _partial_pipeline_matches_request,
)

from .models import TestPartial, TestStorage, TestUserSocialAuth, User
from .strategy import TestStrategy

OLD_NAME = "enterprise-idp"
NEW_NAME = "enterprise-sso"
OTHER_NAME = "partner-idp"
EMAIL = "employee@example.com"
FULLNAME = "Sam Employee"

PAUSE_PIPELINE = (
    "social_core.pipeline.social_auth.social_details",
    "social_core.pipeline.social_auth.social_names",
    "social_core.pipeline.social_auth.social_uid",
    "social_core.pipeline.social_auth.auth_allowed",
    "social_core.tests.test_backend_rename.pause_for_confirmation",
    "social_core.pipeline.social_auth.social_user",
    "social_core.pipeline.user.get_username",
    "social_core.pipeline.user.create_user",
    "social_core.pipeline.social_auth.associate_user",
    "social_core.pipeline.social_auth.load_extra_data",
    "social_core.pipeline.user.user_details",
)

LOGIN_PIPELINE = tuple(
    step for step in PAUSE_PIPELINE if step != f"{__name__}.pause_for_confirmation"
)


@partial
def pause_for_confirmation(strategy, *args, **kwargs):
    if strategy.session_get("confirmation"):
        return {"confirmed": True}
    return strategy.redirect(strategy.build_absolute_uri("/confirm"))


class EnterpriseIdpOAuth2(BaseOAuth2):
    """The backend under its original, pre-rename name."""

    name = OLD_NAME
    AUTHORIZATION_URL = "http://idp.example.com/oauth/authorize"
    ACCESS_TOKEN_URL = "http://idp.example.com/oauth/access_token"

    def get_user_details(self, response: dict[str, Any]) -> dict[str, Any]:
        return {
            "username": response.get("username"),
            "email": response.get("email", ""),
            "fullname": response.get("fullname", ""),
            "first_name": response.get("first_name", ""),
            "last_name": response.get("last_name", ""),
        }


class EnterpriseSsoOAuth2(EnterpriseIdpOAuth2):
    """The same backend after the approved rename is published."""

    name = NEW_NAME


class PartnerIdpOAuth2(EnterpriseIdpOAuth2):
    """A second local provider that reuses the same email and display name."""

    name = OTHER_NAME


PROVIDER_RESPONSE = {
    "id": "stable-account-7",
    "username": "sam",
    "email": EMAIL,
    "fullname": FULLNAME,
    "first_name": "Sam",
    "last_name": "Employee",
}


class BackendRenameTestBase:
    rename_setting = {OLD_NAME: NEW_NAME}

    def setUp(self) -> None:
        User.reset_cache()
        TestUserSocialAuth.reset_cache()
        TestPartial.reset_cache()
        self.strategy = TestStrategy(TestStorage)
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_BACKENDS_RENAME": self.rename_setting,
                "SOCIAL_AUTH_AUTHENTICATION_BACKENDS": (
                    "social_core.tests.test_backend_rename.EnterpriseIdpOAuth2",
                    "social_core.tests.test_backend_rename.EnterpriseSsoOAuth2",
                    "social_core.tests.test_backend_rename.PartnerIdpOAuth2",
                ),
                "SOCIAL_AUTH_PIPELINE": LOGIN_PIPELINE,
            }
        )

    def old_backend(self) -> EnterpriseIdpOAuth2:
        return EnterpriseIdpOAuth2(self.strategy)

    def new_backend(self) -> EnterpriseSsoOAuth2:
        return EnterpriseSsoOAuth2(self.strategy)

    def other_backend(self) -> PartnerIdpOAuth2:
        return PartnerIdpOAuth2(self.strategy)

    def authenticate(self, backend, response=None, user=None):
        return self.strategy.authenticate(
            backend, response=response or dict(PROVIDER_RESPONSE), user=user
        )

    def resume(self, backend):
        token = self.strategy.session_get(PARTIAL_TOKEN_SESSION_NAME)
        partial = self.strategy.partial_load(token)
        assert partial is not None
        return backend.continue_pipeline(partial)

class BackendRenameApprovalTest(BackendRenameTestBase, unittest.TestCase):
    def test_approved_mapping_is_scoped_to_the_published_names(self) -> None:
        backend = self.new_backend()
        self.assertEqual(approved_backend_renames(backend), {OLD_NAME: NEW_NAME})
        self.assertEqual(resolve_backend_name(backend, OLD_NAME), NEW_NAME)
        self.assertEqual(resolve_backend_name(backend, NEW_NAME), NEW_NAME)
        self.assertEqual(legacy_provider_names(backend), (OLD_NAME,))

    def test_unapproved_rename_is_rejected(self) -> None:
        with self.assertRaises(AuthConfigurationError) as caught:
            migrate_backend_renames(
                self.new_backend(), TestStorage, OLD_NAME, OTHER_NAME
            )
        self.assertEqual(caught.exception.code, "invalid_setting")

    def test_invalid_mapping_shapes_are_rejected(self) -> None:
        for invalid in ({"old": ""}, {"old": "old"}, {"a": "b", "b": "c"}, "x"):
            with self.subTest(invalid=invalid):
                strategy = TestStrategy(TestStorage)
                strategy.set_settings({"SOCIAL_AUTH_BACKENDS_RENAME": invalid})
                with self.assertRaises(AuthConfigurationError):
                    approved_backend_renames(EnterpriseSsoOAuth2(strategy))


class BackendRenameMigrationTest(BackendRenameTestBase, unittest.TestCase):
    def test_existing_binding_is_found_by_verified_provider_ownership(self) -> None:
        owner = User("sam", email=EMAIL)
        binding = TestUserSocialAuth(
            owner, OLD_NAME, "stable-account-7", id_key="id"
        )

        social = get_renamed_social_auth(
            self.new_backend(), TestStorage, "stable-account-7", id_key="id"
        )

        self.assertIs(social, binding)
        # The fallback is provider scoped: an unrelated provider cannot hijack it.
        self.assertIsNone(
            get_renamed_social_auth(
                self.other_backend(), TestStorage, "stable-account-7", id_key="id"
            )
        )

    def test_full_rename_then_new_name_lookup_and_repeat_login(self) -> None:
        owner = User("sam", email=EMAIL)
        binding = TestUserSocialAuth(
            owner, OLD_NAME, "stable-account-7", id_key="id"
        )

        report = migrate_backend_renames(
            self.new_backend(), TestStorage, OLD_NAME, NEW_NAME
        )

        self.assertEqual([status.status for status in report.statuses], [RENAMED])
        self.assertTrue(report.complete)
        self.assertEqual(binding.provider, NEW_NAME)
        # The stable account identifier and its key are preserved untouched.
        self.assertEqual((binding.uid, binding.id_key), ("stable-account-7", "id"))
        self.assertEqual(
            pending_rename_providers(self.new_backend(), TestStorage), {}
        )

        # Post-cutover lookups use the published name only.
        self.assertIs(
            get_renamed_social_auth(
                self.new_backend(), TestStorage, "stable-account-7", id_key="id"
            ),
            binding,
        )

        # A repeat login resolves to the same local account, not a new one.
        result = self.authenticate(self.new_backend())
        self.assertIs(result, owner)
        self.assertEqual(len(TestUserSocialAuth.cache_by_uid), 1)
        self.assertEqual(owner.social[0].provider, NEW_NAME)

    def test_idempotent_rerun_reports_already_renamed(self) -> None:
        owner = User("sam", email=EMAIL)
        binding = TestUserSocialAuth(owner, OLD_NAME, "stable-account-7", id_key="id")

        first = migrate_backend_renames(
            self.new_backend(), TestStorage, OLD_NAME, NEW_NAME
        )
        second = migrate_backend_renames(
            self.new_backend(), TestStorage, OLD_NAME, NEW_NAME
        )

        self.assertEqual(first.statuses[0].status, RENAMED)
        self.assertEqual(second.statuses, [])
        self.assertEqual(binding.provider, NEW_NAME)

    def test_row_already_on_new_name_is_reported_without_change(self) -> None:
        owner = User("sam", email=EMAIL)
        binding = TestUserSocialAuth(
            owner, NEW_NAME, "stable-account-7", id_key="id"
        )

        # Drive the per-row path directly: a row already carrying the new name
        # is reported as already renamed and left untouched.
        status = _migrate_one(self.new_backend(), TestStorage, binding, NEW_NAME)
        self.assertEqual(status.status, ALREADY_RENAMED)
        self.assertTrue(status.migrated)
        self.assertEqual(binding.provider, NEW_NAME)

    def test_target_identifier_conflict_blocks_and_remains_recoverable(self) -> None:
        owner = User("sam", email=EMAIL)
        legacy = TestUserSocialAuth(
            owner, OLD_NAME, "stable-account-7", id_key="id"
        )
        # A different local account already owns the new provider's identifier.
        holder = User("holder", email="holder@example.com")
        occupant = TestUserSocialAuth(
            holder, NEW_NAME, "stable-account-7", id_key="id"
        )

        report = migrate_backend_renames(
            self.new_backend(), TestStorage, OLD_NAME, NEW_NAME
        )

        status = report.statuses[0]
        self.assertEqual(status.status, TARGET_CONFLICT)
        self.assertFalse(report.complete)
        self.assertEqual(
            pending_rename_providers(self.new_backend(), TestStorage),
            {OLD_NAME: 1},
        )
        # Nothing was mutated; both rows and the underlying accounts survive.
        self.assertEqual(legacy.provider, OLD_NAME)
        self.assertEqual(occupant.provider, NEW_NAME)
        self.assertEqual(status.conflicts["existing_user_id"], holder.id)

        # Removing the occupant lets a retry finish the migration cleanly.
        TestUserSocialAuth.disconnect(occupant)
        retry = migrate_backend_renames(
            self.new_backend(), TestStorage, OLD_NAME, NEW_NAME
        )
        self.assertEqual([status.status for status in retry.statuses], [RENAMED])
        self.assertEqual(legacy.provider, NEW_NAME)
        self.assertTrue(retry.complete)

    def test_same_username_and_email_are_evidence_not_ownership(self) -> None:
        # A separate local account shares the owner's email and display name.
        local_duplicate = User("sam-duplicate", email=EMAIL)
        local_duplicate.first_name = "Sam"
        owner = User("sam-owner", email=EMAIL)
        binding = TestUserSocialAuth(
            owner, OLD_NAME, "stable-account-7", id_key="id"
        )
        # A second provider returning the same email/display name has its own
        # binding keyed by its own stable identifier.
        TestUserSocialAuth(
            local_duplicate, OTHER_NAME, "partner-account-9", id_key="id"
        )

        report = migrate_backend_renames(
            self.new_backend(), TestStorage, OLD_NAME, NEW_NAME
        )

        self.assertTrue(report.complete)
        self.assertEqual(binding.provider, NEW_NAME)
        self.assertEqual(len(report.evidence), 1)
        evidence = report.evidence[0].evidence
        self.assertEqual(evidence["email"], EMAIL)
        self.assertEqual(evidence["matching_user_ids"], [local_duplicate.id])

    def test_lazy_migration_during_login_recovers_unfinished_storage(self) -> None:
        owner = User("sam", email=EMAIL)
        binding = TestUserSocialAuth(
            owner, OLD_NAME, "stable-account-7", id_key="id"
        )

        # Storage migration was never run: login under the new name still claims
        # the existing binding instead of creating a duplicate account.
        result = self.authenticate(self.new_backend())

        self.assertIs(result, owner)
        self.assertEqual(binding.provider, NEW_NAME)
        self.assertEqual((binding.uid, binding.id_key), ("stable-account-7", "id"))
        self.assertEqual(len(owner.social), 1)

    def test_lazy_migration_conflict_is_surfaced_not_merged(self) -> None:
        owner = User("sam", email=EMAIL)
        legacy = TestUserSocialAuth(
            owner, OLD_NAME, "stable-account-7", id_key="id"
        )
        holder = User("holder", email="holder@example.com")
        occupant = TestUserSocialAuth(
            holder, NEW_NAME, "stable-account-7", id_key="id"
        )

        # The published name already has a verified binding. An anonymous login
        # resolves to that existing account; the unmigrated legacy row is never
        # moved or merged, so both underlying account links stay recoverable.
        result = self.authenticate(self.new_backend())
        self.assertIs(result, holder)
        self.assertEqual(legacy.provider, OLD_NAME)
        self.assertEqual(occupant.provider, NEW_NAME)
        self.assertEqual(len(owner.social), 1)
        self.assertEqual(len(holder.social), 1)

        # The same conflict is reported explicitly by the storage migration.
        report = migrate_backend_renames(
            self.new_backend(), TestStorage, OLD_NAME, NEW_NAME
        )
        self.assertEqual(report.statuses[0].status, TARGET_CONFLICT)
        self.assertEqual(legacy.provider, OLD_NAME)

    def test_authenticated_owner_conflict_is_rejected_without_mutation(self) -> None:
        owner = User("sam", email=EMAIL)
        legacy = TestUserSocialAuth(
            owner, OLD_NAME, "stable-account-7", id_key="id"
        )
        holder = User("holder", email="holder@example.com")
        TestUserSocialAuth(holder, NEW_NAME, "stable-account-7", id_key="id")

        with self.assertRaises(AuthAssociationError) as caught:
            self.authenticate(self.new_backend(), user=owner)
        self.assertEqual(caught.exception.code, "identity_in_use")
        self.assertEqual(legacy.provider, OLD_NAME)

    def test_lazy_rename_write_conflict_raises_and_keeps_legacy_row(self) -> None:
        owner = User("sam", email=EMAIL)
        legacy = TestUserSocialAuth(
            owner, OLD_NAME, "stable-account-7", id_key="id"
        )
        holder = User("holder", email="holder@example.com")

        # No occupant at lookup time, but the storage write collides (a race or
        # a unique constraint enforced by the concrete storage backend).
        def clash(social, new_provider):
            TestUserSocialAuth(holder, new_provider, social.uid, id_key=social.id_key)
            raise ValueError("unique constraint violated")

        with patch.object(
            TestUserSocialAuth, "rename_social_auth_provider", side_effect=clash
        ):
            with self.assertRaises(AuthAssociationError) as caught:
                self.authenticate(self.new_backend())
        self.assertEqual(caught.exception.code, "identifier_migration_conflict")
        self.assertEqual(legacy.provider, OLD_NAME)

    def test_repeated_logins_do_not_duplicate_associations(self) -> None:
        owner = User("sam", email=EMAIL)
        TestUserSocialAuth(owner, OLD_NAME, "stable-account-7", id_key="id")

        for _ in range(3):
            result = self.authenticate(self.new_backend())
            self.assertIs(result, owner)

        self.assertEqual(len(TestUserSocialAuth.cache_by_uid), 1)
        self.assertEqual(len(owner.social), 1)
        self.assertEqual(owner.social[0].provider, NEW_NAME)


class InFlightPartialRenameTest(BackendRenameTestBase, unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.strategy.set_settings({"SOCIAL_AUTH_PIPELINE": PAUSE_PIPELINE})

    def _start_old_login(self):
        result = self.authenticate(self.old_backend())
        # The pipeline halts at the confirmation partial step.
        self.assertEqual(result.url, "http://myapp.com/confirm")
        token = self.strategy.session_get(PARTIAL_TOKEN_SESSION_NAME)
        partial = TestPartial.load(token)
        assert partial is not None
        self.assertEqual(partial.backend, OLD_NAME)
        return partial

    def test_old_receipt_finishes_after_rename_then_new_name_works(self) -> None:
        # 1. A binding exists and a login is started under the old name.
        owner = User("sam", email=EMAIL)
        binding = TestUserSocialAuth(
            owner, OLD_NAME, "stable-account-7", id_key="id"
        )
        partial = self._start_old_login()

        # 2. Cutover begins and is deliberately stopped halfway: only the
        #    settings/publish side changes; the stored binding keeps the old name.
        self.assertEqual(
            pending_rename_providers(self.new_backend(), TestStorage),
            {OLD_NAME: 1},
        )
        self.assertEqual(binding.provider, OLD_NAME)

        # 3. The pre-rename receipt resumes and finishes the original login on
        #    the now-published backend, migrating the provider label lazily. The
        #    saved partial still records the old provider name and halted step.
        self.assertEqual(partial.backend, OLD_NAME)
        self.assertGreater(partial.next_step, 0)
        self.strategy.session_set("confirmation", "done")
        resumed_user = self.resume(self.new_backend())
        self.assertIs(resumed_user, owner)
        self.assertEqual(binding.provider, NEW_NAME)

        # 4. A subsequent login uses only the published name and stays bound.
        second = self.authenticate(self.new_backend())
        self.assertIs(second, owner)
        self.assertEqual(len(owner.social), 1)
        self.assertEqual(owner.social[0].provider, NEW_NAME)

    def test_unrelated_provider_cannot_resume_the_renamed_partial(self) -> None:
        owner = User("sam", email=EMAIL)
        TestUserSocialAuth(owner, OLD_NAME, "stable-account-7", id_key="id")
        self._start_old_login()

        self.strategy.session_set("confirmation", "done")
        # Resuming through an unrelated backend must not match the partial.
        partial = TestPartial.load(
            self.strategy.session_get(PARTIAL_TOKEN_SESSION_NAME)
        )
        self.assertFalse(
            _partial_pipeline_matches_request(
                self.other_backend(), partial, {}, "authentication"
            )
        )
        self.assertTrue(
            _partial_pipeline_matches_request(
                self.new_backend(), partial, {}, "authentication"
            )
        )


if __name__ == "__main__":
    unittest.main()
