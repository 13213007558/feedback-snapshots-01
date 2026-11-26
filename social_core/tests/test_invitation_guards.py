from __future__ import annotations

import unittest
from dataclasses import dataclass
from typing import Any, ClassVar
from unittest.mock import patch

from social_core.backends.base import BaseAuth
from social_core.exceptions import AuthInvitationRevoked
from social_core.invitations import InvitationStage
from social_core.pipeline.partial import partial_step
from social_core.pipeline.social_auth import associate_user
from social_core.pipeline.user import user_details
from social_core.tests.invitation_memory import MemoryInvitationCenter
from social_core.tests.models import (
    TestStorage,
    TestUserSocialAuth,
    User,
)
from social_core.tests.strategy import TestStrategy
from social_core.utils import partial_pipeline_result

PIPELINE = (
    "social_core.pipeline.social_auth.social_details",
    "social_core.pipeline.social_auth.social_uid",
    "social_core.tests.test_invitation_guards.pause_for_confirmation",
    "social_core.pipeline.social_auth.social_user",
    "social_core.pipeline.user.get_username",
    "social_core.pipeline.social_auth.associate_user",
    "social_core.pipeline.social_auth.load_extra_data",
    "social_core.pipeline.user.user_details",
)


@dataclass
class HaltResponse:
    invitation_id: str
    token: str


@partial_step(save_to_session=True)
def pause_for_confirmation(
    strategy: TestStrategy,
    invitation_id: str,
    current_partial: Any,
    **kwargs: Any,
):
    if strategy.session_get(f"resume:{invitation_id}"):
        return {"confirmation": "resumed"}
    return HaltResponse(invitation_id, current_partial.token)


class InvitationTestStrategy(TestStrategy):
    def __init__(self, storage) -> None:
        super().__init__(storage)
        self.invitation_center = MemoryInvitationCenter()
        self.invitation_validator = self.invitation_center


class FakeProviderBackend(BaseAuth):
    name = "fake"
    ID_KEY = "id"
    provider_label = "Fake"

    def get_user_details(self, response):
        return {
            "username": response["username"],
            "email": response.get("email"),
            "first_name": response.get("first_name"),
        }


class AlphaProvider(FakeProviderBackend):
    name = "alpha"


class BetaProvider(FakeProviderBackend):
    name = "beta"


class InvitationGuardScenarioTest(unittest.TestCase):
    backend_paths: ClassVar[tuple[str, str]] = (
        "social_core.tests.test_invitation_guards.AlphaProvider",
        "social_core.tests.test_invitation_guards.BetaProvider",
    )

    def setUp(self) -> None:
        User.reset_cache()
        TestUserSocialAuth.reset_cache()
        self.strategy = InvitationTestStrategy(TestStorage)
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_AUTHENTICATION_BACKENDS": self.backend_paths,
                "SOCIAL_AUTH_PIPELINE": PIPELINE,
            }
        )
        self.session_key = "same-browser-session"
        self.strategy.session_set("session_key", self.session_key)
        self.user = User("support-customer", "customer@example.com")
        self.alpha = AlphaProvider(self.strategy)
        self.beta = BetaProvider(self.strategy)
        self.center = self.strategy.invitation_center
        self.center.issue(
            "inv-alpha",
            user=self.user,
            session_key=self.session_key,
            provider="alpha",
        )
        self.center.issue(
            "inv-beta",
            user=self.user,
            session_key=self.session_key,
            provider="beta",
        )

    def tearDown(self) -> None:
        User.reset_cache()
        TestUserSocialAuth.reset_cache()

    def start_flow(self, backend: FakeProviderBackend, invitation_id: str, uid: str):
        response = {
            "id": uid,
            "username": f"{backend.name}-user",
            "email": f"{uid}@example.test",
            "first_name": f"{backend.name.title()} Name",
        }
        halt = backend.pipeline(
            PIPELINE,
            user=self.user,
            invitation_id=invitation_id,
            response=response,
        )
        self.assertIsInstance(halt, HaltResponse)
        return halt

    def test_revoked_invitation_stops_only_its_out_of_order_flow(self) -> None:
        alpha_halt = self.start_flow(self.alpha, "inv-alpha", "alpha-uid")
        beta_halt = self.start_flow(self.beta, "inv-beta", "beta-uid")

        # The second partial replaces the legacy global token, but the
        # invitation-scoped session index still owns the first partial.
        resolved_alpha = partial_pipeline_result(
            self.alpha, self.user, partial_token=alpha_halt.token
        )
        self.assertIsNotNone(resolved_alpha.partial)
        self.assertEqual(resolved_alpha.partial.token, alpha_halt.token)

        self.center.revoke("inv-alpha")

        self.strategy.session_set("resume:inv-beta", True)
        beta_partial = self.strategy.partial_load(beta_halt.token)
        with patch.object(TestUserSocialAuth, "changed_fields") as changed_fields:
            beta_user = self.beta.continue_pipeline(beta_partial)

        self.assertIs(beta_user, self.user)
        changed_fields.assert_called_once_with(self.user, {"first_name"})
        beta_social = TestUserSocialAuth.get_social_auth("beta", "beta-uid")
        self.assertIsNotNone(beta_social)
        self.assertIs(beta_social.user, self.user)
        self.assertIsNone(TestUserSocialAuth.get_social_auth("alpha", "alpha-uid"))
        self.assertEqual(
            [social.provider for social in self.user.social],
            ["beta"],
        )
        self.assertEqual(self.user.first_name, "Beta Name")
        self.assertIs(self.strategy.get_user(self.user.id), self.user)
        self.assertIs(self.beta.get_user(self.user.id), self.user)

        login_strategy = TestStrategy(TestStorage)
        login_backend = BetaProvider(login_strategy)
        logged_in_user = login_backend.pipeline(
            login_strategy.get_pipeline(login_backend),
            response={
                "id": "beta-uid",
                "username": "beta-user",
                "email": "beta-uid@example.test",
                "first_name": "Beta Name",
            },
        )
        self.assertIs(logged_in_user, self.user)

        with self.assertRaises(AuthInvitationRevoked) as raised:
            alpha_partial = self.strategy.partial_load(alpha_halt.token)
            self.alpha.continue_pipeline(alpha_partial)

        self.assertEqual(raised.exception.invitation_id, "inv-alpha")
        self.assertEqual(raised.exception.end_state, "revoked")
        self.assertEqual(self.center.invitations["inv-alpha"].status, "revoked")
        self.assertEqual(self.center.invitations["inv-alpha"].end_state, "revoked")

        alpha_checks = self.center.checks("inv-alpha")
        self.assertEqual(
            [(check.stage, check.allowed) for check in alpha_checks],
            [
                (InvitationStage.PARTIAL_VALIDATE, True),
                (InvitationStage.PARTIAL_RESUME, False),
            ],
        )
        beta_checks = self.center.checks("inv-beta")
        self.assertEqual(
            [check.stage for check in beta_checks],
            [
                InvitationStage.PARTIAL_RESUME,
                InvitationStage.ASSOCIATION_SAVE,
                InvitationStage.PROFILE_SYNC,
            ],
        )
        self.assertTrue(all(check.allowed for check in beta_checks))
        self.assertEqual(
            {check.session_key for check in beta_checks}, {self.session_key}
        )
        self.assertEqual({check.user_id for check in beta_checks}, {self.user.id})

        self.center.complete("inv-beta")
        self.assertEqual(self.center.invitations["inv-beta"].end_state, "completed")

    def test_association_save_revalidates_revocation(self) -> None:
        self.center.revoke("inv-alpha")
        with (
            self.assertRaises(AuthInvitationRevoked),
            patch.object(TestStorage.user, "create_social_auth") as create,
        ):
            associate_user(
                self.alpha,
                "late-alpha-uid",
                user=self.user,
                invitation_id="inv-alpha",
            )
        create.assert_not_called()
        self.assertIsNone(TestUserSocialAuth.get_social_auth("alpha", "late-alpha-uid"))

    def test_profile_sync_revalidates_before_writing_fields(self) -> None:
        self.center.revoke("inv-alpha")
        with (
            patch.object(TestUserSocialAuth, "changed_fields") as changed_fields,
            self.assertRaises(AuthInvitationRevoked),
        ):
            user_details(
                self.strategy,
                {"first_name": "Must Not Persist"},
                self.alpha,
                user=self.user,
                invitation_id="inv-alpha",
            )

        self.assertIsNone(self.user.first_name)
        changed_fields.assert_not_called()


if __name__ == "__main__":
    unittest.main()
