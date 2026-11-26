from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Event
from typing import ClassVar, cast
from unittest.mock import patch

import requests
import responses

from social_core.actions import do_disconnect
from social_core.backends.github import GithubOAuth2
from social_core.disconnect import DisconnectReport
from social_core.exceptions import AuthPolicyError, AuthProviderError
from social_core.pipeline.utils import partial_prepare
from social_core.tests.exception_helpers import assert_auth_error
from social_core.tests.models import (
    TestPartial,
    TestStorage,
    TestUserSocialAuth,
    User,
)
from social_core.tests.strategy import TestStrategy
from social_core.utils import PARTIAL_TOKEN_SESSION_NAME, parse_qs

from .actions import BaseActionTest


class PausableUserSocialAuth(TestUserSocialAuth):
    """In-memory storage with one pre-commit pause gate per association."""

    entered: ClassVar[dict[int, Event]] = {}
    gates: ClassVar[dict[int, Event]] = {}

    @classmethod
    def arm_pause(cls, association_id: int) -> tuple[Event, Event]:
        entered = Event()
        gate = Event()
        cls.entered[association_id] = entered
        cls.gates[association_id] = gate
        return entered, gate

    @classmethod
    def reset_pauses(cls) -> None:
        cls.entered.clear()
        cls.gates.clear()

    @classmethod
    def disconnect_entries(
        cls,
        entries,
        *,
        user=None,
        backend_name=None,
        check_policy: bool = False,
    ):
        for entry in entries:
            entered = cls.entered.get(entry.id)
            gate = cls.gates.get(entry.id)
            if entered is not None and gate is not None:
                entered.set()
                if not gate.wait(timeout=5):
                    raise TimeoutError("Timed out waiting for disconnect pause gate")
        return super().disconnect_entries(
            entries,
            user=user,
            backend_name=backend_name,
            check_policy=check_policy,
        )


class PausableStorage(TestStorage):
    user = PausableUserSocialAuth


class DisconnectActionTest(BaseActionTest):
    def test_authentication_partial_cannot_skip_disconnect_guard(self) -> None:
        self.do_login()
        user = cast("User", User.get(self.expected_username))
        for legacy in (False, True):
            with self.subTest(legacy=legacy):
                partial = partial_prepare(self.strategy, self.backend, 1, user=user)
                if legacy:
                    partial.data.pop("pipeline_type")
                partial.save()
                self.strategy.session_set(PARTIAL_TOKEN_SESSION_NAME, partial.token)
                with self.assertRaises(AuthPolicyError):
                    do_disconnect(self.backend, user)
                self.assertEqual(len(user.social), 1)
                self.assertIsNone(TestPartial.load(partial.token))

    def test_not_allowed_to_disconnect(self) -> None:
        self.do_login()
        user = cast("User", User.get(self.expected_username))
        self.assertIsNotNone(user)
        with assert_auth_error(self, AuthPolicyError, "disconnect_disallowed"):
            do_disconnect(self.backend, user)

    def test_disconnect(self) -> None:
        self.do_login()
        user = cast("User", User.get(self.expected_username))
        user.password = "password"
        do_disconnect(self.backend, user)
        self.assertEqual(len(user.social), 0)

    def test_disconnect_redirects_to_allowed_private_use_scheme(self) -> None:
        deeplink = "com.example.app://oauth2redirect"
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_DISCONNECT_REDIRECT_URL": deeplink,
                "SOCIAL_AUTH_ALLOWED_REDIRECT_SCHEMES": [
                    "http",
                    "https",
                    "com.example.app",
                ],
            }
        )
        self.do_login()
        user = cast("User", User.get(self.expected_username))
        user.password = "password"
        redirect = do_disconnect(self.backend, user)
        self.assertEqual(redirect.url, deeplink)

    def test_disconnect_ignores_disallowed_scheme_from_request(self) -> None:
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_DISCONNECT_REDIRECT_URL": "/disconnected",
                "SOCIAL_AUTH_ALLOWED_REDIRECT_SCHEMES": [
                    "http",
                    "https",
                    "com.example.app",
                ],
            }
        )
        self.do_login()
        user = cast("User", User.get(self.expected_username))
        user.password = "password"
        self.strategy.set_request_data({"next": "com.evil.app://steal"}, self.backend)
        redirect = do_disconnect(self.backend, user)
        self.assertNotEqual(redirect.url, "com.evil.app://steal")

    def test_disconnect_keeps_allowed_scheme_from_request(self) -> None:
        deeplink = "com.example.app://oauth2redirect"
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_DISCONNECT_REDIRECT_URL": "/disconnected",
                "SOCIAL_AUTH_ALLOWED_REDIRECT_SCHEMES": [
                    "http",
                    "https",
                    "com.example.app",
                ],
            }
        )
        self.do_login()
        user = cast("User", User.get(self.expected_username))
        user.password = "password"
        self.strategy.set_request_data({"next": deeplink}, self.backend)
        redirect = do_disconnect(self.backend, user)
        self.assertEqual(redirect.url, deeplink)

    def test_disconnect_with_association_id(self) -> None:
        self.do_login()
        user = cast("User", User.get(self.expected_username))
        user.password = "password"
        association_id = user.social[0].id
        second_usa = TestUserSocialAuth(user, user.social[0].provider, "uid2")
        self.assertEqual(len(user.social), 2)
        do_disconnect(self.backend, user, association_id)
        self.assertEqual(len(user.social), 1)
        self.assertEqual(user.social[0], second_usa)

    def test_parallel_disconnect_commit_pauses_keep_one_real_login(self) -> None:
        self.addCleanup(PausableUserSocialAuth.reset_pauses)
        user = User(self.expected_username)
        user.password = None
        survivor = PausableUserSocialAuth(
            user,
            self.backend.name,
            "1",
            extra_data={"id": 1},
            id_key="id",
        )
        doomed = PausableUserSocialAuth(
            user,
            self.backend.name,
            "parallel-2",
            extra_data={"id": "parallel-2"},
            id_key="id",
        )
        survivor_entered, survivor_gate = PausableUserSocialAuth.arm_pause(survivor.id)
        doomed_entered, doomed_gate = PausableUserSocialAuth.arm_pause(doomed.id)

        def disconnect(association_id: int):
            strategy = TestStrategy(PausableStorage)
            strategy.set_settings(
                {
                    "SOCIAL_AUTH_GITHUB_KEY": "a-key",
                    "SOCIAL_AUTH_GITHUB_SECRET": "a-secret-key",
                    "SOCIAL_AUTH_DISCONNECT_REDIRECT_URL": "/disconnected",
                }
            )
            backend = GithubOAuth2(strategy)
            return do_disconnect(backend, user, association_id)

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                "survivor": executor.submit(disconnect, survivor.id),
                "doomed": executor.submit(disconnect, doomed.id),
            }
            self.assertTrue(survivor_entered.wait(timeout=5))
            self.assertTrue(doomed_entered.wait(timeout=5))
            self.assertEqual(len(user.social), 2)

            doomed_gate.set()
            self.assertIsNotNone(futures["doomed"].result(timeout=5))
            survivor_gate.set()

            outcomes = {}
            for key, future in futures.items():
                try:
                    outcomes[key] = future.result(timeout=5)
                except BaseException as exc:  # captured for status classification
                    outcomes[key] = exc

        self.assertIsInstance(outcomes["survivor"], AuthPolicyError)
        self.assertEqual(outcomes["survivor"].code, "disconnect_disallowed")
        report = DisconnectReport.from_outcomes(
            [
                ("1", outcomes["survivor"]),
                ("parallel-2", outcomes["doomed"]),
            ]
        )
        self.assertEqual(report.state, "partially_completed")
        self.assertEqual([item.key for item in report.completed], ["parallel-2"])
        self.assertEqual([item.key for item in report.protected], ["1"])
        self.assertFalse(report.can_retry)

        self.assertIsNone(
            TestUserSocialAuth.get_social_auth(self.backend.name, "parallel-2")
        )
        remaining = TestUserSocialAuth.get_social_auth(self.backend.name, "1")
        self.assertIsNotNone(remaining)
        self.assertIs(remaining, survivor)
        self.assertEqual(len(user.social), 1)

        self.do_login()
        self.assertEqual(self.strategy.session_get("username"), self.expected_username)
        self.assertIsNotNone(TestUserSocialAuth.get_social_auth(self.backend.name, "1"))

    def test_parallel_disconnect_unknown_remote_result_is_retryable(self) -> None:
        user = User(self.expected_username)
        user.password = None
        survivor = PausableUserSocialAuth(
            user,
            self.backend.name,
            "1",
            extra_data={"id": 1, "access_token": "survivor-token"},
            id_key="id",
        )
        doomed = PausableUserSocialAuth(
            user,
            self.backend.name,
            "remote-2",
            extra_data={"id": "remote-2", "access_token": "doomed-token"},
            id_key="id",
        )
        remote_entered = {
            "1": Event(),
            "remote-2": Event(),
        }
        remote_gates = {
            "1": Event(),
            "remote-2": Event(),
        }

        def revoke_token(backend, token: str, uid: str):
            remote_entered[uid].set()
            if not remote_gates[uid].wait(timeout=5):
                raise TimeoutError("Timed out waiting for remote revocation gate")
            if uid == "1":
                raise AuthProviderError(
                    backend,
                    code="timeout",
                    stage="disconnect",
                )
            return True

        def disconnect(association_id: int):
            strategy = TestStrategy(PausableStorage)
            strategy.set_settings(
                {
                    "SOCIAL_AUTH_GITHUB_KEY": "a-key",
                    "SOCIAL_AUTH_GITHUB_SECRET": "a-secret-key",
                    "SOCIAL_AUTH_AUTHENTICATION_BACKENDS": (
                        "social_core.backends.github.GithubOAuth2",
                    ),
                    "SOCIAL_AUTH_DISCONNECT_REDIRECT_URL": "/disconnected",
                    "SOCIAL_AUTH_REVOKE_TOKENS_ON_DISCONNECT": True,
                }
            )
            backend = GithubOAuth2(strategy)
            return do_disconnect(backend, user, association_id)

        with patch.object(
            GithubOAuth2,
            "revoke_token",
            autospec=True,
            side_effect=revoke_token,
        ):
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = {
                    "survivor": executor.submit(disconnect, survivor.id),
                    "doomed": executor.submit(disconnect, doomed.id),
                }
                self.assertTrue(remote_entered["1"].wait(timeout=5))
                self.assertTrue(remote_entered["remote-2"].wait(timeout=5))
                self.assertEqual(len(user.social), 2)

                remote_gates["remote-2"].set()
                self.assertIsNotNone(futures["doomed"].result(timeout=5))
                remote_gates["1"].set()

                outcomes = {}
                for key, future in futures.items():
                    try:
                        outcomes[key] = future.result(timeout=5)
                    except BaseException as exc:
                        outcomes[key] = exc

        self.assertIsInstance(outcomes["survivor"], AuthProviderError)
        self.assertEqual(outcomes["survivor"].code, "timeout")
        report = DisconnectReport.from_outcomes(
            [
                ("1", outcomes["survivor"]),
                ("remote-2", outcomes["doomed"]),
            ]
        )
        self.assertEqual(report.state, "partially_completed")
        self.assertTrue(report.can_retry)
        self.assertEqual([item.key for item in report.completed], ["remote-2"])
        retryable = report.retryable_items
        self.assertEqual(len(retryable), 1)
        self.assertEqual(retryable[0].key, "1")
        self.assertEqual(retryable[0].state, "retryable")
        self.assertTrue(retryable[0].retryable)
        self.assertTrue(retryable[0].uncertain)
        self.assertEqual(retryable[0].error_code, "timeout")
        self.assertEqual(retryable[0].recovery, "retry_later")
        self.assertEqual(retryable[0].provider, self.backend.name)
        self.assertEqual(retryable[0].uid, "1")
        public_report = report.public_dict()
        self.assertEqual(public_report["state"], "partially_completed")
        self.assertIs(public_report["can_retry"], True)
        self.assertEqual(public_report["retryable_keys"], ["1"])

        self.assertIsNone(
            TestUserSocialAuth.get_social_auth(self.backend.name, "remote-2")
        )
        remaining = TestUserSocialAuth.get_social_auth(self.backend.name, "1")
        self.assertIsNotNone(remaining)
        self.assertIs(remaining, survivor)
        self.assertEqual(len(user.social), 1)

        self.do_login()
        self.assertEqual(self.strategy.session_get("username"), self.expected_username)
        self.assertIsNotNone(TestUserSocialAuth.get_social_auth(self.backend.name, "1"))

    @responses.activate
    def test_disconnect_with_partial_pipeline(self) -> None:
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_DISCONNECT_PIPELINE": (
                    "social_core.tests.pipeline.ask_for_password",
                    "social_core.tests.pipeline.set_password",
                    "social_core.pipeline.disconnect.allowed_to_disconnect",
                    "social_core.pipeline.disconnect.get_entries",
                    "social_core.pipeline.disconnect.revoke_tokens",
                    "social_core.pipeline.disconnect.disconnect",
                )
            }
        )
        self.do_login()
        user = cast("User", User.get(self.expected_username))
        redirect = do_disconnect(self.backend, user)

        url = self.strategy.build_absolute_uri("/password")
        self.assertEqual(redirect.url, url)
        token = self.strategy.session_get(PARTIAL_TOKEN_SESSION_NAME)
        assert isinstance(token, str)
        partial = TestPartial.load(token)
        assert partial is not None
        self.assertEqual(partial.pipeline_type, "disconnect")
        responses.add(responses.GET, redirect.url, status=200, body="foobar")
        responses.add(responses.POST, redirect.url, status=200)

        password = "foobar"
        requests.get(url, timeout=1)
        requests.post(url, data={"password": password}, timeout=1)
        data = parse_qs(responses.calls[-1].request.body)
        self.assertEqual(data["password"], password)
        self.strategy.session_set("password", data["password"])

        redirect = do_disconnect(self.backend, user)
        self.assertEqual(len(user.social), 0)
        url = self.strategy.build_absolute_uri("/success")
        self.assertEqual(redirect.url, url)
