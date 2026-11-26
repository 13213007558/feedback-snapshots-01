"""Experiment B: unbind where confirmation is unavailable.

Part B1 - remote revoke outcome unknown:
    REVOKE_TOKENS_ON_DISCONNECT is on, the provider revoke endpoint is
    unreachable. The disconnect pipeline aborts in revoke_tokens; the
    local row is never touched. Expected notification: association.pending
    (unbind attempted, remote unknown), NOT association.changed.

Part B2 - local commit state unknown, read-back confirms deletion:
    storage.disconnect applies the delete but the driver reports an
    ambiguous error (commit state unknown). A read-back-only adapter
    cannot trust the return/exception; it reconciles by re-reading.
    Read-back shows the row gone -> only then emit association.changed.

Part B3 - local commit state unknown, read-back shows row present:
    Same ambiguous error, but the delete was not applied. Read-back
    finds the row -> keep association.pending, no changed event.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

import requests  # noqa: E402
import responses  # noqa: E402
from notify import Notifier, Trace  # noqa: E402

from social_core.actions import do_disconnect  # noqa: E402
from social_core.exceptions import AuthProviderError  # noqa: E402
from social_core.pipeline import disconnect as disconnect_pipeline  # noqa: E402
from social_core.tests.actions.actions import BaseActionTest  # noqa: E402
from social_core.tests.models import TestUserSocialAuth, User  # noqa: E402

REVOKE_URL = "https://provider.example.com/oauth2/revoke"


def instrument_disconnect_pipeline(trace: Trace):
    originals = {}
    for name in (
        "allowed_to_disconnect",
        "get_entries",
        "revoke_tokens",
        "disconnect",
    ):
        real = getattr(disconnect_pipeline, name)
        originals[name] = real

        def make(real, name):
            def step(*args, **kwargs):
                trace.record(f"pipeline.disconnect.{name} ENTER")
                try:
                    return real(*args, **kwargs)
                finally:
                    trace.record(f"pipeline.disconnect.{name} EXIT")

            return step

        setattr(disconnect_pipeline, name, make(real, name))
    return originals


def restore_disconnect_pipeline(originals) -> None:
    for name, real in originals.items():
        setattr(disconnect_pipeline, name, real)


class UnbindUnconfirmedTest(BaseActionTest):
    def runTest(self) -> None:
        self.part_b1_remote_revoke_unknown()
        self.tearDown()
        self.setUp()  # reset caches/strategy between parts
        self.part_b2_readback_confirms_delete()
        self.tearDown()
        self.setUp()
        self.part_b3_readback_shows_row_remains()

    # ------------------------------------------------------------------
    def part_b1_remote_revoke_unknown(self) -> None:
        trace = Trace()
        notifier = Notifier()
        self.strategy.set_settings(
            {
                "SOCIAL_AUTH_REVOKE_TOKENS_ON_DISCONNECT": True,
                "SOCIAL_AUTH_GITHUB_REVOKE_TOKEN_URL": REVOKE_URL,
            }
        )
        self.do_login()
        user = User.get(self.expected_username)
        user.password = "password"

        originals = instrument_disconnect_pipeline(trace)
        responses.add(
            responses.POST,
            REVOKE_URL,
            body=requests.ConnectionError("connection reset by peer"),
        )
        error = None
        try:
            do_disconnect(self.backend, user)
        except AuthProviderError as err:
            error = err
            # Ops-facing pending event: attempted, remote outcome unknown.
            notifier.emit(
                "association.pending",
                op="unbind",
                status="remote_unknown",
                provider="github",
                uid=user.social[0].uid,
                user_id=user.id,
                reason=f"{err.code}@{err.stage}",
            )
        finally:
            restore_disconnect_pipeline(originals)

        persisted = TestUserSocialAuth.get_social_auth("github", "1")
        print("=== Experiment B1: remote revoke outcome unknown ===")
        print("call trace:")
        print(trace.dump())
        print(f"\nraised: {type(error).__name__} code={error.code} "
              f"stage={error.stage}")
        print(f"persisted fact: readback github/1 -> "
              f"{'EXISTS (local row retained)' if persisted else 'MISSING'}")
        print("notifications emitted:")
        for e in notifier.events:
            print(f"  {e['kind']} op={e['op']} status={e['status']} "
                  f"reason={e.get('reason')}")

        self.assertIsNotNone(error)
        self.assertEqual(error.code, "connection_failed")
        self.assertEqual(error.stage, "disconnect")
        self.assertIsNotNone(persisted, "local row must survive a failed "
                                        "revoke: pipeline aborts before the "
                                        "disconnect step")
        kinds = {(e["kind"], e["status"]) for e in notifier.events}
        self.assertIn(("association.pending", "remote_unknown"), kinds)
        self.assertNotIn(("association.changed", "committed"), kinds)
        print("OK: no changed-event; pending state kept for reconciliation\n")

    # ------------------------------------------------------------------
    def _run_ambiguous_disconnect(self, apply_delete: bool):
        trace = Trace()
        notifier = Notifier()
        self.do_login()
        # Remote revoke is out of scope for B2/B3: the ambiguous point is
        # the local storage commit.
        self.strategy.set_settings(
            {"SOCIAL_AUTH_REVOKE_TOKENS_ON_DISCONNECT": False}
        )
        user = User.get(self.expected_username)
        user.password = "password"

        real_disconnect = TestUserSocialAuth.disconnect.__func__

        @classmethod
        def ambiguous_disconnect(cls, entry):
            trace.record("storage.disconnect ATTEMPT")
            if apply_delete:
                real_disconnect(cls, entry)
                trace.record("storage.disconnect delete applied")
            # Driver reports failure after (maybe) committing: the caller
            # cannot tell whether the delete is durable.
            raise TimeoutError("driver: commit state unknown")

        TestUserSocialAuth.disconnect = ambiguous_disconnect
        originals = instrument_disconnect_pipeline(trace)
        error = None
        try:
            do_disconnect(self.backend, user)
        except TimeoutError as err:
            error = err
        finally:
            restore_disconnect_pipeline(originals)
            TestUserSocialAuth.disconnect = classmethod(real_disconnect)

        # Read-back-only reconciliation: the only admissible evidence.
        # NOTE: must use the adapter's authoritative read path. This
        # in-memory adapter deletes via user.social, so
        # get_social_auth_for_user is authoritative; the uid-indexed
        # cache_by_uid is stale after disconnect and is printed only as a
        # cautionary cross-check.
        stale = TestUserSocialAuth.get_social_auth("github", "1")
        if stale is not None:
            trace.record(
                "readback WARNING: uid-index still returns stale row; "
                "not authoritative for this adapter"
            )
        readback = TestUserSocialAuth.get_social_auth_for_user(user, "github")
        readback = readback[0] if readback else None
        if readback is None:
            notifier.emit(
                "association.changed",
                op="unbind",
                status="committed",
                provider="github",
                uid="1",
                user_id=user.id,
                confirmed_by="readback",
            )
        else:
            notifier.emit(
                "association.pending",
                op="unbind",
                status="local_unconfirmed",
                provider="github",
                uid="1",
                user_id=user.id,
                reason=str(error),
            )
        return trace, notifier, readback, user

    def part_b2_readback_confirms_delete(self) -> None:
        trace, notifier, readback, user = self._run_ambiguous_disconnect(
            apply_delete=True
        )
        print("=== Experiment B2: ambiguous commit, read-back confirms ===")
        print("call trace:")
        print(trace.dump())
        print(f"\npersisted fact: readback github/1 -> "
              f"{'EXISTS' if readback else 'MISSING (delete confirmed)'} "
              f"user.social={len(user.social)}")
        print("notifications emitted:")
        for e in notifier.events:
            print(f"  {e['kind']} op={e['op']} status={e['status']} "
                  f"confirmed_by={e.get('confirmed_by', '-')}")
        self.assertIsNone(readback)
        kinds = {(e["kind"], e["status"]) for e in notifier.events}
        self.assertIn(("association.changed", "committed"), kinds)
        print("OK: changed-event emitted only after read-back evidence\n")

    def part_b3_readback_shows_row_remains(self) -> None:
        trace, notifier, readback, user = self._run_ambiguous_disconnect(
            apply_delete=False
        )
        print("=== Experiment B3: ambiguous commit, read-back finds row ===")
        print("call trace:")
        print(trace.dump())
        print(f"\npersisted fact: readback github/1 -> "
              f"{'EXISTS (delete NOT applied)' if readback else 'MISSING'} "
              f"user.social={len(user.social)}")
        print("notifications emitted:")
        for e in notifier.events:
            print(f"  {e['kind']} op={e['op']} status={e['status']} "
                  f"reason={e.get('reason', '-')}")
        self.assertIsNotNone(readback)
        kinds = {(e["kind"], e["status"]) for e in notifier.events}
        self.assertIn(("association.pending", "local_unconfirmed"), kinds)
        self.assertNotIn(("association.changed", "committed"), kinds)
        print("OK: pending state retained; no changed-event without evidence\n")


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]], verbosity=0)
