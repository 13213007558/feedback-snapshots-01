"""Experiment A: association row committed, browser redirect then fails.

Scenario: the login pipeline persists the new social-auth association
(storage commit succeeds), but the final HTTP redirect to the browser
fails (client went away / response write error).

Expected: the bind is a durable local fact. A commit-point notification
(association.changed/bind/committed) must exist; a callback-point
notification (callback.completed) must NOT be required to establish the
fact, and is absent here.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from notify import Notifier, Trace  # noqa: E402

from social_core.pipeline import social_auth as social_auth_pipeline  # noqa: E402
from social_core.tests.actions.actions import BaseActionTest  # noqa: E402
from social_core.tests.models import TestUserSocialAuth, User  # noqa: E402


class BindRedirectFailureTest(BaseActionTest):
    def runTest(self) -> None:
        trace = Trace()
        notifier = Notifier()

        # --- instrument the commit point: storage.create_social_auth ---
        real_create = TestUserSocialAuth.create_social_auth.__func__

        @classmethod
        def traced_create(cls, user, uid, provider, id_key=""):
            social = real_create(cls, user, uid, provider, id_key=id_key)
            # Commit-point notification: the row exists after this call.
            trace.record(
                f"storage.create_social_auth COMMIT provider={provider} uid={uid}"
            )
            notifier.emit(
                "association.changed",
                op="bind",
                status="committed",
                provider=provider,
                uid=uid,
                user_id=user.id,
            )
            return social

        TestUserSocialAuth.create_social_auth = traced_create

        # --- trace the pipeline step that triggers the commit ---
        real_associate = social_auth_pipeline.associate_user

        def traced_associate(*args, **kwargs):
            trace.record("pipeline.associate_user ENTER")
            result = real_associate(*args, **kwargs)
            trace.record("pipeline.associate_user EXIT")
            return result

        social_auth_pipeline.associate_user = traced_associate

        # --- instrument the callback point: strategy.redirect ---
        real_redirect = self.strategy.redirect

        def failing_redirect(url):
            trace.record(f"callback.redirect ATTEMPT url={url}")
            if url != self.login_redirect_url:
                # Only the post-login callback redirect fails; the initial
                # redirect to the provider must succeed.
                return real_redirect(url)
            # A naive integration would emit callback.completed only after
            # the redirect is handed to the browser; it never fires here.
            raise OSError("response write failed: client disconnected")

        self.strategy.redirect = failing_redirect

        try:
            with self.assertRaises(OSError):
                self.do_login(after_complete_checks=False)
        finally:
            TestUserSocialAuth.create_social_auth = classmethod(real_create)
            social_auth_pipeline.associate_user = real_associate
            self.strategy.redirect = real_redirect

        user = User.get(self.expected_username)
        persisted = TestUserSocialAuth.get_social_auth("github", "1")

        print("\n=== Experiment A: bind committed, redirect failed ===")
        print("call trace:")
        print(trace.dump())
        print(f"\npersisted fact: user={user.username!r} "
              f"social_rows={len(user.social)} "
              f"readback github/1 -> {'EXISTS' if persisted else 'MISSING'}")
        print("\nnotifications emitted:")
        for e in notifier.events:
            print(f"  {e['kind']} op={e['op']} status={e['status']} "
                  f"idem_key={e['idem_key']}")

        self.assertIsNotNone(persisted, "association row must survive the "
                                        "failed redirect")
        self.assertEqual(len(user.social), 1)
        kinds = {(e["kind"], e["op"], e["status"]) for e in notifier.events}
        self.assertIn(("association.changed", "bind", "committed"), kinds)
        self.assertNotIn(
            ("callback.completed", "bind", "done"),
            kinds,
            "no callback notification may be required to establish the fact",
        )
        print("\nOK: bind fact established at commit point; redirect failure "
              "does not roll it back\n")


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]], verbosity=0)
