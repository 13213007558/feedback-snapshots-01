"""Invariant tests for the two-platform managed-identity source-pinning simulation.

The simulation itself lives in
:mod:`tests.managed_identity_source_simulation` and also writes request records
under ``docs/managed-identity-simulation/``. These tests assert its security
invariants without writing any files, so they are safe to run in CI.
"""
import unittest
from urllib.parse import urlparse

from msal import ManagedIdentityMismatchError
from tests.managed_identity_source_simulation import (
    APPROVED_CLIENT_ID,
    APPROVED_ENDPOINT,
    BROAD_ENDPOINT,
    BROAD_SYSTEM_ASSIGNED_ID,
    run_simulation,
)


class ManagedIdentitySourceSimulationTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report, cls.router = run_simulation()

    def _step(self, number):
        return next(
            step for step in self.report["steps"] if step["step"] == number)

    def test_broad_identity_is_prewarmed_before_the_approved_call(self):
        step1 = self._step(1)["result"]
        self.assertEqual(
            BROAD_SYSTEM_ASSIGNED_ID, step1["broad_client_id"])
        self.assertEqual(1, step1["cached_entries_after_warmup"])

    def test_transient_failure_recovers_on_the_same_approved_source(self):
        step2 = self._step(2)["result"]
        self.assertEqual("identity_provider", step2["token_source"])
        self.assertEqual([APPROVED_ENDPOINT], step2["approved_endpoints_contacted"])
        self.assertFalse(step2["approved_client_ever_used_broad_endpoint"])

    def test_approved_requests_never_reach_the_broad_platform(self):
        approved_calls = [
            call for call in self.router.request_log
            if call["params"].get("client_id") == APPROVED_CLIENT_ID]
        self.assertTrue(approved_calls, "The pinned client must make real calls")
        self.assertTrue(all(
            urlparse(call["url"]).netloc == urlparse(APPROVED_ENDPOINT).netloc
            for call in approved_calls))

    def test_retry_reissues_the_full_challenge_token_pair(self):
        # Two approved challenge/token pairs prove a whole-attempt retry on one source.
        approved_authenticated = [
            call for call in self.router.request_log
            if urlparse(call["url"]).netloc == urlparse(APPROVED_ENDPOINT).netloc
            and call["headers"].get("Authorization")]
        self.assertGreaterEqual(
            len(approved_authenticated), 2,
            "The transient failure must be retried on the approved source")

    def test_later_success_is_served_from_the_approved_identity_cache(self):
        step3 = self._step(3)["result"]
        self.assertEqual("cache", step3["token_source"])
        self.assertEqual(0, step3["new_network_calls"])

    def test_identity_mismatch_is_rejected_and_never_served_from_broad_cache(self):
        step4 = self._step(4)["result"]
        self.assertEqual(
            "msal.ManagedIdentityMismatchError", step4["raised"])
        self.assertFalse(step4["rogue_token_cached"])
        self.assertFalse(step4["broad_endpoint_ever_called_by_approved_client"])

    def test_mismatch_error_is_a_recognizable_managed_identity_error(self):
        # The simulation reports the type name; assert the real class hierarchy too.
        self.assertTrue(issubclass(ManagedIdentityMismatchError, ValueError))


if __name__ == "__main__":
    unittest.main()
