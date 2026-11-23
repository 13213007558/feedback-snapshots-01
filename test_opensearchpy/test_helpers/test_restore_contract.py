# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.

from unittest import TestCase

from opensearchpy import (
    ApprovalStaleError,
    OpenSearch,
    RestorePatternError,
    SnapshotIdentityError,
)
from opensearchpy.helpers import (
    execute_restore,
    plan_restore,
    revalidate_restore,
)


def _snapshot_listing(name, uuid, indices, version="2.15.0", state="SUCCESS"):
    return {
        "snapshots": [
            {
                "snapshot": name,
                "uuid": uuid,
                "version": version,
                "state": state,
                "indices": list(indices),
            }
        ]
    }


# The two local snapshot listings model an update between preflight and execute:
# snapshot "snap-1" initially contains orders/logs/billing, later logs is renamed
# to logs-2026, changing the filtered match for the approved plan.
LISTING_BEFORE = _snapshot_listing(
    "snap-1", "uuid-1", ["orders", "logs", "billing"]
)
LISTING_AFTER = _snapshot_listing(
    "snap-1", "uuid-1", ["orders", "logs-2026", "billing"]
)


class RecordingSnapshot:
    def __init__(self, listing):
        self.listing = listing
        self.restore_calls = []
        self.get_calls = []

    def get(self, repository, snapshot):
        self.get_calls.append((repository, snapshot))
        return self.listing

    def restore(self, repository, snapshot, body, params=None, headers=None):
        self.restore_calls.append(
            {
                "repository": repository,
                "snapshot": snapshot,
                "body": body,
                "params": params,
                "headers": headers,
            }
        )
        return {"accepted": True, "snapshot": snapshot}


class FakeClient:
    def __init__(self, listing):
        self.snapshot = RecordingSnapshot(listing)


class TestRestoreContract(TestCase):
    def test_preflight_freezes_identity_sources_and_targets(self):
        client = FakeClient(LISTING_BEFORE)
        plan = plan_restore(
            client,
            repository="repo",
            snapshot="snap-1",
            target_prefix="dr-tmp-",
            exclude_indices=["billing"],
        )

        self.assertEqual(plan.repository, "repo")
        self.assertEqual(plan.snapshot, "snap-1")
        self.assertEqual(plan.snapshot_uuid, "uuid-1")
        self.assertEqual(plan.source_indices, ("orders", "logs"))
        self.assertEqual(
            plan.target_indices, ("dr-tmp-orders", "dr-tmp-logs")
        )
        self.assertEqual(
            plan.request.body["index_renames"],
            [
                {"source_index": "orders", "target_index": "dr-tmp-orders"},
                {"source_index": "logs", "target_index": "dr-tmp-logs"},
            ],
        )
        self.assertEqual(
            plan.request.path, "/_snapshot/repo/snap-1/_restore"
        )
        self.assertEqual(plan.request.method, "POST")
        self.assertTrue(plan.fingerprint)

    def test_explicit_rename_map_overrides_prefix_target(self):
        client = FakeClient(LISTING_BEFORE)
        plan = plan_restore(
            client,
            repository="repo",
            snapshot="snap-1",
            target_prefix="dr-tmp-",
            include_indices=["orders", "logs"],
            rename_map={"orders": "orders-recovery-copy"},
        )
        targets = dict(
            (rename.source, rename.target) for rename in plan.renames
        )
        self.assertEqual(targets["orders"], "orders-recovery-copy")
        self.assertEqual(targets["logs"], "dr-tmp-logs")

    def test_wildcard_pattern_stops_at_preflight(self):
        client = FakeClient(LISTING_BEFORE)
        with self.assertRaises(RestorePatternError):
            plan_restore(
                client,
                repository="repo",
                snapshot="snap-1",
                target_prefix="dr-tmp-",
                include_indices=["log*"],
            )
        # No restore request was attempted.
        self.assertEqual(client.snapshot.restore_calls, [])

    def test_wildcard_prefix_stops_at_preflight(self):
        client = FakeClient(LISTING_BEFORE)
        with self.assertRaises(RestorePatternError):
            plan_restore(
                client,
                repository="repo",
                snapshot="snap-1",
                target_prefix="dr-*",
            )
        self.assertEqual(client.snapshot.restore_calls, [])

    def test_unknown_snapshot_identity_stops_at_preflight(self):
        client = FakeClient({"snapshots": []})
        with self.assertRaises(SnapshotIdentityError):
            plan_restore(
                client,
                repository="repo",
                snapshot="missing",
                target_prefix="dr-tmp-",
            )

    def test_stale_approval_blocks_restore_and_sends_nothing(self):
        client = FakeClient(LISTING_BEFORE)
        plan = plan_restore(
            client,
            repository="repo",
            snapshot="snap-1",
            target_prefix="dr-tmp-",
            exclude_indices=["billing"],
        )

        changed = FakeClient(LISTING_AFTER)
        reasons = revalidate_restore(changed, plan)
        self.assertTrue(reasons)
        self.assertTrue(any("logs" in reason for reason in reasons))

        with self.assertRaises(ApprovalStaleError):
            execute_restore(changed, plan)

        # Approval invalidation must produce zero restore requests on transport.
        self.assertEqual(changed.snapshot.restore_calls, [])
        # Catalog reads only: one from the explicit revalidation and one from the
        # revalidation inside the blocked execute attempt.
        self.assertEqual(
            changed.snapshot.get_calls,
            [("repo", "snap-1"), ("repo", "snap-1")],
        )

    def test_unchanged_catalog_executes_with_frozen_parameters(self):
        client = FakeClient(LISTING_BEFORE)
        plan = plan_restore(
            client,
            repository="repo",
            snapshot="snap-1",
            target_prefix="dr-tmp-",
            include_indices=["orders", "logs"],
            params={"wait_for_completion": "true"},
        )

        # A separate client with the same listing stands in for the time gap.
        executor = FakeClient(LISTING_BEFORE)
        receipt = execute_restore(executor, plan)

        self.assertEqual(len(executor.snapshot.restore_calls), 1)
        sent = executor.snapshot.restore_calls[0]
        self.assertEqual(sent["repository"], "repo")
        self.assertEqual(sent["snapshot"], "snap-1")
        # The exact approved body, not anything re-derived, is what is sent.
        self.assertEqual(sent["body"], plan.request.body)
        self.assertEqual(
            sent["body"]["indices"], ["orders", "logs"]
        )
        self.assertEqual(sent["params"], {"wait_for_completion": "true"})

        # The receipt locates the real source and destination of each index.
        self.assertEqual(
            [(m.source, m.target) for m in receipt.mappings],
            [
                ("orders", "dr-tmp-orders"),
                ("logs", "dr-tmp-logs"),
            ],
        )
        self.assertEqual(receipt.snapshot_uuid, "uuid-1")
        self.assertEqual(receipt.raw_response, {"accepted": True, "snapshot": "snap-1"})

    def test_execute_uses_approved_even_if_request_args_would_differ(self):
        client = FakeClient(LISTING_BEFORE)
        plan = plan_restore(
            client,
            repository="repo",
            snapshot="snap-1",
            target_prefix="dr-tmp-",
            include_indices=["orders"],
        )
        executor = FakeClient(LISTING_BEFORE)
        receipt = execute_restore(executor, plan)
        sent = executor.snapshot.restore_calls[0]
        # Only the approved single index is restorable, regardless of catalog size.
        self.assertEqual(sent["body"]["indices"], ["orders"])
        self.assertEqual(receipt.request, plan.request)

    def test_native_restore_without_preflight_still_available(self):
        # The optional contract must not disable the native snapshot API.
        from test_opensearchpy.test_cases import OpenSearchTestCase

        case = OpenSearchTestCase()
        case.setUp()
        case.client.snapshot.restore(
            repository="repo",
            snapshot="snap-1",
            body={"indices": ["orders"]},
        )
        calls = case.assert_url_called(
            "POST", "/_snapshot/repo/snap-1/_restore"
        )
        self.assertEqual(calls[0][2], {"indices": ["orders"]})

    def test_real_client_helpers_integrate_with_dummy_transport(self):
        from collections import defaultdict

        class BodyTransport:
            def __init__(self, hosts, responses=None, **kwargs):
                self.responses = list(responses or [])
                self.call_count = 0
                self.calls = defaultdict(list)

            def perform_request(
                self, method, url, params=None, body=None, headers=None
            ):
                response = (
                    self.responses.pop(0) if self.responses else {}
                )
                self.call_count += 1
                self.calls[(method, url)].append((params, headers, body))
                return response

        client = OpenSearch(
            transport_class=BodyTransport,
            responses=[LISTING_BEFORE, LISTING_BEFORE, {"accepted": True}],
        )
        plan = plan_restore(
            client,
            repository="repo",
            snapshot="snap-1",
            target_prefix="dr-tmp-",
            include_indices=["orders"],
        )
        receipt = execute_restore(client, plan)
        # One GET (snapshot read) per phase plus one POST restore.
        self.assertEqual(client.transport.call_count, 3)
        self.assertIn(
            ("POST", "/_snapshot/repo/snap-1/_restore"),
            client.transport.calls,
        )
        self.assertEqual(receipt.target_indices, ("dr-tmp-orders",))
