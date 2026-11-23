# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.

from collections import defaultdict
from typing import Any, Mapping, Optional

import pytest

from opensearchpy import AsyncOpenSearch, ApprovalStaleError
from opensearchpy._async.helpers.restore import (
    async_execute_restore,
    async_plan_restore,
    async_revalidate_restore,
)
from opensearchpy._async.transport import AsyncTransport

pytestmark = pytest.mark.asyncio


def _listing(name, uuid, indices):
    return {
        "snapshots": [
            {
                "snapshot": name,
                "uuid": uuid,
                "version": "2.15.0",
                "state": "SUCCESS",
                "indices": list(indices),
            }
        ]
    }


LISTING_BEFORE = _listing("snap-1", "uuid-1", ["orders", "logs", "billing"])
LISTING_AFTER = _listing("snap-1", "uuid-1", ["orders", "logs-2026", "billing"])


class ScriptedAsyncTransport(AsyncTransport):
    """Returns queued responses in order and records every transport request."""

    def __init__(self, hosts: Any, responses: Any = None, **kwargs: Any) -> None:
        self.hosts = hosts
        self.responses = list(responses or [])
        self.call_count = 0
        self.calls: Any = defaultdict(list)

    async def perform_request(
        self,
        method: str,
        url: str,
        params: Optional[Mapping[str, Any]] = None,
        body: Optional[bytes] = None,
        timeout: Optional[Any] = None,
        ignore: Any = (),
        headers: Optional[Mapping[str, str]] = None,
    ) -> Any:
        response = (
            self.responses.pop(0)
            if self.responses
            else {}
        )
        self.call_count += 1
        self.calls[(method, url)].append((params, headers, body))
        return response


def _client(responses):
    return AsyncOpenSearch(
        transport_class=ScriptedAsyncTransport, responses=responses
    )


class TestAsyncRestoreContract:
    async def test_preflight_then_execute_uses_frozen_request(self):
        client = _client([LISTING_BEFORE, LISTING_BEFORE])
        plan = await async_plan_restore(
            client,
            repository="repo",
            snapshot="snap-1",
            target_prefix="dr-tmp-",
            include_indices=["orders", "logs"],
        )
        assert plan.target_indices == ("dr-tmp-orders", "dr-tmp-logs")

        receipt = await async_execute_restore(client, plan)

        restore_url = ("POST", "/_snapshot/repo/snap-1/_restore")
        assert restore_url in client.transport.calls
        restore_calls = client.transport.calls[restore_url]
        assert len(restore_calls) == 1
        sent_body = restore_calls[0][2]
        assert sent_body == plan.request.body
        assert sent_body["indices"] == ["orders", "logs"]
        assert [(m.source, m.target) for m in receipt.mappings] == [
            ("orders", "dr-tmp-orders"),
            ("logs", "dr-tmp-logs"),
        ]
        # Two snapshot GETs (plan + execute) and one restore POST.
        assert client.transport.call_count == 3

    async def test_stale_approval_sends_no_restore_request(self):
        client = _client([LISTING_BEFORE])
        plan = await async_plan_restore(
            client,
            repository="repo",
            snapshot="snap-1",
            target_prefix="dr-tmp-",
            exclude_indices=["billing"],
        )

        changed = _client([LISTING_AFTER, LISTING_AFTER])
        reasons = await async_revalidate_restore(changed, plan)
        assert reasons
        assert any("logs" in reason for reason in reasons)

        with pytest.raises(ApprovalStaleError):
            await async_execute_restore(changed, plan)

        restore_url = ("POST", "/_snapshot/repo/snap-1/_restore")
        assert restore_url not in changed.transport.calls
        # Two catalog GETs (revalidate + blocked execute) and no restore POST.
        assert changed.transport.call_count == 2

    async def test_async_and_sync_approve_identical_parameters(self):
        from opensearchpy.helpers import plan_restore as sync_plan_restore

        class _SyncSnapshot:
            def get(self, repository, snapshot):
                return LISTING_BEFORE

        class _SyncClient:
            snapshot = _SyncSnapshot()

        sync_plan = sync_plan_restore(
            _SyncClient(),
            repository="repo",
            snapshot="snap-1",
            target_prefix="dr-tmp-",
            include_indices=["orders", "logs"],
        )

        client = _client([LISTING_BEFORE])
        async_plan = await async_plan_restore(
            client,
            repository="repo",
            snapshot="snap-1",
            target_prefix="dr-tmp-",
            include_indices=["orders", "logs"],
        )

        assert async_plan.fingerprint == sync_plan.fingerprint
        assert async_plan.request.body == sync_plan.request.body
        assert async_plan.target_indices == sync_plan.target_indices
