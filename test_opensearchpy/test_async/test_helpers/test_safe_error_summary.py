# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.


from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import pytest

from opensearchpy import TransportError
from opensearchpy._async.helpers import actions as async_helpers
from opensearchpy.helpers import BulkIndexError
from opensearchpy.serializer import JSONSerializer

pytestmark = pytest.mark.asyncio


class AsyncSyntheticBulkClient:
    def __init__(
        self,
        responses: List[Dict[str, Any]],
        fail_with: Optional[TransportError] = None,
        fail_times: int = 1,
    ) -> None:
        self.transport = SimpleNamespace(serializer=JSONSerializer())
        self.responses = list(responses)
        self.fail_with = fail_with
        self.fail_times = fail_times
        self.bodies: List[str] = []

    async def bulk(self, body: str, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        self.bodies.append(body)
        if self.fail_with is not None and len(self.bodies) <= self.fail_times:
            raise self.fail_with
        return self.responses.pop(0)


def _item(op_type: str, **fields: Any) -> Dict[str, Any]:
    return {op_type: fields}


def _response(*items: Dict[str, Any]) -> Dict[str, Any]:
    return {"items": list(items)}


def _actions() -> List[Dict[str, Any]]:
    return [
        {
            "_index": "support-logs",
            "_id": "ok-1",
            "message": "document-body-ok",
            "password": "auth-value-ok",
        },
        {
            "_index": "support-logs",
            "_id": "retry-1",
            "message": "document-body-retry",
            "api_key": "auth-value-retry",
        },
        {
            "_index": "support-logs",
            "_id": "bad-1",
            "message": "document-body-bad",
            "token": "auth-value-bad",
        },
    ]


def _responses() -> List[Dict[str, Any]]:
    return [
        _response(
            _item("index", _index="support-logs", _id="ok-1", status=201),
            _item(
                "index",
                _index="support-logs",
                _id="retry-1",
                status=429,
                error={
                    "type": "es_rejected_execution_exception",
                    "reason": "queue full",
                },
            ),
            _item(
                "index",
                _index="support-logs",
                _id="bad-1",
                status=400,
                error={
                    "type": "mapper_parsing_exception",
                    "reason": "failed to parse document-body-bad",
                },
            ),
        ),
        _response(_item("index", _index="support-logs", _id="retry-1", status=201)),
    ]


def _assert_no_secret(values: Any) -> None:
    rendered = repr(values)
    for secret in (
        "document-body",
        "auth-value",
        "password",
        "api_key",
        "token",
        "queue full",
    ):
        assert secret not in rendered


async def _collect(client: Any, **kwargs: Any) -> List[Any]:
    results = []
    async for result in async_helpers.async_streaming_bulk(
        client, _actions(), **kwargs
    ):
        results.append(result)
    return results


async def test_async_success_retry_and_final_failure() -> None:
    client = AsyncSyntheticBulkClient(_responses())

    results = await _collect(
        client,
        chunk_size=10,
        max_retries=1,
        initial_backoff=0,
        raise_on_error=False,
        safe_error_summary=True,
    )

    assert [True, False, True] == [ok for ok, _ in results]
    assert results[1][1]["index"] == {
        "_index": "support-logs",
        "_id": "bad-1",
        "status": 400,
        "category": "mapper_parsing_exception",
    }
    assert results[2][1]["index"]["_id"] == "retry-1"
    _assert_no_secret(results)

    retry_lines = client.bodies[1].strip().split("\n")
    assert client.transport.serializer.loads(retry_lines[0]) == {
        "index": {"_index": "support-logs", "_id": "retry-1"}
    }
    assert client.transport.serializer.loads(retry_lines[1]) == {
        "message": "document-body-retry",
        "api_key": "auth-value-retry",
    }


async def test_async_retry_payload_matches_normal_usage() -> None:
    normal = AsyncSyntheticBulkClient(_responses())
    safe = AsyncSyntheticBulkClient(_responses())

    await _collect(
        normal, chunk_size=10, max_retries=1, initial_backoff=0, raise_on_error=False
    )
    await _collect(
        safe,
        chunk_size=10,
        max_retries=1,
        initial_backoff=0,
        raise_on_error=False,
        safe_error_summary=True,
    )

    assert normal.bodies == safe.bodies


async def test_async_bulk_returns_minimal_summaries() -> None:
    client = AsyncSyntheticBulkClient(_responses())

    success, failed = await async_helpers.async_bulk(
        client,
        _actions()[:2],
        raise_on_error=False,
        safe_error_summary=True,
    )

    assert success == 1
    assert failed == [
        {
            "index": {
                "_index": "support-logs",
                "_id": "retry-1",
                "status": 429,
                "category": "es_rejected_execution_exception",
            }
        }
    ]
    _assert_no_secret(failed)


async def test_async_raised_error_is_minimal() -> None:
    client = AsyncSyntheticBulkClient(_responses())

    with pytest.raises(BulkIndexError) as raised:
        await _collect(client, safe_error_summary=True)

    summaries = raised.value.errors
    assert len(summaries) == 2
    assert summaries[0]["index"]["_id"] == "retry-1"
    assert summaries[1]["index"]["_id"] == "bad-1"
    assert all(
        set(entry["index"]) == {"_index", "_id", "status", "category"}
        for entry in summaries
    )
    _assert_no_secret(summaries)


async def test_async_transport_failure_is_minimal() -> None:
    client = AsyncSyntheticBulkClient(
        [], fail_with=TransportError(503, "auth-value=top-secret", {})
    )

    results = await _collect(
        client,
        chunk_size=10,
        raise_on_exception=False,
        raise_on_error=False,
        safe_error_summary=True,
    )

    assert [False, False, False] == [ok for ok, _ in results]
    assert all(
        next(iter(item.values()))["category"] == "server_error"
        for _, item in results
    )
    _assert_no_secret(results)


async def test_async_retryable_transport_error_keeps_original_payload() -> None:
    response = _response(
        _item("index", _index="support-logs", _id="retry-1", status=201)
    )
    client = AsyncSyntheticBulkClient(
        [response], fail_with=TransportError(429, "Rejected!", {})
    )

    results = []
    async for result in async_helpers.async_streaming_bulk(
        client,
        [_actions()[1]],
        chunk_size=10,
        max_retries=1,
        initial_backoff=0,
        raise_on_exception=False,
        raise_on_error=False,
        safe_error_summary=True,
    ):
        results.append(result)

    assert [True] == [ok for ok, _ in results]
    assert len(client.bodies) == 2
    assert client.transport.serializer.loads(
        client.bodies[1].strip().split("\n")[1]
    ) == {"message": "document-body-retry", "api_key": "auth-value-retry"}
