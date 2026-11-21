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

from opensearchpy import TransportError, helpers
from opensearchpy.exceptions import OpenSearchException
from opensearchpy.helpers import BulkIndexError
from opensearchpy.serializer import JSONSerializer


class SyntheticBulkClient:
    """In-memory bulk client that returns canned responses in order."""

    def __init__(
        self,
        responses: List[Dict[str, Any]],
        fail_with: Optional[OpenSearchException] = None,
        fail_times: int = 1,
    ) -> None:
        self.transport = SimpleNamespace(serializer=JSONSerializer())
        self.responses = list(responses)
        self.fail_with = fail_with
        self.fail_times = fail_times
        self.bodies: List[str] = []

    def bulk(self, body: str, *args: Any, **kwargs: Any) -> Dict[str, Any]:
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


def _failure_items() -> Dict[str, Any]:
    return {
        "first": _response(
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
                    "root_cause": [
                        {
                            "type": "mapper_parsing_exception",
                            "reason": "document-body-bad",
                        }
                    ],
                },
            ),
        ),
        "retry": _response(
            _item("index", _index="support-logs", _id="retry-1", status=201)
        ),
    }


def _collect(client: SyntheticBulkClient, **kwargs: Any) -> List[Any]:
    return list(helpers.streaming_bulk(client, _actions(), **kwargs))


def _assert_no_secret(summary: Any) -> None:
    rendered = repr(summary)
    for secret in (
        "document-body",
        "auth-value",
        "password",
        "api_key",
        "token",
        "queue full",
    ):
        assert secret not in rendered


def test_successful_and_retryable_and_final_failures_are_summarized() -> None:
    responses = _failure_items()
    client = SyntheticBulkClient([responses["first"], responses["retry"]])

    results = _collect(
        client,
        chunk_size=10,
        max_retries=1,
        initial_backoff=0,
        raise_on_error=False,
        safe_error_summary=True,
    )

    assert [True, False, True] == [ok for ok, _ in results]
    bad_summary = results[1][1]["index"]
    assert bad_summary["_index"] == "support-logs"
    assert bad_summary["_id"] == "bad-1"
    assert bad_summary["status"] == 400
    assert bad_summary["category"] == "mapper_parsing_exception"
    assert set(bad_summary) == {"_index", "_id", "status", "category"}
    assert results[2][1]["index"]["_id"] == "retry-1"
    _assert_no_secret(results)

    retry_lines = client.bodies[1].strip().split("\n")
    assert len(retry_lines) == 2
    retry_action = client.transport.serializer.loads(retry_lines[0])
    retry_document = client.transport.serializer.loads(retry_lines[1])
    assert retry_action == {"index": {"_index": "support-logs", "_id": "retry-1"}}
    assert retry_document == {
        "message": "document-body-retry",
        "api_key": "auth-value-retry",
    }


def test_safe_summary_does_not_change_retry_payload() -> None:
    normal = SyntheticBulkClient(
        [_failure_items()["first"], _failure_items()["retry"]]
    )
    safe = SyntheticBulkClient([_failure_items()["first"], _failure_items()["retry"]])

    list(
        helpers.streaming_bulk(
            normal,
            _actions(),
            chunk_size=10,
            max_retries=1,
            initial_backoff=0,
            raise_on_error=False,
        )
    )
    list(
        helpers.streaming_bulk(
            safe,
            _actions(),
            chunk_size=10,
            max_retries=1,
            initial_backoff=0,
            raise_on_error=False,
            safe_error_summary=True,
        )
    )

    assert normal.bodies == safe.bodies


def test_safe_summary_with_bulk_returns_minimal_failures() -> None:
    client = SyntheticBulkClient(
        [_response(
            _item("index", _index="support-logs", _id="ok-1", status=201),
            _item(
                "index",
                _index="support-logs",
                _id="bad-1",
                status=400,
                error={
                    "type": "mapper_parsing_exception",
                    "reason": "document-body-bad",
                },
            ),
        )]
    )

    success, failed = helpers.bulk(
        client,
        _actions()[:2],
        raise_on_error=False,
        safe_error_summary=True,
    )

    assert success == 1
    assert len(failed) == 1
    summary = failed[0]["index"]
    assert summary == {
        "_index": "support-logs",
        "_id": "bad-1",
        "status": 400,
        "category": "mapper_parsing_exception",
    }
    _assert_no_secret(failed)


def test_safe_summary_is_used_in_raised_bulk_index_error() -> None:
    client = SyntheticBulkClient(
        [_response(
            _item(
                "index",
                _index="support-logs",
                _id="bad-1",
                status=400,
                error={
                    "type": "mapper_parsing_exception",
                    "reason": "document-body-bad",
                },
            )
        )]
    )

    with pytest.raises(BulkIndexError) as raised:
        list(helpers.streaming_bulk(client, _actions()[:1], safe_error_summary=True))

    assert raised.value.errors == [
        {
            "index": {
                "_index": "support-logs",
                "_id": "bad-1",
                "status": 400,
                "category": "mapper_parsing_exception",
            }
        }
    ]
    _assert_no_secret(raised.value.errors)


def test_safe_summary_for_transport_error_hides_error_text() -> None:
    client = SyntheticBulkClient(
        [],
        fail_with=TransportError(429, "auth-value=top-secret", {"message": "token"}),
    )

    results = _collect(
        client,
        chunk_size=10,
        raise_on_exception=False,
        raise_on_error=False,
        safe_error_summary=True,
    )

    assert [False, False, False] == [ok for ok, _ in results]
    for _, item in results:
        summary = next(iter(item.values()))
        assert summary["status"] == 429
        assert summary["category"] == "too_many_requests"
        assert set(summary) == {"_index", "_id", "status", "category"}
    _assert_no_secret(results)


def test_default_error_shape_still_contains_document() -> None:
    client = SyntheticBulkClient(
        [
            _response(
                _item(
                    "index",
                    _index="support-logs",
                    _id="bad-1",
                    status=400,
                    error={"type": "mapper_parsing_exception", "reason": "bad"},
                )
            )
        ]
    )

    with pytest.raises(BulkIndexError) as raised:
        list(helpers.streaming_bulk(client, _actions()[:1]))

    assert raised.value.errors[0]["index"]["data"]["message"] == "document-body-ok"


def test_retryable_transport_error_is_retried_with_original_payload() -> None:
    response = _response(
        _item("index", _index="support-logs", _id="retry-1", status=201)
    )
    client = SyntheticBulkClient(
        [response], fail_with=TransportError(429, "Rejected!", {})
    )

    results = list(
        helpers.streaming_bulk(
            client,
            [_actions()[1]],
            chunk_size=10,
            max_retries=1,
            initial_backoff=0,
            raise_on_exception=False,
            raise_on_error=False,
            safe_error_summary=True,
        )
    )

    assert [True] == [ok for ok, _ in results]
    assert len(client.bodies) == 2
    assert client.transport.serializer.loads(
        client.bodies[1].strip().split("\n")[1]
    ) == {"message": "document-body-retry", "api_key": "auth-value-retry"}
