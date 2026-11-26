"""
BatchCheck tests against an in-memory OpenFGA endpoint.

The endpoint is stateful and deliberately hostile:

* the same object is checked twice for different users/relations,
* results for each request are returned in reverse order,
* configured failures land in the middle of a multi-batch run,
* the server omits a correlation_id until it is retried (or forever).

These tests assert that the synchronous and asynchronous clients pair every
decision with the original user/object/relation request, retry only the checks
without an authoritative result, and report checks that cannot be confirmed as
unconfirmed instead of silently treating them as denials.
"""

import json

from unittest import IsolatedAsyncioTestCase, TestCase

import urllib3

from openfga_sdk import rest
from openfga_sdk.client import ClientConfiguration
from openfga_sdk.client.client import OpenFgaClient
from openfga_sdk.client.models.batch_check_item import ClientBatchCheckItem
from openfga_sdk.client.models.batch_check_request import ClientBatchCheckRequest
from openfga_sdk.configuration import RetryParams
from openfga_sdk.exceptions import ServiceException, UnauthorizedException
from openfga_sdk.sync import rest as sync_rest
from openfga_sdk.sync.client.client import OpenFgaClient as SyncOpenFgaClient


STORE_ID = "01YCP46JKYM8FJCQ37NMBYHE5X"
AUTHORIZATION_MODEL_ID = "01GXSA8YR785C4FYS3C0RTG7B1"
BATCH_CHECK_PATH = f"/stores/{STORE_ID}/batch-check"


# Authorization source of truth. document:budget is granted twice under
# different users and relations, so a shifted result shows up as a wrong
# permission rather than an empty answer.
ALLOWED_RELATIONSHIPS = {
    ("user:anne", "reader", "document:budget"),
    ("user:bob", "editor", "document:budget"),
    ("user:carol", "reader", "document:budget"),
}


def _decision(user, relation, obj):
    return (user, relation, obj) in ALLOWED_RELATIONSHIPS


def _http_response(payload, status=200):
    headers = urllib3.response.HTTPHeaderDict({"content-type": "application/json"})
    body = json.dumps(payload).encode("utf-8")
    return urllib3.HTTPResponse(body, headers, status, preload_content=False)


def _as_body(body):
    return body if isinstance(body, dict) else json.loads(body)


def _failure(status, reason):
    response = _http_response({"code": "internal_error", "message": reason}, status)
    if status == 401:
        return UnauthorizedException(http_resp=response)
    return ServiceException(http_resp=response)


class InMemoryBatchCheckServer:
    """
    Minimal, deterministic OpenFGA BatchCheck server.

    ``failures`` maps a call number (1-based) to either an HTTP failure raised
    for the whole request, or a ``correlation_id`` dropped from that response so
    the SDK has to retry it. ``transient`` maps a correlation_id to the number of
    responses that should report a retryable internal error for it.
    ``always_omit`` drops ids from every response.
    """

    def __init__(
        self, *, reverse=True, failures=None, transient=None, always_omit=None
    ):
        self.reverse = reverse
        self.failures = failures or {}
        self.transient = dict(transient or {})
        self.always_omit = set(always_omit or ())
        self.calls = []

    def respond(self, body):
        checks = body["checks"]
        call_number = len(self.calls) + 1
        self.calls.append([check["correlation_id"] for check in checks])

        failure = self.failures.get(call_number)
        if isinstance(failure, Exception):
            raise failure
        drop_id = failure if isinstance(failure, str) else None

        result = {}
        ordered = list(reversed(checks)) if self.reverse else list(checks)
        for check in ordered:
            correlation_id = check["correlation_id"]
            if correlation_id == drop_id or correlation_id in self.always_omit:
                continue
            if self.transient.get(correlation_id, 0) > 0:
                self.transient[correlation_id] -= 1
                result[correlation_id] = {
                    "error": {
                        "internal_error": "unavailable",
                        "message": "server overloaded",
                    }
                }
                continue
            tuple_key = check["tuple_key"]
            result[correlation_id] = {
                "allowed": _decision(
                    tuple_key["user"], tuple_key["relation"], tuple_key["object"]
                )
            }
        return {"result": result}


class _FakeAsyncRest:
    def __init__(self, server):
        self.server = server

    async def request(
        self,
        method,
        url,
        query_params=None,
        headers=None,
        body=None,
        post_params=None,
        _preload_content=True,
        _request_timeout=None,
        _streaming=False,
    ):
        assert method == "POST" and url.endswith(BATCH_CHECK_PATH), (method, url)
        payload = self.server.respond(_as_body(body))
        response = _http_response(payload)
        return rest.RESTResponse(response, response.data)

    async def close(self):
        pass


class _FakeSyncRest:
    def __init__(self, server):
        self.server = server

    def request(
        self,
        method,
        url,
        query_params=None,
        headers=None,
        body=None,
        post_params=None,
        _preload_content=True,
        _request_timeout=None,
        _streaming=False,
    ):
        assert method == "POST" and url.endswith(BATCH_CHECK_PATH), (method, url)
        payload = self.server.respond(_as_body(body))
        response = _http_response(payload)
        return sync_rest.RESTResponse(response, response.data)

    def close(self):
        pass


def _checks():
    return [
        ClientBatchCheckItem(
            user="user:anne",
            relation="reader",
            object="document:budget",
            correlation_id="anne-reader",
        ),
        ClientBatchCheckItem(
            user="user:bob",
            relation="editor",
            object="document:budget",
            correlation_id="bob-editor",
        ),
        ClientBatchCheckItem(
            user="user:carol",
            relation="reader",
            object="document:budget",
            correlation_id="carol-reader",
        ),
        ClientBatchCheckItem(
            user="user:dave",
            relation="reader",
            object="document:budget",
            correlation_id="dave-reader",
        ),
    ]


def _by_id(response):
    return {item.correlation_id: item for item in response.result}


def assert_identity_consistent(test_case, response):
    """Every confirmed decision must belong to the request it is attached to."""
    for item in response.result:
        if not item.confirmed:
            continue
        request = item.request
        expected = _decision(request.user, request.relation, request.object)
        test_case.assertEqual(
            item.allowed,
            expected,
            f"{item.correlation_id} got allowed={item.allowed} for "
            f"{request.user}/{request.relation}/{request.object}",
        )


def _configuration():
    return ClientConfiguration(
        api_url="http://api.fga.example",
        store_id=STORE_ID,
        retry_params=RetryParams(max_retry=3, min_wait_in_ms=1),
    )


class TestAsyncBatchCheckInMemory(IsolatedAsyncioTestCase):
    async def _run(self, server, options=None):
        client = OpenFgaClient(_configuration())
        client._api_client.rest_client = _FakeAsyncRest(server)
        try:
            return await client.batch_check(
                ClientBatchCheckRequest(checks=_checks()),
                {"authorization_model_id": AUTHORIZATION_MODEL_ID, **(options or {})},
            )
        finally:
            await client.close()

    async def test_out_of_order_results_keep_request_identity(self):
        response = await self._run(InMemoryBatchCheckServer())

        self.assertEqual(
            [item.correlation_id for item in response.result],
            ["anne-reader", "bob-editor", "carol-reader", "dave-reader"],
        )
        assert_identity_consistent(self, response)

    async def test_transient_batch_failure_only_retries_failed_batch(self):
        # max_batch_size=2 sends [anne, bob] then [carol, dave]; the second
        # batch fails once with a 500 and must be retried by itself.
        server = InMemoryBatchCheckServer(failures={2: _failure(500, "boom")})
        response = await self._run(
            server, {"max_batch_size": 2, "max_parallel_requests": 1}
        )

        self.assertEqual(
            server.calls,
            [
                ["anne-reader", "bob-editor"],
                ["carol-reader", "dave-reader"],
                ["carol-reader", "dave-reader"],
            ],
        )
        assert_identity_consistent(self, response)
        self.assertTrue(all(item.confirmed for item in response.result))

    async def test_missing_item_is_retried_without_losing_confirmed_items(self):
        # anne's result is missing on the first call only. bob/carol/dave from
        # the first response must be kept; only anne is retried.
        server = InMemoryBatchCheckServer(failures={1: "anne-reader"})
        response = await self._run(server, {"max_batch_size": 4})

        self.assertEqual(
            server.calls,
            [
                ["anne-reader", "bob-editor", "carol-reader", "dave-reader"],
                ["anne-reader"],
            ],
        )
        assert_identity_consistent(self, response)

    async def test_persistent_missing_item_is_explicitly_unconfirmed(self):
        server = InMemoryBatchCheckServer(always_omit={"dave-reader"})
        response = await self._run(server, {"max_batch_size": 4, "max_retries": 1})

        dave = _by_id(response)["dave-reader"]
        self.assertFalse(dave.confirmed)
        self.assertFalse(dave.allowed)
        self.assertIn("No authoritative result", dave.error.message)
        for correlation_id in ("anne-reader", "bob-editor", "carol-reader"):
            self.assertTrue(_by_id(response)[correlation_id].confirmed)
        assert_identity_consistent(self, response)

    async def test_transport_error_retries_only_the_affected_batch(self):
        class FlakySecondBatch(_FakeAsyncRest):
            def __init__(self, server):
                super().__init__(server)
                self.requests = 0

            async def request(self, *args, **kwargs):
                self.requests += 1
                if self.requests == 2:
                    raise ConnectionError("connection reset")
                return await super().request(*args, **kwargs)

        server = InMemoryBatchCheckServer()
        transport = FlakySecondBatch(server)
        client = OpenFgaClient(_configuration())
        client._api_client.rest_client = transport
        try:
            response = await client.batch_check(
                ClientBatchCheckRequest(checks=_checks()),
                {
                    "authorization_model_id": AUTHORIZATION_MODEL_ID,
                    "max_batch_size": 2,
                    "max_parallel_requests": 1,
                },
            )
        finally:
            await client.close()

        # The first batch succeeded and was not re-sent; only the failed second
        # batch was retried after the transport error.
        self.assertEqual(
            server.calls,
            [["anne-reader", "bob-editor"], ["carol-reader", "dave-reader"]],
        )
        self.assertEqual(transport.requests, 3)
        self.assertTrue(all(item.confirmed for item in response.result))
        assert_identity_consistent(self, response)

    async def test_exhausted_transport_error_leaves_checks_unconfirmed(self):
        class AlwaysFails(_FakeAsyncRest):
            async def request(self, *args, **kwargs):
                raise ConnectionError("still down")

        client = OpenFgaClient(_configuration())
        client._api_client.rest_client = AlwaysFails(InMemoryBatchCheckServer())
        try:
            response = await client.batch_check(
                ClientBatchCheckRequest(checks=_checks()),
                {
                    "authorization_model_id": AUTHORIZATION_MODEL_ID,
                    "max_batch_size": 4,
                    "max_retries": 0,
                },
            )
        finally:
            await client.close()

        self.assertEqual(len(response.result), 4)
        for item in response.result:
            self.assertFalse(item.confirmed)
            self.assertFalse(item.allowed)
            self.assertIn("ConnectionError", item.error.message)

    async def test_per_item_transient_error_retries_only_that_check(self):
        server = InMemoryBatchCheckServer(transient={"bob-editor": 1})
        response = await self._run(server, {"max_batch_size": 4, "max_retries": 2})

        self.assertEqual(
            server.calls,
            [
                ["anne-reader", "bob-editor", "carol-reader", "dave-reader"],
                ["bob-editor"],
            ],
        )
        self.assertTrue(all(item.confirmed for item in response.result))
        assert_identity_consistent(self, response)

    async def test_non_retryable_auth_failure_propagates(self):
        server = InMemoryBatchCheckServer(failures={2: _failure(401, "nope")})
        with self.assertRaises(UnauthorizedException):
            await self._run(server, {"max_batch_size": 2, "max_parallel_requests": 1})


class TestSyncBatchCheckInMemory(TestCase):
    def _run(self, server, options=None):
        client = SyncOpenFgaClient(_configuration())
        client._api_client.rest_client = _FakeSyncRest(server)
        try:
            return client.batch_check(
                ClientBatchCheckRequest(checks=_checks()),
                {"authorization_model_id": AUTHORIZATION_MODEL_ID, **(options or {})},
            )
        finally:
            client.close()

    def test_out_of_order_results_keep_request_identity(self):
        response = self._run(InMemoryBatchCheckServer())

        self.assertEqual(
            [item.correlation_id for item in response.result],
            ["anne-reader", "bob-editor", "carol-reader", "dave-reader"],
        )
        assert_identity_consistent(self, response)

    def test_transient_batch_failure_only_retries_failed_batch(self):
        server = InMemoryBatchCheckServer(failures={2: _failure(500, "boom")})
        response = self._run(server, {"max_batch_size": 2, "max_parallel_requests": 1})

        self.assertEqual(
            server.calls,
            [
                ["anne-reader", "bob-editor"],
                ["carol-reader", "dave-reader"],
                ["carol-reader", "dave-reader"],
            ],
        )
        assert_identity_consistent(self, response)

    def test_missing_item_is_retried_without_losing_confirmed_items(self):
        server = InMemoryBatchCheckServer(failures={1: "bob-editor"})
        response = self._run(server, {"max_batch_size": 4})

        self.assertEqual(
            server.calls,
            [
                ["anne-reader", "bob-editor", "carol-reader", "dave-reader"],
                ["bob-editor"],
            ],
        )
        assert_identity_consistent(self, response)

    def test_persistent_missing_item_is_explicitly_unconfirmed(self):
        server = InMemoryBatchCheckServer(always_omit={"carol-reader"})
        response = self._run(server, {"max_batch_size": 4, "max_retries": 1})

        carol = _by_id(response)["carol-reader"]
        self.assertFalse(carol.confirmed)
        self.assertFalse(carol.allowed)
        self.assertIn("No authoritative result", carol.error.message)
        assert_identity_consistent(self, response)

    def test_per_item_transient_error_retries_only_that_check(self):
        server = InMemoryBatchCheckServer(transient={"dave-reader": 1})
        response = self._run(server, {"max_batch_size": 4, "max_retries": 2})

        self.assertEqual(
            server.calls,
            [
                ["anne-reader", "bob-editor", "carol-reader", "dave-reader"],
                ["dave-reader"],
            ],
        )
        self.assertTrue(all(item.confirmed for item in response.result))
        assert_identity_consistent(self, response)

    def test_non_retryable_auth_failure_propagates(self):
        server = InMemoryBatchCheckServer(failures={2: _failure(401, "nope")})
        with self.assertRaises(UnauthorizedException):
            self._run(server, {"max_batch_size": 2, "max_parallel_requests": 1})
