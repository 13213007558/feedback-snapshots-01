import asyncio
import re
import urllib3

from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, patch

from openfga_sdk import rest
from openfga_sdk.client.models.check_request import ClientCheckRequest
from openfga_sdk.client.models.tuple import ClientTuple
from openfga_sdk.client.models.write_request import ClientWriteRequest
from openfga_sdk.credentials import CredentialConfiguration, Credentials
from openfga_sdk.exceptions import ServiceException
from openfga_sdk.store_rotation import (
    PendingWritePolicy,
    QueryRetryPolicy,
    StaleWriteGenerationError,
    StoreRotationCoordinator,
    StoreProfile,
)


STORE_A = "01YCP46JKYM8FJCQ37NMBYHE5X"
STORE_B = "01YCP46JKYM8FJCQ37NMBYHE6X"
MODEL_A = "01G5JAVJ41T49E9TT3SKVS7X1J"
MODEL_B = "01G5JAVJ41T49E9TT3SKVS7X2J"


def mock_response(body: str, status: int):
    headers = urllib3.response.HTTPHeaderDict({"content-type": "application/json"})
    response = urllib3.HTTPResponse(
        body.encode("utf-8"), headers, status, preload_content=False
    )
    return rest.RESTResponse(response, response.data)


def api_token(token: str) -> Credentials:
    return Credentials(
        method="api_token",
        configuration=CredentialConfiguration(api_token=token),
    )


def profile(store: str, model: str, token: str, name: str) -> StoreProfile:
    return StoreProfile(
        name=name,
        api_url="http://fake.openfga",
        store_id=store,
        authorization_model_id=model,
        credentials=api_token(token),
        auth_label=f"auth-{name}",
    )


PROFILE_A = profile(STORE_A, MODEL_A, "token-A", "A")
PROFILE_B = profile(STORE_B, MODEL_B, "token-B", "B")


class FakeEndpoint:
    def __init__(self, mock_request: AsyncMock):
        self.mock_request = mock_request
        self.observations: list[dict[str, object]] = []
        mock_request.side_effect = self.handle

    async def handle(self, method: str, url: str, **kwargs):
        headers = {
            str(key).lower(): str(value)
            for key, value in (kwargs.get("headers") or {}).items()
        }
        body = kwargs.get("body") or {}
        match = re.search(r"/stores/([^/]+)/(check|write)", url)
        store_id = match.group(1) if match else None
        operation = match.group(2) if match else "other"
        observation = {
            "method": method,
            "url": url,
            "store": store_id,
            "operation": operation,
            "model": (
                body.get("authorization_model_id")
                if isinstance(body, dict)
                else None
            ),
            "authorization": headers.get("authorization"),
            "body": body,
        }
        self.observations.append(observation)

        if operation == "check":
            store_checks = [
                item for item in self.observations if item["operation"] == "check"
            ]
            if store_id == STORE_A and len(store_checks) == 1:
                error = ServiceException(status=500, reason="temporary")
                error.body = b'{"code":"internal_error"}'
                error.header = {}
                raise error
            return mock_response('{"allowed":true}', 200)

        if operation == "write":
            return mock_response("{}", 200)

        raise AssertionError(f"unexpected request: {method} {url}")

    def for_store(self, store_id: str) -> list[dict[str, object]]:
        return [item for item in self.observations if item["store"] == store_id]

    def for_operation(self, operation: str) -> list[dict[str, object]]:
        return [item for item in self.observations if item["operation"] == operation]


def check_body() -> ClientCheckRequest:
    return ClientCheckRequest(
        user="user:anne",
        relation="viewer",
        object="document:roadmap",
    )


def write_body() -> ClientWriteRequest:
    return ClientWriteRequest(
        writes=[
            ClientTuple(
                user="user:anne",
                relation="viewer",
                object="document:roadmap",
            )
        ]
    )


class StoreRotationContractTest(IsolatedAsyncioTestCase):
    @patch.object(rest.RESTClientObject, "request", new_callable=AsyncMock)
    async def test_switch_is_atomic_and_superseded_write_is_fenced(
        self, mock_request: AsyncMock
    ):
        endpoint = FakeEndpoint(mock_request)
        coordinator = StoreRotationCoordinator()
        generation_a = coordinator.approve(PROFILE_A)

        retry_started = asyncio.Event()
        release_retry = asyncio.Event()

        async def before_query_retry(decision):
            retry_started.set()
            await release_retry.wait()

        query_task = asyncio.create_task(
            coordinator.check(check_body(), before_retry=before_query_retry)
        )
        await retry_started.wait()
        self.assertEqual(coordinator.in_flight_query_count, 1)
        self.assertEqual(coordinator.active_queries[0].generation, 1)
        self.assertEqual(coordinator.active_queries[0].status, "retry_waiting")

        write_started = asyncio.Event()
        release_write = asyncio.Event()

        async def before_write_send(ticket):
            write_started.set()
            await release_write.wait()

        ticket = coordinator.enqueue_write(
            write_body(), options={"authorization_model_id": MODEL_A}
        )
        write_task = asyncio.create_task(
            coordinator.send_next_write(before_send=before_write_send)
        )
        await write_started.wait()

        generation_b = coordinator.approve(PROFILE_B)
        new_query = await coordinator.check(check_body())
        self.assertTrue(new_query.allowed)

        release_write.set()
        with self.assertRaises(StaleWriteGenerationError):
            await write_task

        release_retry.set()
        old_query = await query_task
        self.assertTrue(old_query.allowed)
        self.assertEqual(coordinator.in_flight_query_count, 0)

        replacement = coordinator.enqueue_write(
            write_body(), options={"authorization_model_id": MODEL_B}
        )
        await coordinator.send_write(replacement)

        self.assertEqual(generation_a.number, 1)
        self.assertEqual(generation_b.number, 2)

        a_checks = [
            item
            for item in endpoint.for_store(STORE_A)
            if item["operation"] == "check"
        ]
        b_checks = [
            item
            for item in endpoint.for_store(STORE_B)
            if item["operation"] == "check"
        ]
        writes = endpoint.for_operation("write")

        self.assertEqual(len(a_checks), 2)
        self.assertEqual(len(b_checks), 1)
        self.assertEqual(len(writes), 1)
        self.assertEqual(mock_request.call_count, 4)

        for observation in a_checks:
            self.assertEqual(observation["model"], MODEL_A)
            self.assertEqual(observation["authorization"], "Bearer token-A")
        for observation in b_checks:
            self.assertEqual(observation["model"], MODEL_B)
            self.assertEqual(observation["authorization"], "Bearer token-B")
        self.assertEqual(writes[0]["store"], STORE_B)
        self.assertEqual(writes[0]["model"], MODEL_B)
        self.assertEqual(writes[0]["authorization"], "Bearer token-B")

        retry_decisions = [
            item
            for item in coordinator.decisions
            if item.kind == "query_retry" and item.action == "retry_pinned"
        ]
        fence_decisions = [
            item
            for item in coordinator.decisions
            if item.kind == "write_dispatch" and item.action == "fence_superseded"
        ]
        self.assertEqual(len(retry_decisions), 1)
        self.assertEqual(retry_decisions[0].generation, 1)
        self.assertEqual(retry_decisions[0].current_generation, 2)
        self.assertEqual(retry_decisions[0].policy, "pin_to_approved_generation")
        self.assertEqual(len(fence_decisions), 1)
        self.assertFalse(fence_decisions[0].allowed)
        self.assertEqual(fence_decisions[0].ticket_id, ticket.ticket_id)
        self.assertEqual(ticket.status, "fenced")

        await coordinator.aclose()

    @patch.object(rest.RESTClientObject, "request", new_callable=AsyncMock)
    async def test_pinned_query_and_write_keep_original_approval(
        self, mock_request: AsyncMock
    ):
        endpoint = FakeEndpoint(mock_request)
        coordinator = StoreRotationCoordinator(
            write_policy=PendingWritePolicy.PIN_TO_APPROVED_GENERATION
        )
        coordinator.approve(PROFILE_A)

        retry_started = asyncio.Event()
        release_retry = asyncio.Event()

        async def before_retry(decision):
            retry_started.set()
            await release_retry.wait()

        query_task = asyncio.create_task(
            coordinator.check(check_body(), before_retry=before_retry)
        )
        await retry_started.wait()

        send_started = asyncio.Event()
        release_send = asyncio.Event()

        async def before_send(ticket):
            send_started.set()
            await release_send.wait()

        ticket = coordinator.enqueue_write(write_body())
        write_task = asyncio.create_task(
            coordinator.send_write(ticket, before_send=before_send)
        )
        await send_started.wait()

        coordinator.approve(PROFILE_B)
        new_query = await coordinator.check(check_body())
        self.assertTrue(new_query.allowed)

        release_send.set()
        await write_task
        release_retry.set()
        old_query = await query_task
        self.assertTrue(old_query.allowed)

        a_checks = [
            item
            for item in endpoint.for_store(STORE_A)
            if item["operation"] == "check"
        ]
        a_writes = [
            item
            for item in endpoint.for_store(STORE_A)
            if item["operation"] == "write"
        ]
        b_checks = [
            item
            for item in endpoint.for_store(STORE_B)
            if item["operation"] == "check"
        ]
        self.assertEqual(len(a_checks), 2)
        self.assertEqual(len(a_writes), 1)
        self.assertEqual(len(b_checks), 1)
        self.assertEqual(mock_request.call_count, 4)
        self.assertEqual(a_writes[0]["model"], MODEL_A)
        self.assertEqual(a_writes[0]["authorization"], "Bearer token-A")

        pinned_writes = [
            item for item in coordinator.decisions if item.action == "send_pinned"
        ]
        pinned_retries = [
            item for item in coordinator.decisions if item.action == "retry_pinned"
        ]
        self.assertEqual(len(pinned_writes), 1)
        self.assertEqual(len(pinned_retries), 1)
        self.assertEqual(pinned_writes[0].current_generation, 2)
        self.assertEqual(pinned_retries[0].current_generation, 2)
        await coordinator.aclose()

    @patch.object(rest.RESTClientObject, "request", new_callable=AsyncMock)
    async def test_pin_write_policy_sends_original_approval(
        self, mock_request: AsyncMock
    ):
        endpoint = FakeEndpoint(mock_request)
        coordinator = StoreRotationCoordinator(
            write_policy=PendingWritePolicy.PIN_TO_APPROVED_GENERATION
        )
        coordinator.approve(PROFILE_A)

        started = asyncio.Event()
        release = asyncio.Event()

        async def before_send(ticket):
            started.set()
            await release.wait()

        ticket = coordinator.enqueue_write(write_body())
        task = asyncio.create_task(
            coordinator.send_write(ticket, before_send=before_send)
        )
        await started.wait()

        coordinator.approve(PROFILE_B)
        release.set()
        await task

        writes = endpoint.for_operation("write")
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0]["store"], STORE_A)
        self.assertEqual(writes[0]["model"], MODEL_A)
        self.assertEqual(writes[0]["authorization"], "Bearer token-A")

        decision = [
            item
            for item in coordinator.decisions
            if item.action == "send_pinned"
        ]
        self.assertEqual(len(decision), 1)
        self.assertEqual(decision[0].policy, "pin_to_approved_generation")
        await coordinator.aclose()

    @patch.object(rest.RESTClientObject, "request", new_callable=AsyncMock)
    async def test_rebase_write_policy_uses_current_approval(
        self, mock_request: AsyncMock
    ):
        endpoint = FakeEndpoint(mock_request)
        coordinator = StoreRotationCoordinator(
            write_policy=PendingWritePolicy.REBASE_TO_CURRENT_GENERATION
        )
        coordinator.approve(PROFILE_A)

        started = asyncio.Event()
        release = asyncio.Event()

        async def before_send(ticket):
            started.set()
            await release.wait()

        ticket = coordinator.enqueue_write(
            write_body(), options={"authorization_model_id": MODEL_A}
        )
        task = asyncio.create_task(
            coordinator.send_write(ticket, before_send=before_send)
        )
        await started.wait()

        coordinator.approve(PROFILE_B)
        release.set()
        await task

        writes = endpoint.for_operation("write")
        self.assertEqual(len(writes), 1)
        self.assertEqual(writes[0]["store"], STORE_B)
        self.assertEqual(writes[0]["model"], MODEL_B)
        self.assertEqual(writes[0]["authorization"], "Bearer token-B")
        decision = [
            item
            for item in coordinator.decisions
            if item.action == "send_rebased"
        ]
        self.assertEqual(len(decision), 1)
        self.assertEqual(decision[0].policy, "rebase_to_current_generation")
        await coordinator.aclose()

    @patch.object(rest.RESTClientObject, "request", new_callable=AsyncMock)
    async def test_fail_query_policy_does_not_retry_new_generation(
        self, mock_request: AsyncMock
    ):
        endpoint = FakeEndpoint(mock_request)
        coordinator = StoreRotationCoordinator(
            query_policy=QueryRetryPolicy.FAIL_IF_GENERATION_SUPERSEDED
        )
        coordinator.approve(PROFILE_A)

        started = asyncio.Event()
        release = asyncio.Event()

        async def before_retry(decision):
            started.set()
            await release.wait()

        task = asyncio.create_task(
            coordinator.check(check_body(), before_retry=before_retry)
        )
        await started.wait()
        coordinator.approve(PROFILE_B)
        release.set()

        with self.assertRaises(Exception):
            await task

        new_response = await coordinator.check(check_body())
        self.assertTrue(new_response.allowed)

        checks = endpoint.for_operation("check")
        self.assertEqual(len(checks), 2)
        self.assertEqual(checks[0]["store"], STORE_A)
        self.assertEqual(checks[1]["store"], STORE_B)
        decision = [
            item
            for item in coordinator.decisions
            if item.action == "fail_superseded"
        ]
        self.assertEqual(len(decision), 1)
        self.assertFalse(decision[0].allowed)
        await coordinator.aclose()
