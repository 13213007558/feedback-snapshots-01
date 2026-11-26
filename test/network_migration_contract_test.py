from __future__ import annotations

import asyncio
import itertools
import json
import threading

from contextvars import ContextVar
from queue import Queue
from unittest.mock import patch
from urllib.parse import urlparse

import pytest
import urllib3

import openfga_sdk.api_client as async_api_client_module
import openfga_sdk.rest as async_rest_module
import openfga_sdk.sync.api_client as sync_api_client_module
import openfga_sdk.sync.rest as sync_rest_module

from openfga_sdk.client import ClientConfiguration
from openfga_sdk.client.client import OpenFgaClient as AsyncOpenFgaClient
from openfga_sdk.configuration import RetryParams
from openfga_sdk.credentials import CredentialConfiguration, Credentials
from openfga_sdk.exceptions import RateLimitExceededError
from openfga_sdk.sync.client.client import OpenFgaClient as SyncOpenFgaClient


BUSINESS_ORIGIN = "http://fga-network.contract.invalid"
BUSINESS_ADDRESS = f"{BUSINESS_ORIGIN}/stores"
RETRY = "retry"
SUCCESS = "success"

current_owner: ContextVar[str] = ContextVar("current_owner", default="unassigned")


class ContractDoubleError(AssertionError):
    """Raised when a local test double detects an impossible interaction."""


class SharedConnectionDoubleError(ContractDoubleError):
    """Raised when one connection double is leased to two transports."""


class SharedCredentialDoubleError(ContractDoubleError):
    """Raised when a token minted by one instance reaches another transport."""


class Ledger:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._events: list[dict[str, object]] = []
        self._event_counter = itertools.count()
        self._transport_counter = itertools.count()
        self._connection_counter = itertools.count()
        self._token_counter = itertools.count()
        self.tokens: dict[str, dict[str, object]] = {}

    def record(self, kind: str, owner: str, **details: object) -> dict[str, object]:
        event = {
            "seq": next(self._event_counter),
            "kind": kind,
            "owner": owner,
            **details,
        }
        with self._lock:
            self._events.append(event)
        return event

    def events(self, *kinds: str) -> list[dict[str, object]]:
        with self._lock:
            events = list(self._events)
        if kinds:
            return [event for event in events if event["kind"] in kinds]
        return events

    def new_transport_id(self, owner: str) -> str:
        return f"transport-{owner}-{next(self._transport_counter)}"

    def new_connection_id(self) -> str:
        return f"connection-{next(self._connection_counter)}"

    def new_token(self, client_id: str, transport_id: str) -> str:
        token = f"token-{client_id}-{next(self._token_counter)}"
        with self._lock:
            if token in self.tokens:
                raise SharedCredentialDoubleError("token counter reused a token")
            self.tokens[token] = {
                "client_id": client_id,
                "transport_id": transport_id,
            }
        return token


class FakeHttpResponse:
    def __init__(
        self,
        status: int = 200,
        payload: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status = status
        self.reason = "OK" if 200 <= status < 300 else "Error"
        self.data = json.dumps(payload or {}).encode("utf-8")
        response_headers = {"Content-Type": "application/json"}
        if headers:
            response_headers.update(headers)
        self.headers = urllib3.response.HTTPHeaderDict(response_headers)

    def getheader(self, name: str, default: str | None = None) -> str | None:
        return self.headers.get(name, default)

    def getheaders(self) -> dict[str, str]:
        return dict(self.headers)


class ConnectionDouble:
    def __init__(self, ledger: Ledger, owner: str, origin: str) -> None:
        self.id = ledger.new_connection_id()
        self.ledger = ledger
        self.owner = owner
        self.origin = origin
        self.transport_ids: set[str] = set()
        self.closed = False

    def attach(self, transport_id: str) -> None:
        if self.closed:
            raise SharedConnectionDoubleError(
                f"{self.id} for {self.owner} was reused after close"
            )
        if self.transport_ids and transport_id not in self.transport_ids:
            raise SharedConnectionDoubleError(
                f"{self.id} was shared by {sorted(self.transport_ids)} "
                f"and {transport_id}"
            )
        self.transport_ids.add(transport_id)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.ledger.record(
            "connection-closed",
            self.owner,
            connection_id=self.id,
            origin=self.origin,
        )


class RecordingTransport:
    def __init__(
        self,
        owner: str,
        ledger: Ledger,
        outcomes: list[str],
        approved_client_id: str | None = None,
    ) -> None:
        self.owner = owner
        self.approved_client_id = approved_client_id or f"approved-{owner}"
        self.ledger = ledger
        self.transport_id = ledger.new_transport_id(owner)
        self.outcomes = list(outcomes)
        self.connections: dict[str, ConnectionDouble] = {}
        self.closed = False
        self.business_calls = 0

    def _connection_for(self, url: str) -> ConnectionDouble:
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        connection = self.connections.get(origin)
        if connection is None:
            connection = ConnectionDouble(self.ledger, self.owner, origin)
            self.connections[origin] = connection
            self.ledger.record(
                "connection-opened",
                self.owner,
                connection_id=connection.id,
                origin=origin,
                transport_id=self.transport_id,
            )
        connection.attach(self.transport_id)
        return connection

    def _retry_error(self) -> RateLimitExceededError:
        response = FakeHttpResponse(
            status=429,
            payload={
                "code": "rate_limit_exceeded",
                "message": "contract retry requested",
            },
        )
        return RateLimitExceededError(http_resp=response)

    def _handle_request(
        self,
        method: str,
        url: str,
        headers: object | None = None,
        post_params: object | None = None,
        **_kwargs: object,
    ) -> FakeHttpResponse:
        current_owner.set(self.owner)
        if self.closed:
            raise ContractDoubleError(
                f"{self.transport_id} for {self.owner} was used after close"
            )

        connection = self._connection_for(url)
        parsed_path = urlparse(url).path

        if parsed_path.endswith("/oauth/token"):
            if not isinstance(post_params, dict):
                raise ContractDoubleError("token request did not receive form data")
            client_id = post_params.get("client_id")
            client_secret = post_params.get("client_secret")
            if client_id != self.approved_client_id:
                raise SharedCredentialDoubleError(
                    f"{self.owner} transport refused client_id {client_id!r}"
                )

            token = self.ledger.new_token(str(client_id), self.transport_id)
            self.ledger.record(
                "credential-fetched",
                self.owner,
                address=url,
                client_id=client_id,
                client_secret=client_secret,
                connection_id=connection.id,
                token=token,
                transport_id=self.transport_id,
            )
            return FakeHttpResponse(
                payload={
                    "access_token": token,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                }
            )

        header_map = dict(headers or {})
        authorization = header_map.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            raise SharedCredentialDoubleError(
                f"{self.owner} business request had no bearer token"
            )
        token = authorization.removeprefix("Bearer ")
        token_record = self.ledger.tokens.get(token)
        if token_record is None:
            raise SharedCredentialDoubleError(
                f"{self.owner} used a token not minted by the local transport"
            )
        if token_record["client_id"] != self.approved_client_id:
            raise SharedCredentialDoubleError(
                f"{self.owner} used token for {token_record['client_id']}"
            )
        if token_record["transport_id"] != self.transport_id:
            raise SharedCredentialDoubleError(
                f"{self.owner} used a credential minted by another transport"
            )

        self.business_calls += 1
        attempt = self.business_calls
        if not self.outcomes:
            raise ContractDoubleError(
                f"{self.owner} received unexpected business attempt {attempt}"
            )
        outcome = self.outcomes.pop(0)
        self.ledger.record(
            "business-request",
            self.owner,
            address=url,
            method=method,
            attempt=attempt,
            authorization=authorization,
            token=token,
            token_client_id=token_record["client_id"],
            connection_id=connection.id,
            transport_id=self.transport_id,
        )

        if outcome == RETRY:
            raise self._retry_error()
        if outcome != SUCCESS:
            raise ContractDoubleError(f"unknown scripted outcome {outcome!r}")
        return FakeHttpResponse(payload={"stores": [], "continuation_token": ""})

    def _close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.ledger.record(
            "transport-closing", self.owner, transport_id=self.transport_id
        )
        for connection in list(self.connections.values()):
            connection.close()
        self.connections.clear()
        self.ledger.record(
            "transport-closed", self.owner, transport_id=self.transport_id
        )


class AsyncRecordingTransport(RecordingTransport):
    async def request(self, *args: object, **kwargs: object) -> FakeHttpResponse:
        return self._handle_request(*args, **kwargs)

    async def close(self) -> None:
        self._close()


class SyncRecordingTransport(RecordingTransport):
    def request(self, *args: object, **kwargs: object) -> FakeHttpResponse:
        return self._handle_request(*args, **kwargs)

    def close(self) -> None:
        self._close()


class AsyncWait:
    def __init__(self, seconds: float) -> None:
        self.seconds = seconds
        self.release = asyncio.Event()


class AsyncClock:
    def __init__(self, ledger: Ledger, auto_release: bool = False) -> None:
        self.ledger = ledger
        self.auto_release = auto_release
        self.started: asyncio.Queue[AsyncWait] = asyncio.Queue()
        self.waits: list[AsyncWait] = []

    async def sleep(self, seconds: float | int) -> None:
        wait = AsyncWait(float(seconds))
        self.waits.append(wait)
        owner = current_owner.get()
        self.ledger.record(
            "retry-wait-start",
            owner,
            seconds=wait.seconds,
            wait_index=len(self.waits),
        )
        self.started.put_nowait(wait)
        if self.auto_release:
            wait.release.set()
        await wait.release.wait()
        self.ledger.record(
            "retry-wait-end",
            owner,
            seconds=wait.seconds,
            wait_index=len(self.waits),
        )


class SyncWait:
    def __init__(self, seconds: float) -> None:
        self.seconds = seconds
        self.release = threading.Event()


class SyncClock:
    def __init__(self, ledger: Ledger, auto_release: bool = False) -> None:
        self.ledger = ledger
        self.auto_release = auto_release
        self.started: Queue[SyncWait] = Queue()
        self.waits: list[SyncWait] = []

    def sleep(self, seconds: float | int) -> None:
        wait = SyncWait(float(seconds))
        self.waits.append(wait)
        owner = current_owner.get()
        self.ledger.record(
            "retry-wait-start",
            owner,
            seconds=wait.seconds,
            wait_index=len(self.waits),
        )
        self.started.put(wait)
        if self.auto_release:
            wait.release.set()
        if not wait.release.wait(timeout=5):
            raise ContractDoubleError("timed out waiting for test to release retry")
        self.ledger.record(
            "retry-wait-end",
            owner,
            seconds=wait.seconds,
            wait_index=len(self.waits),
        )


def configuration_for(owner: str) -> ClientConfiguration:
    return ClientConfiguration(
        api_url=BUSINESS_ORIGIN,
        credentials=Credentials(
            method="client_credentials",
            configuration=CredentialConfiguration(
                client_id=f"approved-{owner}",
                client_secret=f"secret-{owner}",
                api_issuer=f"https://idp-{owner}.contract.invalid",
                api_audience="fga-network-migration-contract",
            ),
        ),
        retry_params=RetryParams(max_retry=1, min_wait_in_ms=1000),
        timeout_millisec=5000,
    )


def make_async_client(
    configuration: ClientConfiguration, transport: AsyncRecordingTransport
) -> AsyncOpenFgaClient:
    with patch.object(
        async_rest_module,
        "RESTClientObject",
        new=lambda *_args, **_kwargs: transport,
    ):
        return AsyncOpenFgaClient(configuration)


def make_sync_client(
    configuration: ClientConfiguration, transport: SyncRecordingTransport
) -> SyncOpenFgaClient:
    with patch.object(
        sync_rest_module,
        "RESTClientObject",
        new=lambda *_args, **_kwargs: transport,
    ):
        return SyncOpenFgaClient(configuration)


async def capture_async(bucket: dict[str, object], key: str, awaitable) -> None:
    try:
        bucket[key] = await awaitable
    except BaseException as exc:
        bucket[f"{key}_error"] = exc


def capture_sync(bucket: dict[str, object], key: str, callback) -> None:
    try:
        bucket[key] = callback()
    except BaseException as exc:
        bucket[f"{key}_error"] = exc


def assert_migration_contract(
    ledger: Ledger,
    old_transport: RecordingTransport,
    new_transport: RecordingTransport,
) -> None:
    business_events = ledger.events("business-request")
    old_business = [event for event in business_events if event["owner"] == "old"]
    new_business = [event for event in business_events if event["owner"] == "new"]

    assert [event["attempt"] for event in old_business] == [1, 2]
    assert [event["attempt"] for event in new_business] == [1, 2, 3]

    assert {event["address"] for event in business_events} == {BUSINESS_ADDRESS}

    credential_events = ledger.events("credential-fetched")
    old_credentials = [event for event in credential_events if event["owner"] == "old"]
    new_credentials = [event for event in credential_events if event["owner"] == "new"]
    assert len(old_credentials) == 1
    assert len(new_credentials) == 1
    assert old_credentials[0]["address"] == (
        "https://idp-old.contract.invalid/oauth/token"
    )
    assert new_credentials[0]["address"] == (
        "https://idp-new.contract.invalid/oauth/token"
    )
    assert old_credentials[0]["client_id"] == "approved-old"
    assert old_credentials[0]["client_secret"] == "secret-old"
    assert new_credentials[0]["client_id"] == "approved-new"
    assert new_credentials[0]["client_secret"] == "secret-new"

    old_business_connection = old_business[0]["connection_id"]
    new_business_connection = new_business[0]["connection_id"]
    assert old_business_connection != new_business_connection
    assert all(
        event["connection_id"] == old_business_connection for event in old_business
    )
    assert all(
        event["connection_id"] == new_business_connection for event in new_business
    )

    for event in business_events:
        token_record = ledger.tokens[str(event["token"])]
        assert event["token_client_id"] == f"approved-{event['owner']}"
        assert token_record["client_id"] == f"approved-{event['owner']}"
        assert token_record["transport_id"] == event["transport_id"]
        assert event["authorization"] == f"Bearer {event['token']}"

    observed_sequence = [
        (
            event["kind"],
            event["owner"],
            event.get("attempt"),
            event.get("connection_id"),
        )
        for event in ledger.events(
            "credential-fetched",
            "business-request",
            "retry-wait-start",
            "retry-wait-end",
            "connection-closed",
        )
    ]
    expected_sequence = [
        ("credential-fetched", "old", None, old_credentials[0]["connection_id"]),
        ("business-request", "old", 1, old_business_connection),
        ("retry-wait-start", "old", None, None),
        ("credential-fetched", "new", None, new_credentials[0]["connection_id"]),
        ("business-request", "new", 1, new_business_connection),
        ("retry-wait-end", "old", None, None),
        ("business-request", "old", 2, old_business_connection),
        ("business-request", "new", 2, new_business_connection),
        ("retry-wait-start", "new", None, None),
        ("connection-closed", "old", None, old_credentials[0]["connection_id"]),
        ("connection-closed", "old", None, old_business_connection),
        ("retry-wait-end", "new", None, None),
        ("business-request", "new", 3, new_business_connection),
        ("connection-closed", "new", None, new_credentials[0]["connection_id"]),
        ("connection-closed", "new", None, new_business_connection),
    ]
    assert observed_sequence == expected_sequence

    closed_connections = ledger.events("connection-closed")
    old_closed = [
        event["connection_id"]
        for event in closed_connections
        if event["owner"] == "old"
    ]
    new_closed = [
        event["connection_id"]
        for event in closed_connections
        if event["owner"] == "new"
    ]
    assert old_closed == [
        old_credentials[0]["connection_id"],
        old_business_connection,
    ]
    assert new_closed == [
        new_credentials[0]["connection_id"],
        new_business_connection,
    ]
    assert set(old_closed).isdisjoint(new_closed)
    assert old_transport.closed is True
    assert new_transport.closed is True


@pytest.mark.asyncio
async def test_async_migration_close_rebuild_keeps_instances_isolated() -> None:
    ledger = Ledger()
    clock = AsyncClock(ledger)
    old_transport = AsyncRecordingTransport("old", ledger, [RETRY, SUCCESS])
    new_transport = AsyncRecordingTransport("new", ledger, [SUCCESS, RETRY, SUCCESS])
    old_client = make_async_client(configuration_for("old"), old_transport)
    new_client = make_async_client(configuration_for("new"), new_transport)
    bucket: dict[str, object] = {}
    tasks: list[asyncio.Task[None]] = []

    try:
        with patch.object(async_api_client_module.asyncio, "sleep", new=clock.sleep):
            old_task = asyncio.create_task(
                capture_async(bucket, "old", old_client.list_stores())
            )
            tasks.append(old_task)
            old_wait = await asyncio.wait_for(clock.started.get(), timeout=5)

            new_stores = await new_client.list_stores()
            assert new_stores.stores == []

            old_wait.release.set()
            await asyncio.wait_for(old_task, timeout=5)
            assert "old_error" not in bucket, bucket.get("old_error")

            new_retry_task = asyncio.create_task(
                capture_async(bucket, "new_retry", new_client.list_stores())
            )
            tasks.append(new_retry_task)
            new_wait = await asyncio.wait_for(clock.started.get(), timeout=5)

            new_business_connection = new_transport.connections[BUSINESS_ORIGIN]
            old_business_connection = old_transport.connections[BUSINESS_ORIGIN]
            await old_client.close()

            assert old_business_connection.closed is True
            assert new_business_connection.closed is False

            new_wait.release.set()
            await asyncio.wait_for(new_retry_task, timeout=5)
            assert "new_retry_error" not in bucket, bucket.get("new_retry_error")
            assert bucket["new_retry"].stores == []

            await new_client.close()

        assert_migration_contract(ledger, old_transport, new_transport)
    except BaseException:
        for wait in clock.waits:
            wait.release.set()
        for task in tasks:
            task.cancel()
        raise
    finally:
        for wait in clock.waits:
            wait.release.set()
        await old_client.close()
        await new_client.close()


def test_sync_migration_close_rebuild_keeps_instances_isolated() -> None:
    ledger = Ledger()
    clock = SyncClock(ledger)
    old_transport = SyncRecordingTransport("old", ledger, [RETRY, SUCCESS])
    new_transport = SyncRecordingTransport("new", ledger, [SUCCESS, RETRY, SUCCESS])
    old_client = make_sync_client(configuration_for("old"), old_transport)
    new_client = make_sync_client(configuration_for("new"), new_transport)
    bucket: dict[str, object] = {}
    threads: list[threading.Thread] = []

    try:
        with patch.object(sync_api_client_module.time, "sleep", new=clock.sleep):
            old_thread = threading.Thread(
                target=capture_sync,
                args=(bucket, "old", old_client.list_stores),
                daemon=True,
            )
            old_thread.start()
            threads.append(old_thread)
            old_wait = clock.started.get(timeout=5)

            new_stores = new_client.list_stores()
            assert new_stores.stores == []

            old_wait.release.set()
            old_thread.join(timeout=5)
            assert not old_thread.is_alive()
            assert "old_error" not in bucket, bucket.get("old_error")

            new_thread = threading.Thread(
                target=capture_sync,
                args=(bucket, "new_retry", new_client.list_stores),
                daemon=True,
            )
            new_thread.start()
            threads.append(new_thread)
            new_wait = clock.started.get(timeout=5)

            new_business_connection = new_transport.connections[BUSINESS_ORIGIN]
            old_business_connection = old_transport.connections[BUSINESS_ORIGIN]
            old_client.close()

            assert old_business_connection.closed is True
            assert new_business_connection.closed is False

            new_wait.release.set()
            new_thread.join(timeout=5)
            assert not new_thread.is_alive()
            assert "new_retry_error" not in bucket, bucket.get("new_retry_error")
            assert bucket["new_retry"].stores == []

            new_client.close()

        assert_migration_contract(ledger, old_transport, new_transport)
    except BaseException:
        for wait in clock.waits:
            wait.release.set()
        raise
    finally:
        for wait in clock.waits:
            wait.release.set()
        for thread in threads:
            thread.join(timeout=5)
        old_client.close()
        new_client.close()


@pytest.mark.asyncio
async def test_async_single_instance_retry_control() -> None:
    ledger = Ledger()
    clock = AsyncClock(ledger, auto_release=True)
    transport = AsyncRecordingTransport("control", ledger, [RETRY, SUCCESS])
    client = make_async_client(configuration_for("control"), transport)

    try:
        with patch.object(async_api_client_module.asyncio, "sleep", new=clock.sleep):
            result = await client.list_stores()
            assert result.stores == []
            assert len(clock.waits) == 1
            assert 1 <= clock.waits[0].seconds < 2
            await client.close()

        business = ledger.events("business-request")
        assert [event["attempt"] for event in business] == [1, 2]
        assert business[0]["connection_id"] == business[1]["connection_id"]
        closed = ledger.events("connection-closed")
        assert len(closed) == 2
        assert {event["connection_id"] for event in closed} == {
            business[0]["connection_id"],
            ledger.events("credential-fetched")[0]["connection_id"],
        }
    finally:
        await client.close()


def test_sync_single_instance_retry_control() -> None:
    ledger = Ledger()
    clock = SyncClock(ledger, auto_release=True)
    transport = SyncRecordingTransport("control", ledger, [RETRY, SUCCESS])
    client = make_sync_client(configuration_for("control"), transport)

    try:
        with patch.object(sync_api_client_module.time, "sleep", new=clock.sleep):
            result = client.list_stores()
            assert result.stores == []
            assert len(clock.waits) == 1
            assert 1 <= clock.waits[0].seconds < 2
            client.close()

        business = ledger.events("business-request")
        assert [event["attempt"] for event in business] == [1, 2]
        assert business[0]["connection_id"] == business[1]["connection_id"]
        closed = ledger.events("connection-closed")
        assert len(closed) == 2
        assert {event["connection_id"] for event in closed} == {
            business[0]["connection_id"],
            ledger.events("credential-fetched")[0]["connection_id"],
        }
    finally:
        client.close()


def test_connection_double_rejects_cross_transport_sharing() -> None:
    ledger = Ledger()
    connection = ConnectionDouble(ledger, "shared", BUSINESS_ORIGIN)
    connection.attach("transport-a")

    with pytest.raises(SharedConnectionDoubleError):
        connection.attach("transport-b")

    connection.close()
    with pytest.raises(SharedConnectionDoubleError):
        connection.attach("transport-a")


def test_transport_detects_credential_minted_by_other_instance() -> None:
    ledger = Ledger()
    new_transport = SyncRecordingTransport("new", ledger, [SUCCESS])
    token = ledger.new_token("approved-old", "old-transport")

    with pytest.raises(SharedCredentialDoubleError):
        new_transport._handle_request(
            "GET",
            BUSINESS_ADDRESS,
            headers={"Authorization": f"Bearer {token}"},
        )


@pytest.mark.asyncio
async def test_async_clients_own_transport_and_oauth_clients() -> None:
    old_configuration = configuration_for("old-identity")
    new_configuration = configuration_for("new-identity")
    old_configuration.connection_pool_maxsize = 7
    new_configuration.connection_pool_maxsize = 9
    old_client = AsyncOpenFgaClient(old_configuration)
    new_client = AsyncOpenFgaClient(new_configuration)
    try:
        old_rest = old_client._api_client.rest_client
        new_rest = new_client._api_client.rest_client
        assert old_rest is not new_rest
        assert old_rest.pool_manager is not new_rest.pool_manager
        assert old_rest.pool_manager.connector.limit == 7
        assert new_rest.pool_manager.connector.limit == 9
        assert old_client._api._oauth2_client is not new_client._api._oauth2_client
        assert old_client._api._oauth2_client.configuration is old_configuration
        assert new_client._api._oauth2_client.configuration is new_configuration
    finally:
        await old_client.close()
        await new_client.close()


def test_sync_client_oauth_and_pool_use_their_own_configuration() -> None:
    configuration = configuration_for("sync-config")
    configuration.connection_pool_maxsize = 5
    client = SyncOpenFgaClient(configuration)
    try:
        rest_client = client._api_client.rest_client
        assert client._api._oauth2_client.configuration is configuration
        assert rest_client.pool_manager.connection_pool_kw["maxsize"] == 5
    finally:
        client.close()


def test_shared_connection_double_is_rejected_by_both_clients() -> None:
    ledger = Ledger()
    shared_connection = ConnectionDouble(ledger, "shared", BUSINESS_ORIGIN)

    sync_old_transport = SyncRecordingTransport("old", ledger, [SUCCESS])
    sync_new_transport = SyncRecordingTransport("new", ledger, [SUCCESS])
    sync_old_transport.connections[BUSINESS_ORIGIN] = shared_connection
    sync_new_transport.connections[BUSINESS_ORIGIN] = shared_connection
    sync_old = make_sync_client(configuration_for("old"), sync_old_transport)
    sync_new = make_sync_client(configuration_for("new"), sync_new_transport)
    try:
        assert sync_old.list_stores().stores == []
        with pytest.raises(SharedConnectionDoubleError):
            sync_new.list_stores()
    finally:
        sync_old.close()
        sync_new.close()

    async def async_scenario() -> None:
        async_shared = ConnectionDouble(ledger, "shared-async", BUSINESS_ORIGIN)
        async_old_transport = AsyncRecordingTransport("old", ledger, [SUCCESS])
        async_new_transport = AsyncRecordingTransport("new", ledger, [SUCCESS])
        async_old_transport.connections[BUSINESS_ORIGIN] = async_shared
        async_new_transport.connections[BUSINESS_ORIGIN] = async_shared
        async_old = make_async_client(configuration_for("old"), async_old_transport)
        async_new = make_async_client(configuration_for("new"), async_new_transport)
        try:
            stores = await async_old.list_stores()
            assert stores.stores == []
            with pytest.raises(SharedConnectionDoubleError):
                await async_new.list_stores()
        finally:
            await async_old.close()
            await async_new.close()

    asyncio.run(async_scenario())


def test_shared_credential_double_is_rejected_by_both_clients() -> None:
    ledger = Ledger()
    sync_old_transport = SyncRecordingTransport("old", ledger, [SUCCESS])
    sync_new_transport = SyncRecordingTransport("new", ledger, [SUCCESS])
    sync_old = make_sync_client(configuration_for("old"), sync_old_transport)
    sync_new = make_sync_client(configuration_for("new"), sync_new_transport)
    try:
        assert sync_old.list_stores().stores == []
        sync_new._api._oauth2_client = sync_old._api._oauth2_client
        with pytest.raises(SharedCredentialDoubleError):
            sync_new.list_stores()
    finally:
        sync_old.close()
        sync_new.close()

    async def async_scenario() -> None:
        async_old_transport = AsyncRecordingTransport("old", ledger, [SUCCESS])
        async_new_transport = AsyncRecordingTransport("new", ledger, [SUCCESS])
        async_old = make_async_client(configuration_for("old"), async_old_transport)
        async_new = make_async_client(configuration_for("new"), async_new_transport)
        try:
            stores = await async_old.list_stores()
            assert stores.stores == []
            async_new._api._oauth2_client = async_old._api._oauth2_client
            with pytest.raises(SharedCredentialDoubleError):
                await async_new.list_stores()
        finally:
            await async_old.close()
            await async_new.close()

    asyncio.run(async_scenario())
