"""End-to-end proof of per-operation admission for async endpoint discovery.

This file is both a pytest module and a runnable demonstration::

    .venv/bin/python tests/test_discovery_egress.py
    # or
    .venv/bin/python -m pytest --noconftest --asyncio-mode=auto -q \\
        tests/test_discovery_egress.py

It drives the real aiobotocore call chain
``client.<op>() -> AioBaseClient._make_api_call -> AioEndpoint._send_request
-> request-created (discovery admission) -> AIOHTTPSession -> aiohttp
connector`` against a *fake endpoint discovery service*.

Actual connection records come from an ``EgressTCPConnector`` subclass at
aiohttp's ``_wrap_create_connection`` seam.  Inside this sandbox binding a
TCP port is forbidden (``EPERM``), so the test dial pairs a ``socketpair``
with a scripted raw-HTTP responder: real aiohttp framing/parsing over a real
connected fd, with the logical ``(host, port)`` recorded exactly where a TCP
socket would otherwise be opened.  On a normal machine the separate
``test_real_tcp_connect_records`` case binds loopback servers and records
genuine OS accepts.

The final ledger distinguishes the three outcomes using *connection records*,
not tokens or config objects:

* ``CONTINUE`` -- an ``connected`` record on a discovered, admitted target;
* ``FALLBACK`` -- an ``connected`` record with ``role=default-fallback``;
* ``STOP``     -- a ``stop``/``connect_blocked`` record and zero connections.
"""

from __future__ import annotations

import asyncio
import json
import socket
import tempfile
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import botocore.loaders
import pytest

import aiobotocore.session
from aiobotocore.config import AioConfig
from aiobotocore.egress import (
    OUTCOME_CONTINUE,
    OUTCOME_FALLBACK,
    OUTCOME_STOP,
    ConnectionLedger,
    EgressGate,
    EgressPolicy,
    EgressTCPConnector,
    GuardedAIOHTTPSession,
    RequiredDiscoveryBlocked,
    install_endpoint_egress,
)

SERVICE = 'egressdemo'
API_VERSION = '2024-06-01'

DEFAULT_EP = 'http://127.0.0.1:9000'
LEGAL_EP = 'http://127.0.0.1:9101'
PENDING_EP = 'http://127.0.0.1:9202'
VOLATILE_EP = 'http://127.0.0.1:9303'
UNAPPROVED_DEFAULT_EP = 'http://127.0.0.1:9595'

PUT_OK = b'{"Ok": true}'
GET_OK = b'{"Value": "default"}'


def _service_model() -> dict[str, Any]:
    return {
        'version': '2.0',
        'metadata': {
            'apiVersion': API_VERSION,
            'endpointPrefix': 'egress-demo',
            'serviceId': 'EgressDemo',
            'protocol': 'json',
            'jsonVersion': '1.1',
            'targetPrefix': 'EgressDemo',
            'serviceFullName': 'Egress Egress-Demo Service',
            'signatureVersion': 'v4',
        },
        'operations': {
            'DescribeEndpoints': {
                'name': 'DescribeEndpoints',
                'http': {'method': 'POST', 'requestUri': '/endpoints'},
                'input': {'shape': 'DescribeEndpointsRequest'},
                'output': {'shape': 'DescribeEndpointsResponse'},
                'endpointoperation': True,
            },
            'PutThing': {
                'name': 'PutThing',
                'http': {'method': 'POST', 'requestUri': '/put'},
                'input': {'shape': 'PutThingRequest'},
                'output': {'shape': 'PutThingResponse'},
                # Protocol-required discovery: no default fallback.
                'endpointdiscovery': {'required': True},
            },
            'GetThing': {
                'name': 'GetThing',
                'http': {'method': 'POST', 'requestUri': '/get'},
                'input': {'shape': 'GetThingRequest'},
                'output': {'shape': 'GetThingResponse'},
                # Optional discovery: may use the approved default endpoint.
                'endpointdiscovery': {},
            },
        },
        'shapes': {
            'DescribeEndpointsRequest': {
                'type': 'structure',
                'members': {
                    'Operation': {'shape': 'String'},
                    'Identifiers': {'shape': 'Identifiers'},
                },
            },
            'Identifiers': {
                'type': 'map',
                'key': {'shape': 'String'},
                'value': {'shape': 'String'},
            },
            'DescribeEndpointsResponse': {
                'type': 'structure',
                'members': {'Endpoints': {'shape': 'Endpoints'}},
            },
            'Endpoints': {'type': 'list', 'member': {'shape': 'Endpoint'}},
            'Endpoint': {
                'type': 'structure',
                'members': {
                    'Address': {'shape': 'String'},
                    'CachePeriodInMinutes': {'shape': 'Long'},
                },
            },
            'PutThingRequest': {
                'type': 'structure',
                'required': ['ThingId'],
                'members': {'ThingId': {'shape': 'ThingId'}},
            },
            'GetThingRequest': {
                'type': 'structure',
                'required': ['ThingId'],
                'members': {'ThingId': {'shape': 'ThingId'}},
            },
            'ThingId': {'type': 'string', 'endpointdiscoveryid': True},
            'PutThingResponse': {
                'type': 'structure',
                'members': {'Ok': {'shape': 'Boolean'}},
            },
            'GetThingResponse': {
                'type': 'structure',
                'members': {'Value': {'shape': 'String'}},
            },
            'String': {'type': 'string'},
            'Long': {'type': 'long'},
            'Boolean': {'type': 'boolean'},
        },
    }


_MODEL_ROOT: str | None = None


def ensure_model() -> str:
    global _MODEL_ROOT
    if _MODEL_ROOT is not None:
        return _MODEL_ROOT
    root = Path(tempfile.mkdtemp(prefix='egress-demo-model-'))
    folder = root / SERVICE / API_VERSION
    folder.mkdir(parents=True, exist_ok=True)
    (folder / 'service-2.json').write_text(json.dumps(_service_model()))
    _MODEL_ROOT = str(root)
    return _MODEL_ROOT


class FakeDiscoveryService:
    """Scripted stand-in for the service's DescribeEndpoints control plane."""

    def __init__(
        self,
        endpoints_by_operation: dict[str, list[str]] | None = None,
    ) -> None:
        self.endpoints_by_operation = endpoints_by_operation or {}
        self.calls: list[tuple[str | None, dict]] = []

    def set(self, operation: str, addresses: list[str]) -> None:
        self.endpoints_by_operation[operation] = list(addresses)

    def describe_endpoints(self, Operation=None, Identifiers=None, **_: Any):
        self.calls.append((Operation, dict(Identifiers or {})))
        addresses = self.endpoints_by_operation.get(Operation, [])
        return {
            'Endpoints': [
                {'Address': address, 'CachePeriodInMinutes': 60}
                for address in addresses
            ]
        }


class ScriptedRoute:
    """Stateful response script for one destination port."""

    def __init__(
        self,
        *,
        body: bytes = PUT_OK,
        status: int = 200,
        error_code: str | None = None,
        succeed_after_error: bool = False,
        on_serve: Any | None = None,
    ) -> None:
        self.body = body
        self.status = status
        self.error_code = error_code
        self.succeed_after_error = succeed_after_error
        self.on_serve = on_serve
        self.hits = 0

    def respond(self) -> tuple[int, bytes, str | None]:
        self.hits += 1
        if self.on_serve is not None:
            self.on_serve(self)
        if self.error_code and not (
            self.succeed_after_error and self.hits > 1
        ):
            payload = json.dumps(
                {'__type': self.error_code, 'message': self.error_code}
            ).encode()
            return 400, payload, self.error_code
        return self.status, self.body, None


async def _socketpair_server(sock_b: socket.socket, route: ScriptedRoute):
    """Speak one HTTP exchange over the server end of a socketpair.

    Uses raw non-blocking socket IO on purpose: no asyncio transport is
    created on this side, so closing ``sock_b`` in ``finally`` cannot leak an
    unclosed selector transport.
    """
    loop = asyncio.get_running_loop()

    async def recv_some() -> bytes:
        try:
            return await loop.sock_recv(sock_b, 4096)
        except (OSError, asyncio.CancelledError):
            return b''

    try:
        data = b''
        while b'\r\n\r\n' not in data:
            chunk = await recv_some()
            if not chunk:
                break
            data += chunk
        head, _, remainder = data.partition(b'\r\n\r\n')
        content_length = 0
        expect_continue = False
        for line in head.split(b'\r\n'):
            lower = line.lower()
            if lower.startswith(b'content-length:'):
                content_length = int(line.split(b':', 1)[1].strip())
            if lower.startswith(b'expect:') and b'100-continue' in lower:
                expect_continue = True
        if expect_continue:
            await loop.sock_sendall(sock_b, b'HTTP/1.1 100 Continue\r\n\r\n')
        body = remainder
        while len(body) < content_length:
            chunk = await recv_some()
            if not chunk:
                break
            body += chunk

        status, payload, _ = route.respond()
        reason = {
            200: 'OK',
            400: 'Bad Request',
            421: 'Misdirected Request',
        }.get(status, 'OK')
        response = (
            f'HTTP/1.1 {status} {reason}\r\n'
            'Content-Type: application/x-amz-json-1.1\r\n'
            f'Content-Length: {len(payload)}\r\n'
            'Connection: close\r\n\r\n'
        ).encode() + payload
        await loop.sock_sendall(sock_b, response)
    except Exception as exc:  # pragma: no cover - diagnostic path
        print('socketpair server error:', repr(exc))
    finally:
        try:
            sock_b.close()
        except OSError:
            pass


class DemoConnector(EgressTCPConnector):
    """Connector that dials an in-memory socketpair instead of the OS."""

    def __init__(self, *args: Any, router: dict[int, ScriptedRoute], **kw: Any):
        super().__init__(*args, **kw)
        self._router = router
        self._dial_tasks: set[asyncio.Task] = set()

    async def _egress_dial(
        self, args, addr_infos, req, timeout, client_error, kwargs
    ):
        port = req.port
        route = self._router.get(port)
        if route is None:
            raise AssertionError(f'no scripted route for port {port}')
        sock_a, sock_b = socket.socketpair()
        sock_a.setblocking(False)
        sock_b.setblocking(False)
        task = asyncio.ensure_future(_socketpair_server(sock_b, route))
        self._dial_tasks.add(task)
        task.add_done_callback(self._dial_tasks.discard)
        task.add_done_callback(
            lambda t: None if t.cancelled() else t.exception()
        )
        kwargs.pop('ssl', None)
        kwargs.pop('server_hostname', None)
        return await self._loop.create_connection(args[0], sock=sock_a)


class DemoSession(GuardedAIOHTTPSession):
    router: dict[int, ScriptedRoute] = {}

    async def _create_connector(self, proxy_url):
        if self._verify or self._cert_file or proxy_url:
            ssl_context, proxy_ssl_context = await asyncio.to_thread(
                self._build_ssl_contexts, proxy_url
            )
        else:
            ssl_context, proxy_ssl_context = self._build_ssl_contexts(
                proxy_url
            )
        connector = DemoConnector(
            egress_gate=self.egress_gate,
            router=self.router,
            limit=self._max_pool_connections,
            ssl=ssl_context,
            proxy_ssl_context=proxy_ssl_context,
            **self._connector_args,
        )
        self._demo_connector = connector
        return connector


def demo_session_class(gate: EgressGate, router: dict[int, ScriptedRoute]):
    class _BoundDemoSession(DemoSession):
        def __init__(self, **kwargs: Any) -> None:
            super().__init__(**kwargs)
            self.egress_gate = gate
            self.router = router

    return _BoundDemoSession




class Harness:
    def __init__(
        self, client, policy, ledger, gate, discovery, router
    ) -> None:
        self.client = client
        self.policy = policy
        self.ledger = ledger
        self.gate = gate
        self.discovery = discovery
        self.router = router


@asynccontextmanager
async def harness(
    *,
    allowed=(DEFAULT_EP, LEGAL_EP),
    approved=(),
    defaults=(DEFAULT_EP,),
    endpoints: dict[str, list[str]] | None = None,
    always_discover: bool = True,
    endpoint_url: str = DEFAULT_EP,
    withdraw_on_volatile_error: bool = False,
    volatile_error: bool = False,
):
    ensure_model()
    loader = botocore.loaders.Loader(extra_search_paths=[ensure_model()])
    session = aiobotocore.session.AioSession()
    session.register_component('data_loader', loader)

    policy = EgressPolicy(
        allowed=list(allowed),
        approved=list(approved),
        default_endpoints=list(defaults),
    )
    ledger = ConnectionLedger()
    gate = EgressGate(policy, ledger)

    def _withdraw_on_first_error(route: ScriptedRoute) -> None:
        if withdraw_on_volatile_error and route.hits == 1:
            policy.withdraw(VOLATILE_EP)

    router = {
        9000: ScriptedRoute(body=GET_OK),
        9101: ScriptedRoute(body=PUT_OK),
        9202: ScriptedRoute(body=PUT_OK),
        9303: ScriptedRoute(
            body=PUT_OK,
            error_code=(
                'InvalidEndpointException' if volatile_error else None
            ),
            succeed_after_error=volatile_error,
            on_serve=_withdraw_on_first_error,
        ),
    }
    discovery = FakeDiscoveryService(
        endpoints
        or {'PutThing': [LEGAL_EP], 'GetThing': [LEGAL_EP]}
    )

    config = AioConfig(
        http_session_cls=demo_session_class(gate, router),
        connector_args={
            'force_close': True,
            'keepalive_timeout': None,
        },
        retries={'total_max_attempts': 4},
        connect_timeout=5,
        read_timeout=5,
    )
    async with session.create_client(
        SERVICE,
        region_name='us-east-1',
        endpoint_url=endpoint_url,
        aws_access_key_id='test',
        aws_secret_access_key='test',
        config=config,
        verify=False,
    ) as client:
        install_endpoint_egress(
            client,
            gate=gate,
            discovery_source=discovery,
            default_endpoint=endpoint_url,
            always_discover=always_discover,
        )
        handle = Harness(client, policy, ledger, gate, discovery, router)
        try:
            yield handle
        finally:
            # Let every scripted socketpair server finish and close its end
            # before the event loop tears down, so no transport/fd leaks.
            http_session = getattr(
                client._endpoint, 'http_session', None
            )
            connector = getattr(http_session, '_demo_connector', None)
            if connector is not None and connector._dial_tasks:
                await asyncio.gather(
                    *list(connector._dial_tasks),
                    return_exceptions=True,
                )


def _targets(ledger: ConnectionLedger) -> list[str]:
    return ledger.targets()


# ---------------------------------------------------------------------------
# Reusable scenarios (used by both pytest and the __main__ demonstration).
# ---------------------------------------------------------------------------


async def scenario_legal() -> dict[str, Any]:
    async with harness(
        endpoints={'PutThing': [LEGAL_EP], 'GetThing': [LEGAL_EP]}
    ) as h:
        result = await h.client.put_thing(ThingId='legal-1')
        return {
            'name': 'legal discovery result -> CONTINUE',
            'ledger': h.ledger,
            'targets': _targets(h.ledger),
            'ok': result.get('Ok') is True,
            'error': None,
        }


async def scenario_pending_approval() -> dict[str, Any]:
    async with harness(
        allowed=[DEFAULT_EP],
        endpoints={'PutThing': [PENDING_EP]},
    ) as h:
        error = None
        try:
            await h.client.put_thing(ThingId='pending-1')
        except RequiredDiscoveryBlocked as exc:
            error = exc
        blocked_before = list(h.ledger.blocks)
        targets_before = _targets(h.ledger)

        h.policy.approve(PENDING_EP, ticket='CHG-7558')
        result = await h.client.put_thing(ThingId='pending-1')
        return {
            'name': 'pending approval -> STOP, then approve -> CONTINUE',
            'ledger': h.ledger,
            'error': error,
            'blocker': getattr(error, 'blocker', None),
            'blocked_before': blocked_before,
            'targets_before_approval': targets_before,
            'targets': _targets(h.ledger),
            'ok': result.get('Ok') is True,
        }


async def scenario_withdraw_warm_cache() -> dict[str, Any]:
    async with harness(
        allowed=[DEFAULT_EP],
        approved=[VOLATILE_EP],
        endpoints={'GetThing': [VOLATILE_EP]},
    ) as h:
        first = await h.client.get_thing(ThingId='volatile-1')
        targets_after_first = _targets(h.ledger)

        version = h.policy.withdraw(VOLATILE_EP, reason='rotated / removed')
        second = await h.client.get_thing(ThingId='volatile-1')
        return {
            'name': 'control-plane withdrawal -> FALLBACK on warm cache',
            'ledger': h.ledger,
            'targets_after_first': targets_after_first,
            'targets': _targets(h.ledger),
            'withdrawn_version': version,
            'first': first,
            'second': second,
            'error': None,
        }


async def scenario_retry_after_withdrawal() -> dict[str, Any]:
    async with harness(
        allowed=[DEFAULT_EP],
        approved=[VOLATILE_EP],
        endpoints={'GetThing': [VOLATILE_EP]},
        withdraw_on_volatile_error=True,
        volatile_error=True,
    ) as h:
        result = await h.client.get_thing(ThingId='retry-1')
        return {
            'name': 'request retry + withdrawal -> FALLBACK to default',
            'ledger': h.ledger,
            'targets': _targets(h.ledger),
            'volatile_hits': h.router[9303].hits,
            'retry_attempts': result['ResponseMetadata'].get(
                'RetryAttempts'
            ),
            'error': None,
        }


async def scenario_required_stop() -> dict[str, Any]:
    async with harness(
        allowed=[DEFAULT_EP],
        endpoints={'PutThing': [PENDING_EP]},
    ) as h:
        error = None
        try:
            await h.client.put_thing(ThingId='stop-1')
        except RequiredDiscoveryBlocked as exc:
            error = exc
        return {
            'name': 'required op, no qualified discovery address -> STOP',
            'ledger': h.ledger,
            'targets': _targets(h.ledger),
            'error': error,
            'blocker': getattr(error, 'blocker', None),
        }


async def scenario_optional_unapproved_default() -> dict[str, Any]:
    async with harness(
        allowed=[],
        defaults=[],
        endpoint_url=UNAPPROVED_DEFAULT_EP,
        endpoints={'GetThing': []},
    ) as h:
        from aiobotocore.egress import UnapprovedDefaultEndpoint

        error = None
        try:
            await h.client.get_thing(ThingId='nodefault-1')
        except UnapprovedDefaultEndpoint as exc:
            error = exc
        return {
            'name': 'optional op, default not approved -> explicit STOP',
            'ledger': h.ledger,
            'targets': _targets(h.ledger),
            'error': error,
            'blocker': getattr(error, 'blocker', None),
        }


async def scenario_transport_gate() -> dict[str, Any]:
    from aiobotocore.egress import _exception_is_egress_block

    async with harness(
        allowed=[DEFAULT_EP],
        defaults=[DEFAULT_EP],
        endpoint_url=UNAPPROVED_DEFAULT_EP,
        always_discover=False,
        endpoints={},
    ) as h:
        error = None
        try:
            await h.client.get_thing(ThingId='gate-1')
        except Exception as exc:  # surfaced as HTTPClientError wrapper
            error = exc
        return {
            'name': 'transport seam independently blocks unapproved origin',
            'ledger': h.ledger,
            'targets': _targets(h.ledger),
            'error': error,
            'egress_block': _exception_is_egress_block(error),
        }


async def scenario_parallel() -> dict[str, Any]:
    async with harness(
        endpoints={
            'PutThing': [LEGAL_EP],
            # Not approved -> the optional Get falls back to the default.
            'GetThing': [PENDING_EP],
        }
    ) as h:
        put, get = await asyncio.gather(
            h.client.put_thing(ThingId='parallel-put'),
            h.client.get_thing(ThingId='parallel-get'),
        )
        connected = h.ledger.connections
        return {
            'name': 'parallel optional + required calls stay per-operation',
            'ledger': h.ledger,
            'targets': _targets(h.ledger),
            'operations': sorted(
                {r.operation for r in connected if r.operation}
            ),
            'roles': sorted({r.role for r in connected if r.role}),
            'ok': put.get('Ok') is True and 'Value' in get,
            'error': None,
        }


async def run_triad() -> dict[str, Any]:
    """One ledger in which CONTINUE/FALLBACK/STOP are all observable."""
    async with harness(
        allowed=[DEFAULT_EP, LEGAL_EP],
        endpoints={
            'PutThing': [LEGAL_EP],
            'GetThing': [PENDING_EP],
        },
    ) as h:
        await h.client.put_thing(ThingId='triad-continue')
        await h.client.get_thing(ThingId='triad-fallback')
        h.policy.withdraw(LEGAL_EP)
        stop_error = None
        try:
            await h.client.put_thing(ThingId='triad-stop-new-id')
        except RequiredDiscoveryBlocked as exc:
            stop_error = exc

        connected = h.ledger.connections
        continue_rows = [r for r in connected if r.role == 'discovered']
        fallback_rows = [
            r for r in connected if r.role == 'default-fallback'
        ]
        stop_rows = h.ledger.of_kind('stop', 'connect_blocked')
        classification = {
            OUTCOME_CONTINUE: [r.address for r in continue_rows],
            OUTCOME_FALLBACK: [r.address for r in fallback_rows],
            OUTCOME_STOP: [r.blocker for r in stop_rows],
        }
        return {
            'name': 'TRIAD',
            'ledger': h.ledger,
            'classification': classification,
            'stop_error': stop_error,
            'targets': _targets(h.ledger),
        }


# ---------------------------------------------------------------------------
# pytest coverage
# ---------------------------------------------------------------------------


def test_policy_precedence_and_live_version():
    policy = EgressPolicy(
        allowed=['127.0.0.1:9000', '127.0.0.1:9101'],
        default_endpoints=['127.0.0.1:9000'],
    )
    assert policy.admit(LEGAL_EP).reason == 'baseline_allowed'
    pending = policy.observe(PENDING_EP)
    assert pending.allowed is False
    assert pending.blocker == 'approval-workflow:pending-approval'
    version = policy.approve(PENDING_EP)
    assert policy.admit(PENDING_EP).allowed is True
    assert policy.version == version
    policy.withdraw(LEGAL_EP)
    withdrawn = policy.admit(LEGAL_EP)
    assert withdrawn.allowed is False
    assert withdrawn.reason == 'withdrawn'
    # Withdrawal beats the still-present baseline allow rule.
    assert withdrawn.blocker == 'control-plane:withdrawn-address'

    # One atomic control-plane push can admit and revoke in a single call.
    policy.apply_update(
        approve=['127.0.0.1:9404'],
        withdraw=[LEGAL_EP],
    )
    assert policy.admit('127.0.0.1:9404').allowed is True
    assert policy.admit(LEGAL_EP).reason == 'withdrawn'


@pytest.mark.asyncio
async def test_legal_discovery_result_continues():
    result = await scenario_legal()
    assert result['error'] is None
    assert result['ok'] is True
    assert result['targets'] == ['127.0.0.1:9101']
    record = result['ledger'].connections[0]
    assert record.role == 'discovered'
    assert record.operation == 'PutThing'


@pytest.mark.asyncio
async def test_pending_result_waits_for_approval_then_continues():
    result = await scenario_pending_approval()
    assert isinstance(result['error'], RequiredDiscoveryBlocked)
    assert result['blocker'] == 'approval-workflow:pending-approval'
    assert result['targets_before_approval'] == []
    assert len(result['blocked_before']) == 1
    assert result['targets'] == ['127.0.0.1:9202']
    assert result['ok'] is True


@pytest.mark.asyncio
async def test_withdrawn_address_leaves_warm_cache_selection():
    result = await scenario_withdraw_warm_cache()
    assert result['targets_after_first'] == ['127.0.0.1:9303']
    assert result['targets'] == [
        '127.0.0.1:9303',
        '127.0.0.1:9000',
    ]
    roles = [r.role for r in result['ledger'].connections]
    assert roles == ['discovered', 'default-fallback']


@pytest.mark.asyncio
async def test_withdrawal_on_retry_moves_to_approved_default():
    result = await scenario_retry_after_withdrawal()
    assert result['targets'] == [
        '127.0.0.1:9303',
        '127.0.0.1:9000',
    ]
    # The bad endpoint is hit once; the retry never dials it again.
    assert result['volatile_hits'] == 1
    assert result['retry_attempts'] == 1


@pytest.mark.asyncio
async def test_required_operation_stops_with_blocking_source():
    result = await scenario_required_stop()
    assert isinstance(result['error'], RequiredDiscoveryBlocked)
    assert result['targets'] == []
    assert result['blocker'] == 'approval-workflow:pending-approval'
    assert result['ledger'].blocks


@pytest.mark.asyncio
async def test_optional_operation_unapproved_default_has_explicit_rule():
    from aiobotocore.egress import UnapprovedDefaultEndpoint

    result = await scenario_optional_unapproved_default()
    assert isinstance(result['error'], UnapprovedDefaultEndpoint)
    assert result['targets'] == []
    assert 'default' in (result['blocker'] or '')


@pytest.mark.asyncio
async def test_transport_seam_blocks_denied_origin():
    result = await scenario_transport_gate()
    assert result['egress_block'] is True
    assert result['targets'] == []
    blocked = result['ledger'].of_kind('connect_blocked')
    assert blocked and '9595' in (blocked[0].address or '')


@pytest.mark.asyncio
async def test_parallel_optional_and_required_are_attributed():
    result = await scenario_parallel()
    assert result['ok'] is True
    assert set(result['targets']) == {
        '127.0.0.1:9101',
        '127.0.0.1:9000',
    }
    assert result['operations'] == ['GetThing', 'PutThing']
    assert set(result['roles']) == {'default-fallback', 'discovered'}


@pytest.mark.asyncio
async def test_triad_is_classified_from_connection_records():
    result = await run_triad()
    classification = result['classification']
    assert classification[OUTCOME_CONTINUE] == ['127.0.0.1:9101']
    assert classification[OUTCOME_FALLBACK] == ['127.0.0.1:9000']
    assert classification[OUTCOME_STOP] == [
        'control-plane:withdrawn-address'
    ]
    assert isinstance(result['stop_error'], RequiredDiscoveryBlocked)
    # Actual dial targets: only the two approved origins, never the withdrawn
    # one after the control-plane update.
    assert result['targets'] == [
        '127.0.0.1:9101',
        '127.0.0.1:9000',
    ]


def test_real_tcp_connect_records():
    """Genuine loopback TCP accepts; skipped where bind(2) is forbidden."""
    import http.server
    import threading

    try:
        http.server.ThreadingHTTPServer(
            ('127.0.0.1', 0), http.server.BaseHTTPRequestHandler
        ).server_close()
    except PermissionError:
        pytest.skip('local TCP binding is not permitted in this sandbox')
    except OSError as exc:  # pragma: no cover - environment dependent
        pytest.skip(f'loopback bind unavailable: {exc}')

    hits: dict[int, int] = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 - stdlib API
            length = int(self.headers.get('Content-Length', '0'))
            if length:
                self.rfile.read(length)
            port = self.server.server_address[1]
            hits[port] = hits.get(port, 0) + 1
            payload = PUT_OK
            self.send_response(200)
            self.send_header('Content-Type', 'application/x-amz-json-1.1')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):  # silence test server logs
            pass

    servers = []
    threads = []
    origins = []
    for _ in range(2):
        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append(server)
        threads.append(thread)
        origins.append(f'http://127.0.0.1:{port}')
    default_origin, discovered_origin = origins
    try:

        async def run():
            from aiobotocore.egress import guarded_aiohttp_session_class

            policy = EgressPolicy(
                allowed=[default_origin, discovered_origin],
                default_endpoints=[default_origin],
            )
            ledger = ConnectionLedger()
            gate = EgressGate(policy, ledger)
            config = AioConfig(
                http_session_cls=guarded_aiohttp_session_class(gate),
                connector_args={
                    'force_close': True,
                    'keepalive_timeout': None,
                },
            )
            ensure_model()
            session = aiobotocore.session.AioSession()
            session.register_component(
                'data_loader',
                botocore.loaders.Loader(
                    extra_search_paths=[ensure_model()]
                ),
            )
            async with session.create_client(
                SERVICE,
                region_name='us-east-1',
                endpoint_url=default_origin,
                aws_access_key_id='test',
                aws_secret_access_key='test',
                config=config,
                verify=False,
            ) as client:
                install_endpoint_egress(
                    client,
                    gate=gate,
                    discovery_source=FakeDiscoveryService(
                        {'PutThing': [discovered_origin]}
                    ),
                    default_endpoint=default_origin,
                )
                await client.put_thing(ThingId='real-tcp')
            return ledger

        ledger = asyncio.run(run())
        disc_port = int(discovered_origin.rsplit(':', 1)[1])
        default_port = int(default_origin.rsplit(':', 1)[1])
        assert hits.get(disc_port) == 1
        assert hits.get(default_port) is None
        assert ledger.targets() == [f'127.0.0.1:{disc_port}']
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=2)


# ---------------------------------------------------------------------------
# Runnable demonstration
# ---------------------------------------------------------------------------

_SCENARIOS = (
    scenario_legal,
    scenario_pending_approval,
    scenario_required_stop,
    scenario_withdraw_warm_cache,
    scenario_retry_after_withdrawal,
    scenario_optional_unapproved_default,
    scenario_transport_gate,
    scenario_parallel,
)


async def _amain() -> int:
    print('=' * 86)
    print(' aiobotocore async endpoint discovery -- tiered egress admission demo')
    print('=' * 86)
    failures = 0
    for scenario in _SCENARIOS:
        result = await scenario()
        print('\n### ' + result['name'])
        print(result['ledger'].render())
        if result.get('error') is not None:
            print(f'    raised: {type(result["error"]).__name__}: '
                  f'{result["error"]}')
        if result.get('targets') is not None:
            print(f'    actual dial targets: {result["targets"]}')
        if 'egress_block' in result:
            print(f'    transport egress block detected: '
                  f'{result["egress_block"]}')
        if result.get('ok') is False:
            failures += 1

    triad = await run_triad()
    print('\n' + '=' * 86)
    print(' FINAL VERDICT FROM ACTUAL CONNECTION RECORDS ONLY')
    print('=' * 86)
    for outcome in (OUTCOME_CONTINUE, OUTCOME_FALLBACK, OUTCOME_STOP):
        evidence = triad['classification'][outcome]
        print(f'  {outcome:<9} -> {evidence}')
    print('\n' + triad['ledger'].render())
    print(f'\n  dial sequence: {triad["targets"]}')

    assert triad['classification'][OUTCOME_CONTINUE] == ['127.0.0.1:9101']
    assert triad['classification'][OUTCOME_FALLBACK] == ['127.0.0.1:9000']
    assert triad['classification'][OUTCOME_STOP] == [
        'control-plane:withdrawn-address'
    ]
    print('\nALL DEMONSTRATED INVARIANTS HOLD')
    return failures


if __name__ == '__main__':
    raise SystemExit(asyncio.run(_amain()))
