# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.

import json
from typing import Any

import pytest

from opensearchpy import AsyncTransport, Transport
from opensearchpy.connection import Connection
from opensearchpy.exceptions import ConnectionError, TransportError

APPROVED_NODE = ("10.1.0.10", 9200)
UNKNOWN_NODE = ("203.0.113.7", 9200)


def _nodes_response(*addresses: str) -> str:
    nodes = {}
    for index, address in enumerate(addresses):
        nodes["node-%i" % index] = {
            "name": "node-%i" % index,
            "roles": ["data"],
            "http": {"publish_address": address},
        }
    return json.dumps({"_nodes": {"total": len(nodes)}, "nodes": nodes})


def _node(host: str, port: int, **kwargs: Any) -> dict:
    host_opts = {"host": host, "port": port}
    host_opts.update(kwargs)
    return host_opts


class _FakeConnectionBase(Connection):
    def __init__(self, **kwargs: Any) -> None:
        self.node_data = kwargs.pop("node_data", "{}")
        self.fail_times = kwargs.pop("fail_times", 0)
        self.failures = 0
        self.requests: Any = []
        super().__init__(**kwargs)

    def _record_request(self, args: Any, kwargs: Any) -> Any:
        if args[:2] == ("GET", "/_nodes/_all/http"):
            self.requests.append(("sniff", args, kwargs))
            return "sniff", 200, {}, self.node_data

        self.requests.append(("request", args, kwargs))
        if self.failures < self.fail_times:
            self.failures += 1
            raise ConnectionError(None, "connection refused", Exception())
        return "request", 200, {}, "{}"


class FakeConnection(_FakeConnectionBase):
    def perform_request(self, *args: Any, **kwargs: Any) -> Any:
        _, status, headers, data = self._record_request(args, kwargs)
        return status, headers, data


class AsyncFakeConnection(_FakeConnectionBase):
    async def perform_request(self, *args: Any, **kwargs: Any) -> Any:
        _, status, headers, data = self._record_request(args, kwargs)
        return status, headers, data

    async def close(self) -> None:
        pass


def _real_requests(*connection_groups: Any) -> Any:
    seen = set()
    requests = []
    for group in connection_groups:
        for connection in group:
            if id(connection) in seen:
                continue
            seen.add(id(connection))
            requests.extend(
                (connection.host, args[0])
                for kind, args, _ in connection.requests
                if kind == "request"
            )
    return requests


def _hosts_in_pool(transport: Any) -> Any:
    return sorted(
        connection.host for connection in transport.connection_pool.connections
    )


class TestSyncSniffAccessPolicy:
    def test_initial_connection_uses_only_approved_hosts(self) -> None:
        t: Any = Transport(
            [_node(*APPROVED_NODE)],
            connection_class=FakeConnection,
            allowed_hosts=["10.0.0.0/8"],
            randomize_hosts=False,
            sniff_on_start=True,
            node_data=_nodes_response("10.1.0.10:9200", "203.0.113.7:9200"),
        )

        assert _hosts_in_pool(t) == ["http://10.1.0.10:9200"]

    def test_refresh_pool_drops_unknown_hosts(self) -> None:
        t: Any = Transport(
            [_node(*APPROVED_NODE)],
            connection_class=FakeConnection,
            allowed_hosts=["10.0.0.0/8"],
            randomize_hosts=False,
            node_data=_nodes_response("10.1.0.10:9200", "203.0.113.7:9200"),
        )
        t.sniff_hosts()

        assert _hosts_in_pool(t) == ["http://10.1.0.10:9200"]

    def test_refresh_accepts_approved_hostname_wildcard(self) -> None:
        t: Any = Transport(
            [_node(*APPROVED_NODE)],
            connection_class=FakeConnection,
            allowed_hosts=["*.search.internal"],
            randomize_hosts=False,
            node_data=_nodes_response(
                "node-1.search.internal:9200", "node-1.other.internal:9200"
            ),
        )
        t.sniff_hosts()

        assert _hosts_in_pool(t) == ["http://node-1.search.internal:9200"]

    def test_empty_discovery_keeps_existing_approved_connections(self) -> None:
        t: Any = Transport(
            [_node(*APPROVED_NODE)],
            connection_class=FakeConnection,
            allowed_hosts=["10.0.0.0/8"],
            randomize_hosts=False,
            node_data=_nodes_response(),
        )
        seeds = list(t.connection_pool.connections)

        t.sniff_hosts()

        assert list(t.connection_pool.connections) == seeds
        initial_connections = list(t.connection_pool.connections)
        t.perform_request("GET", "/")
        assert _real_requests(initial_connections, t.connection_pool.connections) == [
            ("http://10.1.0.10:9200", "GET")
        ]

    def test_all_rejected_discovery_keeps_existing_connections(self) -> None:
        t: Any = Transport(
            [_node(*APPROVED_NODE)],
            connection_class=FakeConnection,
            allowed_hosts=["10.0.0.0/8"],
            randomize_hosts=False,
            node_data=_nodes_response("203.0.113.7:9200"),
        )
        seeds = list(t.connection_pool.connections)

        t.sniff_hosts()

        assert list(t.connection_pool.connections) == seeds

    def test_retry_does_not_reach_rejected_discovered_hosts(self) -> None:
        t: Any = Transport(
            [
                _node(*APPROVED_NODE, fail_times=1),
                _node("10.1.0.11", 9200),
            ],
            connection_class=FakeConnection,
            allowed_hosts=["10.0.0.0/8"],
            randomize_hosts=False,
            sniff_on_connection_fail=True,
            max_retries=3,
            node_data=_nodes_response("10.1.0.11:9200", "203.0.113.7:9200"),
        )

        initial_connections = list(t.connection_pool.connections)
        t.perform_request("GET", "/")

        # The failed seed was retired; the remaining approved connections
        # continue to serve.
        assert _hosts_in_pool(t) == ["http://10.1.0.11:9200"]
        # Every real request, including the retry after the failed one, went
        # to an approved host.
        assert set(
            _real_requests(initial_connections, t.connection_pool.connections)
        ) == {
            ("http://10.1.0.10:9200", "GET"),
            ("http://10.1.0.11:9200", "GET"),
        }

    def test_retry_after_all_rejected_discovery_uses_existing_hosts(self) -> None:
        t: Any = Transport(
            [
                _node(*APPROVED_NODE, fail_times=1),
                _node("10.1.0.11", 9200),
            ],
            connection_class=FakeConnection,
            allowed_hosts=["10.0.0.0/8"],
            randomize_hosts=False,
            sniff_on_connection_fail=True,
            max_retries=3,
            node_data=_nodes_response("203.0.113.7:9200"),
        )

        initial_connections = list(t.connection_pool.connections)
        t.perform_request("GET", "/")

        assert _hosts_in_pool(t) == ["http://10.1.0.11:9200"]
        hosts = {
            host
            for host, _ in _real_requests(
                initial_connections, t.connection_pool.connections
            )
        }
        assert hosts == {"http://10.1.0.10:9200", "http://10.1.0.11:9200"}

    def test_unapproved_seed_host_is_still_a_configured_entry_point(self) -> None:
        # The policy governs discovery only; explicitly configured hosts are
        # the application's approved entry points.
        t: Any = Transport(
            [_node(*UNKNOWN_NODE)],
            connection_class=FakeConnection,
            allowed_hosts=["10.0.0.0/8"],
            randomize_hosts=False,
            node_data=_nodes_response("203.0.113.7:9200"),
        )

        t.perform_request("GET", "/")

        assert _hosts_in_pool(t) == ["http://203.0.113.7:9200"]
        assert _real_requests(t.connection_pool.connections) == [
            ("http://203.0.113.7:9200", "GET")
        ]


class TestAsyncSniffAccessPolicy:
    async def test_initial_connection_uses_only_approved_hosts(self) -> None:
        t: Any = AsyncTransport(
            [_node(*APPROVED_NODE)],
            connection_class=AsyncFakeConnection,
            allowed_hosts=["10.0.0.0/8"],
            randomize_hosts=False,
            sniff_on_start=True,
            node_data=_nodes_response("10.1.0.10:9200", "203.0.113.7:9200"),
        )

        await t._async_call()

        assert _hosts_in_pool(t) == ["http://10.1.0.10:9200"]

    async def test_refresh_pool_drops_unknown_hosts(self) -> None:
        t: Any = AsyncTransport(
            [_node(*APPROVED_NODE)],
            connection_class=AsyncFakeConnection,
            allowed_hosts=["10.0.0.0/8"],
            randomize_hosts=False,
            node_data=_nodes_response("10.1.0.10:9200", "203.0.113.7:9200"),
        )
        await t._async_call()
        await t.sniff_hosts()

        assert _hosts_in_pool(t) == ["http://10.1.0.10:9200"]

    async def test_empty_discovery_keeps_existing_approved_connections(self) -> None:
        t: Any = AsyncTransport(
            [_node(*APPROVED_NODE)],
            connection_class=AsyncFakeConnection,
            allowed_hosts=["10.0.0.0/8"],
            randomize_hosts=False,
            node_data=_nodes_response(),
        )
        await t._async_call()
        seeds = list(t.connection_pool.connections)

        await t.sniff_hosts()

        assert list(t.connection_pool.connections) == seeds
        await t._async_call()
        initial_connections = list(t.connection_pool.connections)
        await t.perform_request("GET", "/")
        assert _real_requests(initial_connections, t.connection_pool.connections) == [
            ("http://10.1.0.10:9200", "GET")
        ]

    async def test_retry_does_not_reach_rejected_discovered_hosts(self) -> None:
        t: Any = AsyncTransport(
            [
                _node(*APPROVED_NODE, fail_times=1),
                _node("10.1.0.11", 9200),
            ],
            connection_class=AsyncFakeConnection,
            allowed_hosts=["10.0.0.0/8"],
            randomize_hosts=False,
            sniff_on_connection_fail=True,
            max_retries=3,
            node_data=_nodes_response("10.1.0.11:9200", "203.0.113.7:9200"),
        )

        await t._async_call()
        initial_connections = list(t.connection_pool.connections)
        await t.perform_request("GET", "/")

        assert _hosts_in_pool(t) == ["http://10.1.0.11:9200"]
        assert set(
            _real_requests(initial_connections, t.connection_pool.connections)
        ) == {
            ("http://10.1.0.10:9200", "GET"),
            ("http://10.1.0.11:9200", "GET"),
        }

    async def test_retry_after_all_rejected_discovery_uses_existing_hosts(self) -> None:
        t: Any = AsyncTransport(
            [
                _node(*APPROVED_NODE, fail_times=1),
                _node("10.1.0.11", 9200),
            ],
            connection_class=AsyncFakeConnection,
            allowed_hosts=["10.0.0.0/8"],
            randomize_hosts=False,
            sniff_on_connection_fail=True,
            max_retries=3,
            node_data=_nodes_response("203.0.113.7:9200"),
        )

        await t._async_call()
        initial_connections = list(t.connection_pool.connections)
        await t.perform_request("GET", "/")

        assert _hosts_in_pool(t) == ["http://10.1.0.11:9200"]
        hosts = {
            host
            for host, _ in _real_requests(
                initial_connections, t.connection_pool.connections
            )
        }
        assert hosts == {"http://10.1.0.10:9200", "http://10.1.0.11:9200"}


class TestNoPolicyKeepsPreviousBehavior:
    def test_sync_empty_discovery_still_raises_without_policy(self) -> None:
        t: Any = Transport(
            [_node(*APPROVED_NODE)],
            connection_class=FakeConnection,
            randomize_hosts=False,
            node_data=_nodes_response(),
        )

        with pytest.raises(TransportError):
            t.sniff_hosts()

    async def test_async_empty_discovery_still_raises_without_policy(self) -> None:
        t: Any = AsyncTransport(
            [_node(*APPROVED_NODE)],
            connection_class=AsyncFakeConnection,
            randomize_hosts=False,
            node_data=_nodes_response(),
        )
        await t._async_call()

        with pytest.raises(TransportError):
            await t.sniff_hosts()
