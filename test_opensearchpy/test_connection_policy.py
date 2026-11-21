# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.


import json
import ssl
import threading
import time
from typing import Any

import pytest

from opensearchpy import (
    ConnectionPolicy,
    ConnectionPolicyError,
    OpenSearch,
    Transport,
    Urllib3HttpConnection,
)
from opensearchpy.connection import Connection
from opensearchpy.connection_pool import ConnectionPool, DummyConnectionPool

from .test_cases import TestCase


def make_context(name: str) -> "ssl.SSLContext":
    """A local, identifiable stand-in for a company CA bundle."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.name = name
    return context


class PolicyConnection(Connection):
    """Fake connection that reports which policy generation served a call."""

    def __init__(self, **kwargs: Any) -> None:
        self.context_name = getattr(kwargs.get("ssl_context"), "name", None)
        self.ca_certs = kwargs.get("ca_certs")
        self.closed = False
        self.in_flight = threading.Event()
        self.release = threading.Event()
        self.block = kwargs.pop("block", False)
        self.status = kwargs.pop("status", 200)
        self.identity = kwargs.pop("identity", None)
        super().__init__(**kwargs)

    def perform_request(self, *args: Any, **kwargs: Any) -> Any:
        if self.block:
            self.in_flight.set()
            if not self.release.wait(5):
                raise RuntimeError("test did not release the in-flight request")
        return (
            self.status,
            {"content-type": "application/json"},
            json.dumps(
                {
                    "identity": self.identity,
                    "generation": self.generation,
                    "context": self.context_name,
                }
            ),
        )

    def close(self) -> None:
        self.closed = True


class TestConnectionPolicy(TestCase):
    def test_initial_generation_is_visible_on_connection_and_pool(self) -> None:
        t: Any = Transport(
            [{"identity": "pool-0"}],
            connection_class=PolicyConnection,
            randomize_hosts=False,
        )
        connection = t.get_connection()
        self.assertEqual(0, t.generation)
        self.assertEqual(0, connection.generation)
        self.assertEqual("initial", connection.generation_label)
        self.assertEqual(0, t.connection_pool.generation)
        self.assertEqual("initial", t.connection_pool.label)

    def test_reload_builds_a_new_generation_and_routes_new_requests_to_it(self) -> None:
        t: Any = Transport(
            [{"identity": "pool-0"}],
            connection_class=PolicyConnection,
            randomize_hosts=False,
        )
        old_pool = t.connection_pool
        self.assertEqual("pool-0", t.perform_request("GET", "/")["identity"])

        new_context = make_context("company-ca-2026")
        new_pool = t.reload_connection_policy(
            ConnectionPolicy(
                hosts=[{"identity": "pool-1"}],
                generation="ca-2026",
                label="company-ca-2026",
                options={"ssl_context": new_context, "use_ssl": True},
            )
        )

        self.assertIsNot(old_pool, new_pool)
        self.assertIs(t.connection_pool, new_pool)
        self.assertEqual("ca-2026", t.generation)
        self.assertTrue(old_pool.connections[0].closed)
        response = t.perform_request("GET", "/")
        self.assertEqual("pool-1", response["identity"])
        self.assertEqual("ca-2026", response["generation"])
        self.assertEqual("company-ca-2026", response["context"])
        self.assertEqual("company-ca-2026", t.get_connection().context_name)

    def test_old_pool_survives_until_the_last_in_flight_request_finishes(self) -> None:
        t: Any = Transport(
            [{"identity": "pool-0", "block": True}],
            connection_class=PolicyConnection,
            randomize_hosts=False,
        )
        old_pool = t.connection_pool
        old_connection = old_pool.connections[0]
        results: Any = []

        def call_old_pool() -> None:
            results.append(t.perform_request("GET", "/"))

        worker = threading.Thread(target=call_old_pool)
        worker.start()
        self.assertTrue(old_connection.in_flight.wait(5))

        t.reload_connection_policy(
            ConnectionPolicy(
                hosts=[{"identity": "pool-1"}],
                generation="ca-2026",
                options={"ssl_context": make_context("company-ca-2026")},
            )
        )
        # The request was delegated before the switch: it must not be closed
        # out from under the caller, and it completes under the old policy.
        self.assertFalse(old_connection.closed)
        self.assertEqual("pool-1", t.perform_request("GET", "/")["identity"])

        old_connection.release.set()
        worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual("pool-0", results[0]["identity"])
        self.assertEqual(0, results[0]["generation"])
        self.assertTrue(old_connection.closed)
        self.assertEqual("pool-1", t.perform_request("GET", "/")["identity"])

    def test_invalid_policy_keeps_the_original_pool_usable(self) -> None:
        t: Any = Transport(
            [{"identity": "pool-0"}],
            connection_class=PolicyConnection,
            randomize_hosts=False,
        )
        old_pool = t.connection_pool

        with self.assertRaises(ConnectionPolicyError):
            t.reload_connection_policy(
                ConnectionPolicy(
                    hosts=[{"identity": "pool-1"}],
                    generation="broken",
                    options={"ssl_context": "not-an-ssl-context"},
                )
            )

        self.assertIs(old_pool, t.connection_pool)
        self.assertEqual(0, t.generation)
        self.assertFalse(old_pool.connections[0].closed)
        self.assertEqual("pool-0", t.perform_request("GET", "/")["identity"])

    def test_missing_ca_bundle_is_rejected_before_the_swap(self) -> None:
        t: Any = Transport(
            [{"identity": "pool-0"}],
            connection_class=PolicyConnection,
            randomize_hosts=False,
        )
        old_pool = t.connection_pool

        with self.assertRaises(ConnectionPolicyError):
            t.reload_connection_policy(
                {
                    "hosts": [{"identity": "pool-1"}],
                    "generation": "broken",
                    "verify_certs": True,
                    "ca_certs": "/does/not/exist/company-ca.pem",
                }
            )

        self.assertIs(old_pool, t.connection_pool)
        self.assertEqual("pool-0", t.perform_request("GET", "/")["identity"])

    def test_failing_policy_loader_keeps_the_original_pool_usable(self) -> None:
        t: Any = Transport(
            [{"identity": "pool-0"}],
            connection_class=PolicyConnection,
            randomize_hosts=False,
        )
        old_pool = t.connection_pool

        def loader() -> ConnectionPolicy:
            raise OSError("CA bundle is not readable")

        with self.assertRaises(ConnectionPolicyError):
            t.reload_connection_policy(loader)

        self.assertIs(old_pool, t.connection_pool)
        self.assertEqual("pool-0", t.perform_request("GET", "/")["identity"])

    def test_policy_tls_options_replace_stale_ones(self) -> None:
        t: Any = Transport(
            [{"identity": "pool-0"}],
            connection_class=PolicyConnection,
            ca_certs="/old/ca.pem",
        )
        t.reload_connection_policy(
            ConnectionPolicy(
                hosts=[{"identity": "pool-1"}],
                generation=1,
                options={"ssl_context": make_context("new-ca")},
            )
        )
        connection = t.get_connection()
        self.assertEqual("new-ca", connection.context_name)
        self.assertIsNone(connection.ca_certs)

    def test_client_exposes_policy_reload(self) -> None:
        client = OpenSearch(
            [{"host": "localhost", "port": 9200}],
            connection_class=PolicyConnection,
            transport_class=Transport,
        )
        new_pool = client.transport.reload_connection_policy(
            ConnectionPolicy(
                hosts=[{"host": "localhost", "port": 9200}],
                generation="ca-2",
            )
        )
        self.assertEqual("ca-2", client.transport.generation)
        self.assertEqual("ca-2", new_pool.generation)
        self.assertIs(new_pool, client.transport.connection_pool)

    def test_second_reload_does_not_inherit_previous_policy_tls(self) -> None:
        t: Any = Transport(
            [{"identity": "pool-0"}],
            connection_class=PolicyConnection,
            randomize_hosts=False,
        )
        t.reload_connection_policy(
            ConnectionPolicy(
                hosts=[{"identity": "pool-1"}],
                generation="ca-1",
                options={"ssl_context": make_context("company-ca-1")},
            )
        )
        t.reload_connection_policy(
            ConnectionPolicy(
                hosts=[{"identity": "pool-2", "ca_certs": "/new/company-ca.pem"}],
                generation="ca-2",
            )
        )
        connection = t.get_connection()
        self.assertEqual("ca-2", connection.generation)
        self.assertIsNone(connection.context_name)
        self.assertEqual("/new/company-ca.pem", connection.ca_certs)


class TestAsyncConnectionPolicy:
    @pytest.mark.asyncio
    async def test_async_reload_and_failed_load(self) -> None:
        from opensearchpy import AsyncTransport

        class AsyncPolicyConnection(PolicyConnection):
            async def perform_request(self, *args: Any, **kwargs: Any) -> Any:
                return super().perform_request(*args, **kwargs)

            async def close(self) -> None:
                self.closed = True

        t: Any = AsyncTransport(
            [{"identity": "pool-0"}],
            connection_class=AsyncPolicyConnection,
            randomize_hosts=False,
        )
        await t._async_call()
        old_pool = t.connection_pool
        response = await t.perform_request("GET", "/")
        assert response["identity"] == "pool-0"

        with pytest.raises(ConnectionPolicyError):
            await t.reload_connection_policy(
                {"hosts": [{"identity": "bad"}], "ssl_context": object()}
            )
        assert t.connection_pool is old_pool
        assert (await t.perform_request("GET", "/"))["identity"] == "pool-0"

        await t.reload_connection_policy(
            ConnectionPolicy(
                hosts=[{"identity": "pool-1"}],
                generation="ca-2026",
                options={"ssl_context": make_context("company-ca-2026")},
            )
        )
        response = await t.perform_request("GET", "/")
        assert response["identity"] == "pool-1"
        assert response["generation"] == "ca-2026"
        assert response["context"] == "company-ca-2026"
        assert old_pool.connections[0].closed is True
        await t.close()
