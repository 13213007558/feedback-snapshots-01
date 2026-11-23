# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.
#
#  Licensed to Elasticsearch B.V. under one or more contributor
#  license agreements. See the NOTICE file distributed with
#  this work for additional information regarding copyright
#  ownership. Elasticsearch B.V. licenses this file to you under
#  the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
# 	http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing,
#  software distributed under the License is distributed on an
#  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
#  KIND, either express or implied.  See the License for the
#  specific language governing permissions and limitations
#  under the License.


import asyncio
import json
from typing import Any
from unittest.mock import patch

import pytest
from _pytest.mark.structures import MarkDecorator

from opensearchpy import AIOHttpConnection, AsyncTransport
from opensearchpy.connection import Connection
from opensearchpy.connection_pool import DummyConnectionPool
from opensearchpy.exceptions import (
    ConnectionError,
    SerializationError,
    TransportError,
    UnsupportedResponseFormatError,
)
from opensearchpy.serializer import Serializer

pytestmark: MarkDecorator = pytest.mark.asyncio


class PluginFormatSerializer(Serializer):
    """Custom response format only registered for internal plugin requests."""

    mimetype = "application/vnd.opensearch.plugin+json"

    def __init__(self) -> None:
        self.load_calls = 0

    def loads(self, s: Any) -> Any:
        self.load_calls += 1
        return {"plugin_only": True, "raw": s}

    def dumps(self, data: Any) -> Any:
        return str(data)


class DummyConnection(Connection):
    def __init__(self, **kwargs: Any) -> None:
        self.exception = kwargs.pop("exception", None)
        self.status, self.data = kwargs.pop("status", 200), kwargs.pop("data", "{}")
        # The host options carry the fake *response* headers. ``Connection``
        # seeds its own request headers, so keep a private copy for replies.
        self.response_headers = dict(kwargs.pop("headers", {}) or {})
        self.headers = {}
        self.delay = kwargs.pop("delay", 0)
        self.calls: Any = []
        self.closed = False
        super().__init__(**kwargs)

    async def perform_request(self, *args: Any, **kwargs: Any) -> Any:
        if self.closed:
            raise RuntimeError("This connection is closed")
        if self.delay:
            await asyncio.sleep(self.delay)
        self.calls.append((args, kwargs))
        if self.exception:
            raise self.exception
        return self.status, self.response_headers, self.data

    async def close(self) -> None:
        if self.closed:
            raise RuntimeError("This connection is already closed")
        self.closed = True


CLUSTER_NODES = """{
  "_nodes" : {
    "total" : 1,
    "successful" : 1,
    "failed" : 0
  },
  "cluster_name" : "opensearch",
  "nodes" : {
    "SRZpKFZdQguhhvifmN6UVA" : {
      "name" : "SRZpKFZ",
      "transport_address" : "127.0.0.1:9300",
      "host" : "127.0.0.1",
      "ip" : "127.0.0.1",
      "version" : "5.0.0",
      "build_hash" : "253032b",
      "roles" : [ "cluster_manager", "data", "ingest" ],
      "http" : {
        "bound_address" : [ "[fe80::1]:9200", "[::1]:9200", "127.0.0.1:9200" ],
        "publish_address" : "1.1.1.1:123",
        "max_content_length_in_bytes" : 104857600
      }
    }
  }
}"""

CLUSTER_NODES_7X_PUBLISH_HOST = """{
  "_nodes" : {
    "total" : 1,
    "successful" : 1,
    "failed" : 0
  },
  "cluster_name" : "opensearch",
  "nodes" : {
    "SRZpKFZdQguhhvifmN6UVA" : {
      "name" : "SRZpKFZ",
      "transport_address" : "127.0.0.1:9300",
      "host" : "127.0.0.1",
      "ip" : "127.0.0.1",
      "version" : "5.0.0",
      "build_hash" : "253032b",
      "roles" : [ "cluster_manager", "data", "ingest" ],
      "http" : {
        "bound_address" : [ "[fe80::1]:9200", "[::1]:9200", "127.0.0.1:9200" ],
        "publish_address" : "somehost.tld/1.1.1.1:123",
        "max_content_length_in_bytes" : 104857600
      }
    }
  }
}"""


class TestTransport:
    async def test_single_connection_uses_dummy_connection_pool(self) -> None:
        t1: Any = AsyncTransport([{}])
        await t1._async_call()
        assert isinstance(t1.connection_pool, DummyConnectionPool)
        t2: Any = AsyncTransport([{"host": "localhost"}])
        await t2._async_call()
        assert isinstance(t2.connection_pool, DummyConnectionPool)

    async def test_request_timeout_extracted_from_params_and_passed(self) -> None:
        t: Any = AsyncTransport([{}], connection_class=DummyConnection)

        await t.perform_request("GET", "/", params={"request_timeout": 42})
        assert 1 == len(t.get_connection().calls)
        assert ("GET", "/", {}, None) == t.get_connection().calls[0][0]
        assert {
            "timeout": 42,
            "ignore": (),
            "headers": None,
        } == t.get_connection().calls[0][1]

    async def test_timeout_extracted_from_params_and_passed(self) -> None:
        t: Any = AsyncTransport([{}], connection_class=DummyConnection)

        await t.perform_request("GET", "/", params={"timeout": 84})
        assert 1 == len(t.get_connection().calls)
        assert ("GET", "/", {}, None) == t.get_connection().calls[0][0]
        assert {
            "timeout": 84,
            "ignore": (),
            "headers": None,
        } == t.get_connection().calls[0][1]

    async def test_opaque_id(self) -> None:
        t: Any = AsyncTransport(
            [{}], opaque_id="app-1", connection_class=DummyConnection
        )

        await t.perform_request("GET", "/")
        assert 1 == len(t.get_connection().calls)
        assert ("GET", "/", None, None) == t.get_connection().calls[0][0]
        assert {
            "timeout": None,
            "ignore": (),
            "headers": None,
        } == t.get_connection().calls[0][1]

        # Now try with an 'x-opaque-id' set on perform_request().
        await t.perform_request("GET", "/", headers={"x-opaque-id": "request-1"})
        assert 2 == len(t.get_connection().calls)
        assert ("GET", "/", None, None) == t.get_connection().calls[1][0]
        assert {
            "timeout": None,
            "ignore": (),
            "headers": {"x-opaque-id": "request-1"},
        } == t.get_connection().calls[1][1]

    async def test_perform_request_all_arguments_passed_correctly(self) -> None:
        t: Any = AsyncTransport([{}], connection_class=DummyConnection)
        method, url, params, body = "GET", "/test_url", {"params": "test"}, "test_body"
        timeout, ignore, headers = 11, ("ignore",), {"h": "test"}

        await t.perform_request(method, url, params, body, timeout, ignore, headers)

        assert t.get_connection().calls == [
            (
                (method, url, params, body.encode()),
                {"headers": headers, "ignore": ignore, "timeout": timeout},
            )
        ]

    async def test_request_with_custom_user_agent_header(self) -> None:
        t: Any = AsyncTransport([{}], connection_class=DummyConnection)

        await t.perform_request(
            "GET", "/", headers={"user-agent": "my-custom-value/1.2.3"}
        )
        assert 1 == len(t.get_connection().calls)
        assert {
            "timeout": None,
            "ignore": (),
            "headers": {"user-agent": "my-custom-value/1.2.3"},
        } == t.get_connection().calls[0][1]

    async def test_send_get_body_as_source(self) -> None:
        t: Any = AsyncTransport(
            [{}], send_get_body_as="source", connection_class=DummyConnection
        )

        await t.perform_request("GET", "/", body={})
        assert 1 == len(t.get_connection().calls)
        assert ("GET", "/", {"source": "{}"}, None) == t.get_connection().calls[0][0]

    async def test_send_get_body_as_post(self) -> None:
        t: Any = AsyncTransport(
            [{}], send_get_body_as="POST", connection_class=DummyConnection
        )

        await t.perform_request("GET", "/", body={})
        assert 1 == len(t.get_connection().calls)
        assert ("POST", "/", None, b"{}") == t.get_connection().calls[0][0]

    async def test_body_gets_encoded_into_bytes(self) -> None:
        t: Any = AsyncTransport([{}], connection_class=DummyConnection)

        await t.perform_request("GET", "/", body="你好")
        assert 1 == len(t.get_connection().calls)
        assert (
            "GET",
            "/",
            None,
            b"\xe4\xbd\xa0\xe5\xa5\xbd",
        ) == t.get_connection().calls[0][0]

    async def test_body_bytes_get_passed_untouched(self) -> None:
        t: Any = AsyncTransport([{}], connection_class=DummyConnection)

        body = b"\xe4\xbd\xa0\xe5\xa5\xbd"
        await t.perform_request("GET", "/", body=body)
        assert 1 == len(t.get_connection().calls)
        assert ("GET", "/", None, body) == t.get_connection().calls[0][0]

    async def test_body_surrogates_replaced_encoded_into_bytes(self) -> None:
        t: Any = AsyncTransport([{}], connection_class=DummyConnection)

        await t.perform_request("GET", "/", body="你好\uda6a")
        assert 1 == len(t.get_connection().calls)
        assert (
            "GET",
            "/",
            None,
            b"\xe4\xbd\xa0\xe5\xa5\xbd\xed\xa9\xaa",
        ) == t.get_connection().calls[0][0]

    async def test_kwargs_passed_on_to_connections(self) -> None:
        t: Any = AsyncTransport([{"host": "google.com"}], port=123)
        await t._async_call()
        assert 1 == len(t.connection_pool.connections)
        assert "http://google.com:123" == t.connection_pool.connections[0].host

    async def test_kwargs_passed_on_to_connection_pool(self) -> None:
        dt = object()
        t: Any = AsyncTransport([{}, {}], dead_timeout=dt)
        await t._async_call()
        assert dt is t.connection_pool.dead_timeout

    async def test_custom_connection_class(self) -> None:
        class MyConnection:
            def __init__(self, **kwargs: Any) -> None:
                self.kwargs = kwargs

        t: Any = AsyncTransport([{}], connection_class=MyConnection)
        await t._async_call()
        assert 1 == len(t.connection_pool.connections)
        assert isinstance(t.connection_pool.connections[0], MyConnection)

    async def test_add_connection(self) -> None:
        t: Any = AsyncTransport([{}], randomize_hosts=False)
        t.add_connection({"host": "google.com", "port": 1234})

        assert 2 == len(t.connection_pool.connections)
        assert "http://google.com:1234" == t.connection_pool.connections[1].host

    async def test_request_will_fail_after_x_retries(self) -> None:
        t: Any = AsyncTransport(
            [{"exception": ConnectionError(None, "abandon ship", Exception())}],
            connection_class=DummyConnection,
        )

        connection_error = False
        try:
            await t.perform_request("GET", "/")
        except ConnectionError:
            connection_error = True

        assert connection_error
        assert 4 == len(t.get_connection().calls)

    async def test_failed_connection_will_be_marked_as_dead(self) -> None:
        t: Any = AsyncTransport(
            [{"exception": ConnectionError(None, "abandon ship", Exception())}] * 2,
            connection_class=DummyConnection,
        )

        connection_error = False
        try:
            await t.perform_request("GET", "/")
        except ConnectionError:
            connection_error = True

        assert connection_error
        assert 0 == len(t.connection_pool.connections)

    async def test_resurrected_connection_will_be_marked_as_live_on_success(
        self,
    ) -> None:
        for method in ("GET", "HEAD"):
            t: Any = AsyncTransport([{}, {}], connection_class=DummyConnection)
            await t._async_call()
            con1 = t.connection_pool.get_connection()
            con2 = t.connection_pool.get_connection()
            t.connection_pool.mark_dead(con1)
            t.connection_pool.mark_dead(con2)

            await t.perform_request(method, "/")
            assert 1 == len(t.connection_pool.connections)
            assert 1 == len(t.connection_pool.dead_count)

    async def test_sniff_will_use_seed_connections(self) -> None:
        t: Any = AsyncTransport(
            [{"data": CLUSTER_NODES}], connection_class=DummyConnection
        )
        await t._async_call()
        t.set_connections([{"data": "invalid"}])

        await t.sniff_hosts()
        assert 1 == len(t.connection_pool.connections)
        assert "http://1.1.1.1:123" == t.get_connection().host

    async def test_sniff_on_start_fetches_and_uses_nodes_list(self) -> None:
        t: Any = AsyncTransport(
            [{"data": CLUSTER_NODES}],
            connection_class=DummyConnection,
            sniff_on_start=True,
        )
        await t._async_call()
        await t.sniffing_task  # Need to wait for the sniffing task to complete

        assert 1 == len(t.connection_pool.connections)
        assert "http://1.1.1.1:123" == t.get_connection().host

    async def test_sniff_on_start_ignores_sniff_timeout(self) -> None:
        t: Any = AsyncTransport(
            [{"data": CLUSTER_NODES}],
            connection_class=DummyConnection,
            sniff_on_start=True,
            sniff_timeout=12,
        )
        await t._async_call()
        await t.sniffing_task  # Need to wait for the sniffing task to complete

        assert (("GET", "/_nodes/_all/http"), {"timeout": None}) == t.seed_connections[
            0
        ].calls[0]

    async def test_sniff_uses_sniff_timeout(self) -> None:
        t: Any = AsyncTransport(
            [{"data": CLUSTER_NODES}],
            connection_class=DummyConnection,
            sniff_timeout=42,
        )
        await t._async_call()
        await t.sniff_hosts()

        assert (("GET", "/_nodes/_all/http"), {"timeout": 42}) == t.seed_connections[
            0
        ].calls[0]

    async def test_sniff_reuses_connection_instances_if_possible(self) -> None:
        t: Any = AsyncTransport(
            [{"data": CLUSTER_NODES}, {"host": "1.1.1.1", "port": 123}],
            connection_class=DummyConnection,
            randomize_hosts=False,
        )
        await t._async_call()
        connection = t.connection_pool.connections[1]
        connection.delay = 3.0  # Add this delay to make the sniffing deterministic.

        await t.sniff_hosts()
        assert 1 == len(t.connection_pool.connections)
        assert connection is t.get_connection()

    async def test_sniff_on_fail_triggers_sniffing_on_fail(self) -> None:
        t: Any = AsyncTransport(
            [
                {"exception": ConnectionError(None, "abandon ship", Exception())},
                {"data": CLUSTER_NODES},
            ],
            connection_class=DummyConnection,
            sniff_on_connection_fail=True,
            max_retries=0,
            randomize_hosts=False,
        )
        await t._async_call()

        connection_error = False
        try:
            await t.perform_request("GET", "/")
        except ConnectionError:
            connection_error = True

        await t.sniffing_task  # Need to wait for the sniffing task to complete

        assert connection_error
        assert 1 == len(t.connection_pool.connections)
        assert "http://1.1.1.1:123" == t.get_connection().host

    @patch("opensearchpy._async.transport.AsyncTransport.sniff_hosts")
    async def test_sniff_on_fail_failing_does_not_prevent_retires(
        self, sniff_hosts: Any
    ) -> None:
        sniff_hosts.side_effect = [TransportError("sniff failed")]
        t: Any = AsyncTransport(
            [
                {"exception": ConnectionError(None, "abandon ship", Exception())},
                {"data": CLUSTER_NODES},
            ],
            connection_class=DummyConnection,
            sniff_on_connection_fail=True,
            max_retries=3,
            randomize_hosts=False,
        )
        await t._async_init()

        conn_err, conn_data = t.connection_pool.connections
        response = await t.perform_request("GET", "/")
        assert json.loads(CLUSTER_NODES) == response
        assert 1 == sniff_hosts.call_count
        assert 1 == len(conn_err.calls)
        assert 1 == len(conn_data.calls)

    async def test_sniff_after_n_seconds(self) -> None:
        event_loop = asyncio.get_event_loop()

        t: Any = AsyncTransport(
            [{"data": CLUSTER_NODES}],
            connection_class=DummyConnection,
            sniffer_timeout=5,
        )
        await t._async_call()

        for _ in range(4):
            await t.perform_request("GET", "/")
        assert 1 == len(t.connection_pool.connections)
        assert isinstance(t.get_connection(), DummyConnection)
        t.last_sniff = event_loop.time() - 5.1

        await t.perform_request("GET", "/")
        await t.sniffing_task  # Need to wait for the sniffing task to complete

        assert 1 == len(t.connection_pool.connections)
        assert "http://1.1.1.1:123" == t.get_connection().host
        assert event_loop.time() - 1 < t.last_sniff < event_loop.time() + 0.01

    async def test_sniff_7x_publish_host(self) -> None:
        """
        Test the response shaped when a 7.x node has publish_host set
        and the returned data is shaped in the fqdn/ip:port format.
        """
        t: Any = AsyncTransport(
            [{"data": CLUSTER_NODES_7X_PUBLISH_HOST}],
            connection_class=DummyConnection,
            sniff_timeout=42,
        )
        await t._async_call()
        await t.sniff_hosts()
        # Ensure we parsed out the fqdn and port from the fqdn/ip:port string.
        assert t.connection_pool.connection_opts[0][1] == {
            "host": "somehost.tld",
            "port": 123,
        }

    async def test_transport_close_closes_all_pool_connections(self) -> None:
        t1: Any = AsyncTransport([{}], connection_class=DummyConnection)
        await t1._async_call()

        assert not any([conn.closed for conn in t1.connection_pool.connections])
        await t1.close()
        assert all([conn.closed for conn in t1.connection_pool.connections])

        t2: Any = AsyncTransport([{}, {}], connection_class=DummyConnection)
        await t2._async_call()

        assert not any([conn.closed for conn in t2.connection_pool.connections])
        await t2.close()
        assert all([conn.closed for conn in t2.connection_pool.connections])

    async def test_sniff_on_start_error_if_no_sniffed_hosts(self) -> None:
        t: Any = AsyncTransport(
            [
                {"data": ""},
                {"data": ""},
                {"data": ""},
            ],
            connection_class=DummyConnection,
            sniff_on_start=True,
        )

        # If our initial sniffing attempt comes back
        # empty then we raise an error.
        with pytest.raises(TransportError) as e:
            await t._async_call()
        assert str(e.value) == "TransportError(N/A, 'Unable to sniff hosts.')"

    async def test_sniff_on_start_waits_for_sniff_to_complete(self) -> None:
        event_loop = asyncio.get_event_loop()

        t: Any = AsyncTransport(
            [
                {"delay": 1, "data": ""},
                {"delay": 1, "data": ""},
                {"delay": 1, "data": CLUSTER_NODES},
            ],
            connection_class=DummyConnection,
            sniff_on_start=True,
        )

        # Start the timer right before the first task
        # and have a bunch of tasks come in immediately.
        tasks = []
        start_time = event_loop.time()
        for _ in range(5):
            tasks.append(event_loop.create_task(t._async_call()))
            await asyncio.sleep(0)  # Yield to the loop

        assert t.sniffing_task is not None

        # Tasks streaming in later.
        for _ in range(5):
            tasks.append(event_loop.create_task(t._async_call()))
            await asyncio.sleep(0.1)

        # Now that all the API calls have come in we wait for
        # them all to resolve before
        await asyncio.gather(*tasks)
        end_time = event_loop.time()
        duration = end_time - start_time

        # All the tasks blocked on the sniff of each node
        # and then resolved immediately after.
        assert 1 <= duration < 2

    async def test_sniff_on_start_close_unlocks_async_calls(self) -> None:
        event_loop = asyncio.get_event_loop()

        t: Any = AsyncTransport(
            [
                {"delay": 10, "data": CLUSTER_NODES},
            ],
            connection_class=DummyConnection,
            sniff_on_start=True,
        )

        # Start making _async_calls() before we cancel
        tasks = []
        start_time = event_loop.time()
        for _ in range(3):
            tasks.append(event_loop.create_task(t._async_call()))
            await asyncio.sleep(0)

        # Close the transport while the sniffing task is active! :(
        await t.close()

        # Now we start waiting on all those _async_calls()
        await asyncio.gather(*tasks)
        end_time = event_loop.time()
        duration = end_time - start_time

        # A lot quicker than 10 seconds defined in 'delay'
        assert duration < 1

    async def test_init_connection_pool_with_many_hosts(self) -> None:
        """
        Check init of connection pool with multiple connections.

        NOTE: since AsyncTransport performs internal hosts sniffing
        after building a connection the actual init of connection_class
        instances is reallocated from AsyncTransport.__init__()
        to AsyncTransport._async_init
        """
        amt_hosts = 4
        hosts = [{"host": "localhost", "port": 9092}] * amt_hosts
        t: Any = AsyncTransport(
            hosts=hosts,
        )
        await t._async_init()
        assert len(t.connection_pool.connections) == amt_hosts
        await t._async_call()

    async def test_init_pool_with_connection_class_to_many_hosts(self) -> None:
        """
        Check init of connection pool with user specified connection_class.

        NOTE: since AsyncTransport performs internal hosts sniffing
        after building a connection the actual init of connection_class
        instances is reallocated from AsyncTransport.__init__()
        to AsyncTransport._async_init
        """
        amt_hosts = 4
        hosts = [{"host": "localhost", "port": 9092}] * amt_hosts
        t: Any = AsyncTransport(
            hosts=hosts,
            connection_class=AIOHttpConnection,
        )
        await t._async_init()
        assert len(t.connection_pool.connections) == amt_hosts
        assert isinstance(
            t.connection_pool.connections[0],
            AIOHttpConnection,
        )


class TestAllowedResponseMimetypes:
    plugin_mimetype = PluginFormatSerializer.mimetype
    json_payload = '{"answer":42}'
    plugin_payload = "plugin-payload"

    def _transport(self, headers: Any, data: Any, **kwargs: Any) -> Any:
        self.plugin_serializer = PluginFormatSerializer()
        return AsyncTransport(
            [{"data": data, "headers": headers}],
            connection_class=DummyConnection,
            serializers={self.plugin_mimetype: self.plugin_serializer},
            **kwargs,
        )

    async def test_json_response_still_decoded_without_custom_decoder(
        self,
    ) -> None:
        t = self._transport({"content-type": "application/json"}, self.json_payload)

        response = await t.perform_request(
            "GET", "/public-search", allowed_mimetypes=("application/json",)
        )

        assert {"answer": 42} == response
        assert 0 == self.plugin_serializer.load_calls

    async def test_plugin_format_decoded_only_when_allowed_by_request(
        self,
    ) -> None:
        t = self._transport({"content-type": self.plugin_mimetype}, self.plugin_payload)

        response = await t.perform_request(
            "GET",
            "/_plugins/internal",
            allowed_mimetypes=("application/json", self.plugin_mimetype),
        )

        assert {"plugin_only": True, "raw": self.plugin_payload} == response
        assert 1 == self.plugin_serializer.load_calls

    async def test_per_request_mapping_can_supply_decoder(self) -> None:
        t = self._transport({"content-type": self.plugin_mimetype}, self.plugin_payload)
        request_only = PluginFormatSerializer()

        response = await t.perform_request(
            "GET",
            "/_plugins/internal",
            allowed_mimetypes={self.plugin_mimetype: request_only},
        )

        assert {"plugin_only": True, "raw": self.plugin_payload} == response
        assert 1 == request_only.load_calls
        assert 0 == self.plugin_serializer.load_calls

    async def test_public_request_rejects_plugin_format_without_decoding(
        self,
    ) -> None:
        t = self._transport({"content-type": self.plugin_mimetype}, self.plugin_payload)

        with pytest.raises(UnsupportedResponseFormatError) as caught:
            await t.perform_request(
                "GET", "/public-search", allowed_mimetypes=("application/json",)
            )

        assert isinstance(caught.value, SerializationError)
        assert "not an allowed response format" in str(caught.value)
        assert 0 == self.plugin_serializer.load_calls

    async def test_response_without_content_type_uses_default_mimetype(
        self,
    ) -> None:
        t = self._transport({}, self.json_payload)

        response = await t.perform_request(
            "GET", "/public-search", allowed_mimetypes=("application/json",)
        )

        assert {"answer": 42} == response
        assert 0 == self.plugin_serializer.load_calls

    async def test_missing_content_type_rejected_when_default_is_not_allowed(
        self,
    ) -> None:
        t = self._transport({}, self.json_payload)

        with pytest.raises(UnsupportedResponseFormatError):
            await t.perform_request(
                "GET",
                "/_plugins/internal",
                allowed_mimetypes=(self.plugin_mimetype,),
            )

        assert 0 == self.plugin_serializer.load_calls

    async def test_configured_default_mimetype_respects_request_policy(
        self,
    ) -> None:
        t = self._transport(
            {}, self.plugin_payload, default_mimetype=self.plugin_mimetype
        )

        with pytest.raises(UnsupportedResponseFormatError):
            await t.perform_request(
                "GET", "/public-search", allowed_mimetypes=("application/json",)
            )
        assert 0 == self.plugin_serializer.load_calls

        response = await t.perform_request(
            "GET", "/_plugins/internal", allowed_mimetypes=(self.plugin_mimetype,)
        )
        assert {"plugin_only": True, "raw": self.plugin_payload} == response
        assert 1 == self.plugin_serializer.load_calls

    async def test_omitting_allowed_mimetypes_keeps_legacy_behavior(
        self,
    ) -> None:
        t = self._transport({"content-type": self.plugin_mimetype}, self.plugin_payload)

        response = await t.perform_request("GET", "/legacy")

        assert {"plugin_only": True, "raw": self.plugin_payload} == response
        assert 1 == self.plugin_serializer.load_calls

    async def test_charset_suffix_is_stripped_before_allowlist_check(
        self,
    ) -> None:
        t = self._transport(
            {"content-type": "application/json; charset=utf-8"}, self.json_payload
        )

        response = await t.perform_request(
            "GET", "/public-search", allowed_mimetypes=("application/json",)
        )

        assert {"answer": 42} == response
        assert 0 == self.plugin_serializer.load_calls

    async def test_compatible_json_types_are_accepted(self) -> None:
        for content_type in (
            "application/vnd.elasticsearch+json",
            "application/vnd.elasticsearch+json;compatible-with=7",
            "APPLICATION/JSON; charset=UTF-8",
        ):
            t = self._transport({"content-type": content_type}, self.json_payload)
            response = await t.perform_request(
                "GET", "/public-search", allowed_mimetypes=("application/json",)
            )
            assert {"answer": 42} == response
            assert 0 == self.plugin_serializer.load_calls

    async def test_empty_body_keeps_existing_semantics(self) -> None:
        t = self._transport({"content-type": self.plugin_mimetype}, "")

        response = await t.perform_request(
            "GET", "/public-search", allowed_mimetypes=("application/json",)
        )

        assert "" == response
        assert 0 == self.plugin_serializer.load_calls

    async def test_head_does_not_decode_a_rejected_type(self) -> None:
        t = self._transport({"content-type": self.plugin_mimetype}, "")

        response = await t.perform_request(
            "HEAD", "/some-index", allowed_mimetypes=("application/json",)
        )

        assert response
        assert 0 == self.plugin_serializer.load_calls

    async def test_rejected_decoding_is_not_retried_or_marks_node_dead(self) -> None:
        plugin_serializer = PluginFormatSerializer()
        t = AsyncTransport(
            [
                {
                    "data": self.plugin_payload,
                    "headers": {"content-type": self.plugin_mimetype},
                },
                {
                    "data": self.json_payload,
                    "headers": {"content-type": "application/json"},
                },
            ],
            connection_class=DummyConnection,
            serializers={self.plugin_mimetype: plugin_serializer},
            randomize_hosts=False,
        )

        with pytest.raises(UnsupportedResponseFormatError):
            await t.perform_request(
                "GET", "/_search", allowed_mimetypes=("application/json",)
            )

        assert 2 == len(t.connection_pool.connections)
        assert {} == t.connection_pool.dead_count
        assert 0 == plugin_serializer.load_calls
        assert 1 == sum(len(c.calls) for c in t.connection_pool.connections)

    async def test_policy_is_not_sent_as_query_parameter_or_header(self) -> None:
        t = self._transport({"content-type": "application/json"}, self.json_payload)

        await t.perform_request(
            "GET",
            "/_search",
            params={"q": "x"},
            headers={"x-custom": "1"},
            allowed_mimetypes=("application/json",),
        )

        ((args, kwargs),) = t.get_connection().calls
        assert {"q": "x"} == args[2]
        assert "1" == kwargs["headers"]["x-custom"]
        assert "allowed_mimetypes" not in kwargs
        assert "allowed_mimetypes" not in kwargs["headers"]

    async def test_ignored_status_response_body_respects_policy(self) -> None:
        t = self._transport(
            {"content-type": self.plugin_mimetype},
            self.plugin_payload,
            status=404,
        )

        with pytest.raises(UnsupportedResponseFormatError):
            await t.perform_request(
                "GET", "/_search", ignore=404, allowed_mimetypes=("application/json",)
            )

        assert 0 == self.plugin_serializer.load_calls
        assert 1 == len(t.connection_pool.connections)

    async def test_ignored_status_allowed_body_is_decoded(self) -> None:
        t = self._transport(
            {"content-type": "application/json"}, self.json_payload, status=404
        )

        response = await t.perform_request(
            "GET", "/_search", ignore=404, allowed_mimetypes=("application/json",)
        )

        assert {"answer": 42} == response
        assert 0 == self.plugin_serializer.load_calls


class TestTwoNodeResponsePolicy:
    """Real AsyncTransport with two fake nodes and a retryable failure."""

    plugin_mimetype = PluginFormatSerializer.mimetype
    json_payload = '{"answer":42}'
    plugin_payload = "plugin-payload"

    def _transport(self) -> Any:
        self.plugin_serializer = PluginFormatSerializer()
        t = AsyncTransport(
            [
                {"exception": ConnectionError(None, "node down", Exception())},
                {
                    "data": self.plugin_payload,
                    "headers": {"content-type": self.plugin_mimetype},
                },
            ],
            connection_class=DummyConnection,
            serializers={self.plugin_mimetype: self.plugin_serializer},
            randomize_hosts=False,
            max_retries=1,
        )
        return t

    async def test_public_query_retries_then_rejects_plugin_format_without_decoding(
        self,
    ) -> None:
        t = self._transport()
        await t._async_call()
        self.failed, self.healthy = t.connection_pool.connections

        with pytest.raises(UnsupportedResponseFormatError):
            await t.perform_request(
                "GET", "/_search", allowed_mimetypes=("application/json",)
            )

        assert 1 == len(self.failed.calls)
        assert 1 == len(self.healthy.calls)
        assert 0 == self.plugin_serializer.load_calls
        assert 1 == len(t.connection_pool.connections)
        assert self.failed in t.connection_pool.dead_count
        assert self.healthy not in t.connection_pool.dead_count

    async def test_plugin_query_interleaved_with_retried_public_query(self) -> None:
        t = self._transport()
        await t._async_call()

        plugin_response = await t.perform_request(
            "POST",
            "/_plugins/_sql",
            allowed_mimetypes=(self.plugin_mimetype,),
        )
        assert {"plugin_only": True, "raw": self.plugin_payload} == plugin_response
        assert 1 == self.plugin_serializer.load_calls

        with pytest.raises(UnsupportedResponseFormatError):
            await t.perform_request(
                "GET", "/_search", allowed_mimetypes=("application/json",)
            )

        plugin_response = await t.perform_request(
            "POST",
            "/_plugins/_sql",
            allowed_mimetypes=(self.plugin_mimetype,),
        )
        assert {"plugin_only": True, "raw": self.plugin_payload} == plugin_response
        assert 2 == self.plugin_serializer.load_calls

    async def test_concurrent_plugin_and_public_requests_stay_isolated(self) -> None:
        t = self._transport()
        await t._async_call()

        async def plugin_call() -> Any:
            return await t.perform_request(
                "POST",
                "/_plugins/_sql",
                allowed_mimetypes=(self.plugin_mimetype,),
            )

        async def public_call() -> Any:
            try:
                result = await t.perform_request(
                    "GET", "/_search", allowed_mimetypes=("application/json",)
                )
            except UnsupportedResponseFormatError as e:
                return e
            return result

        results = await asyncio.gather(
            plugin_call(), public_call(), plugin_call(), public_call()
        )
        plugin_results = (results[0], results[2])
        public_results = (results[1], results[3])

        assert all(
            r == {"plugin_only": True, "raw": self.plugin_payload}
            for r in plugin_results
        )
        assert all(
            isinstance(r, UnsupportedResponseFormatError) for r in public_results
        )
        assert 2 == self.plugin_serializer.load_calls


class TestTextResponseEndpointsKeepWorking:
    """Endpoints that normally answer with text keep a text-aware default."""

    async def test_cat_and_hot_threads_allow_text_by_default(self) -> None:
        from opensearchpy import AsyncOpenSearch

        recorded = []

        class RecordingTransport(AsyncTransport):
            def __init__(self, hosts: Any, **kwargs: Any) -> None:
                self.hosts = hosts
                self.kwargs = kwargs

            def get_connection(self) -> Any:  # pragma: no cover - not used
                return None

            async def perform_request(self, *args: Any, **kwargs: Any) -> Any:
                recorded.append(kwargs.copy())
                return (200, {}, "{}")

            async def close(self) -> None:
                pass

        client = AsyncOpenSearch(transport_class=RecordingTransport)
        await client.cat.tasks()
        await client.nodes.hot_threads()
        assert recorded[0]["allowed_mimetypes"] == (
            "application/json",
            "text/plain",
        )
        assert recorded[1]["allowed_mimetypes"] == (
            "application/json",
            "text/plain",
        )

    async def test_search_defaults_to_json_only(self) -> None:
        from opensearchpy import AsyncOpenSearch

        recorded = []

        class RecordingTransport(AsyncTransport):
            def __init__(self, hosts: Any, **kwargs: Any) -> None:
                self.hosts = hosts

            async def perform_request(self, *args: Any, **kwargs: Any) -> Any:
                recorded.append(kwargs.copy())
                return (200, {}, "{}")

            async def close(self) -> None:
                pass

        client = AsyncOpenSearch(transport_class=RecordingTransport)
        await client.search()
        await client.plugins.sql.query(body={"query": "SELECT 1"})
        assert recorded[0]["allowed_mimetypes"] == ("application/json",)
        assert recorded[1]["allowed_mimetypes"] is None


class TestClientEntryResponsePolicy:
    """Public entry points default to JSON; plugin entry points do not."""

    plugin_mimetype = PluginFormatSerializer.mimetype
    json_payload = '{"answer":42}'
    plugin_payload = "plugin-payload"

    def _client(self, headers: Any, data: Any) -> Any:
        from opensearchpy import AsyncOpenSearch

        self.plugin_serializer = PluginFormatSerializer()
        return AsyncOpenSearch(
            [{"host": "localhost", "port": 9200, "headers": headers, "data": data}],
            connection_class=DummyConnection,
            serializers={self.plugin_mimetype: self.plugin_serializer},
        )

    async def test_search_rejects_plugin_format_by_default(self) -> None:
        client = self._client(
            {"content-type": self.plugin_mimetype}, self.plugin_payload
        )

        with pytest.raises(UnsupportedResponseFormatError):
            await client.search(body={"query": {"match_all": {}}})

        assert 0 == self.plugin_serializer.load_calls

    async def test_search_accepts_per_request_json_policy(self) -> None:
        client = self._client({"content-type": "application/json"}, self.json_payload)

        result = await client.search(allowed_mimetypes=("application/json",))

        assert {"answer": 42} == result
        assert 0 == self.plugin_serializer.load_calls

    async def test_search_can_explicitly_allow_plugin_format(self) -> None:
        client = self._client(
            {"content-type": self.plugin_mimetype}, self.plugin_payload
        )

        result = await client.search(allowed_mimetypes=(self.plugin_mimetype,))

        assert {"plugin_only": True, "raw": self.plugin_payload} == result
        assert 1 == self.plugin_serializer.load_calls

    async def test_plugin_endpoint_is_not_affected_by_public_search(self) -> None:
        client = self._client(
            {"content-type": self.plugin_mimetype}, self.plugin_payload
        )

        plugin_result = await client.plugins.sql.query(body={"query": "SELECT 1"})
        assert {"plugin_only": True, "raw": self.plugin_payload} == plugin_result
        assert 1 == self.plugin_serializer.load_calls

        with pytest.raises(UnsupportedResponseFormatError):
            await client.search()

        assert 1 == self.plugin_serializer.load_calls

    async def test_low_level_http_get_defaults_to_json_policy(self) -> None:
        client = self._client(
            {"content-type": self.plugin_mimetype}, self.plugin_payload
        )

        with pytest.raises(UnsupportedResponseFormatError):
            await client.http.get("/some/path")

        assert 0 == self.plugin_serializer.load_calls

    async def test_low_level_http_get_can_allow_plugin_format(self) -> None:
        client = self._client(
            {"content-type": self.plugin_mimetype}, self.plugin_payload
        )

        result = await client.http.get(
            "/_plugins/_sql", allowed_mimetypes=(self.plugin_mimetype,)
        )

        assert {"plugin_only": True, "raw": self.plugin_payload} == result
        assert 1 == self.plugin_serializer.load_calls

    async def test_low_level_http_head_keeps_boolean_semantics(self) -> None:
        client = self._client({"content-type": self.plugin_mimetype}, "")

        assert await client.http.head("/some-index")
        assert 0 == self.plugin_serializer.load_calls

    async def test_request_policy_never_reaches_the_wire(self) -> None:
        client = self._client({"content-type": "application/json"}, self.json_payload)

        await client.search(
            params={"q": "x"},
            headers={"x-custom": "1"},
            allowed_mimetypes=("application/json",),
        )

        calls = client.transport.connection_pool.connections[0].calls
        args, kwargs = calls[-1]
        assert {"q": "x"} == args[2]
        assert "1" == kwargs["headers"]["x-custom"]
        assert "allowed_mimetypes" not in kwargs["headers"]
