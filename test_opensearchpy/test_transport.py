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


import json
import time
from typing import Any
from unittest.mock import patch

from opensearchpy.connection import Connection
from opensearchpy.connection_pool import DummyConnectionPool
from opensearchpy.exceptions import (
    ConnectionError,
    SerializationError,
    TransportError,
    UnsupportedResponseFormatError,
)
from opensearchpy.serializer import Serializer
from opensearchpy.transport import Transport, get_host_info

from .test_cases import TestCase


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
        self.calls: Any = []
        super().__init__(**kwargs)

    def perform_request(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append((args, kwargs))
        if self.exception:
            raise self.exception
        return self.status, self.response_headers, self.data


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


class TestHostsInfoCallback(TestCase):
    def test_cluster_manager_only_nodes_are_ignored(self) -> None:
        nodes = [
            {"roles": ["cluster_manager"]},
            {"roles": ["cluster_manager", "data", "ingest"]},
            {"roles": ["data", "ingest"]},
            {"roles": []},
            {},
        ]
        chosen = [
            i
            for i, node_info in enumerate(nodes)
            if get_host_info(node_info, i) is not None  # type: ignore
        ]
        self.assertEqual([1, 2, 3, 4], chosen)


class TestTransport(TestCase):
    def test_single_connection_uses_dummy_connection_pool(self) -> None:
        t1: Any = Transport([{}])
        self.assertIsInstance(t1.connection_pool, DummyConnectionPool)
        t2: Any = Transport([{"host": "localhost"}])
        self.assertIsInstance(t2.connection_pool, DummyConnectionPool)

    def test_request_timeout_extracted_from_params_and_passed(self) -> None:
        t: Any = Transport([{}], connection_class=DummyConnection)

        t.perform_request("GET", "/", params={"request_timeout": 42})
        self.assertEqual(1, len(t.get_connection().calls))
        self.assertEqual(("GET", "/", {}, None), t.get_connection().calls[0][0])
        self.assertEqual(
            {"timeout": 42, "ignore": (), "headers": None},
            t.get_connection().calls[0][1],
        )

    def test_timeout_extracted_from_params_and_passed(self) -> None:
        t: Any = Transport([{}], connection_class=DummyConnection)

        t.perform_request("GET", "/", params={"timeout": 84})
        self.assertEqual(1, len(t.get_connection().calls))
        self.assertEqual(("GET", "/", {}, None), t.get_connection().calls[0][0])
        self.assertEqual(
            {"timeout": 84, "ignore": (), "headers": None},
            t.get_connection().calls[0][1],
        )

    def test_opaque_id(self) -> None:
        t: Any = Transport([{}], opaque_id="app-1", connection_class=DummyConnection)

        t.perform_request("GET", "/")
        self.assertEqual(1, len(t.get_connection().calls))
        self.assertEqual(("GET", "/", None, None), t.get_connection().calls[0][0])
        self.assertEqual(
            {"timeout": None, "ignore": (), "headers": None},
            t.get_connection().calls[0][1],
        )

        # Now try with an 'x-opaque-id' set on perform_request().
        t.perform_request("GET", "/", headers={"x-opaque-id": "request-1"})
        self.assertEqual(2, len(t.get_connection().calls))
        self.assertEqual(("GET", "/", None, None), t.get_connection().calls[1][0])
        self.assertEqual(
            {"timeout": None, "ignore": (), "headers": {"x-opaque-id": "request-1"}},
            t.get_connection().calls[1][1],
        )

    def test_request_with_custom_user_agent_header(self) -> None:
        t: Any = Transport([{}], connection_class=DummyConnection)

        t.perform_request("GET", "/", headers={"user-agent": "my-custom-value/1.2.3"})
        self.assertEqual(1, len(t.get_connection().calls))
        self.assertEqual(
            {
                "timeout": None,
                "ignore": (),
                "headers": {"user-agent": "my-custom-value/1.2.3"},
            },
            t.get_connection().calls[0][1],
        )

    def test_send_get_body_as_source(self) -> None:
        t: Any = Transport(
            [{}], send_get_body_as="source", connection_class=DummyConnection
        )

        t.perform_request("GET", "/", body={})
        self.assertEqual(1, len(t.get_connection().calls))
        self.assertEqual(
            ("GET", "/", {"source": "{}"}, None), t.get_connection().calls[0][0]
        )

    def test_send_get_body_as_post(self) -> None:
        t: Any = Transport(
            [{}], send_get_body_as="POST", connection_class=DummyConnection
        )

        t.perform_request("GET", "/", body={})
        self.assertEqual(1, len(t.get_connection().calls))
        self.assertEqual(("POST", "/", None, b"{}"), t.get_connection().calls[0][0])

    def test_body_gets_encoded_into_bytes(self) -> None:
        t: Any = Transport([{}], connection_class=DummyConnection)

        t.perform_request("GET", "/", body="你好")
        self.assertEqual(1, len(t.get_connection().calls))
        self.assertEqual(
            ("GET", "/", None, b"\xe4\xbd\xa0\xe5\xa5\xbd"),
            t.get_connection().calls[0][0],
        )

    def test_body_bytes_get_passed_untouched(self) -> None:
        t: Any = Transport([{}], connection_class=DummyConnection)

        body = b"\xe4\xbd\xa0\xe5\xa5\xbd"
        t.perform_request("GET", "/", body=body)
        self.assertEqual(1, len(t.get_connection().calls))
        self.assertEqual(("GET", "/", None, body), t.get_connection().calls[0][0])

    def test_body_surrogates_replaced_encoded_into_bytes(self) -> None:
        t: Any = Transport([{}], connection_class=DummyConnection)

        t.perform_request("GET", "/", body="你好\uda6a")
        self.assertEqual(1, len(t.get_connection().calls))
        self.assertEqual(
            ("GET", "/", None, b"\xe4\xbd\xa0\xe5\xa5\xbd\xed\xa9\xaa"),
            t.get_connection().calls[0][0],
        )

    def test_kwargs_passed_on_to_connections(self) -> None:
        t: Any = Transport([{"host": "google.com"}], port=123)
        self.assertEqual(1, len(t.connection_pool.connections))
        self.assertEqual("http://google.com:123", t.connection_pool.connections[0].host)

    def test_kwargs_passed_on_to_connection_pool(self) -> None:
        dt = object()
        t: Any = Transport([{}, {}], dead_timeout=dt)
        self.assertIs(dt, t.connection_pool.dead_timeout)

    def test_custom_connection_class(self) -> None:
        class MyConnection(Connection):
            def __init__(self, **kwargs: Any) -> None:
                self.kwargs = kwargs

        t: Any = Transport([{}], connection_class=MyConnection)
        self.assertEqual(1, len(t.connection_pool.connections))
        self.assertIsInstance(t.connection_pool.connections[0], MyConnection)

    def test_add_connection(self) -> None:
        t: Any = Transport([{}], randomize_hosts=False)
        t.add_connection({"host": "google.com", "port": 1234})

        self.assertEqual(2, len(t.connection_pool.connections))
        self.assertEqual(
            "http://google.com:1234", t.connection_pool.connections[1].host
        )

    def test_perform_request_all_arguments_passed_correctly(self) -> None:
        t: Any = Transport([{}], connection_class=DummyConnection)
        method, url, params, body = "GET", "/test_url", {"params": "test"}, "test_body"
        timeout, ignore, headers = 11, ("ignore",), {"h": "test"}

        t.perform_request(method, url, params, body, timeout, ignore, headers)

        self.assertEqual(
            t.get_connection().calls,
            [
                (
                    (method, url, params, body.encode()),
                    {"headers": headers, "ignore": ignore, "timeout": timeout},
                )
            ],
        )

    def test_request_will_fail_after_x_retries(self) -> None:
        t: Any = Transport(
            [{"exception": ConnectionError(None, "abandon ship", Exception())}],
            connection_class=DummyConnection,
        )

        self.assertRaises(ConnectionError, t.perform_request, "GET", "/")
        self.assertEqual(4, len(t.get_connection().calls))

    def test_failed_connection_will_be_marked_as_dead(self) -> None:
        t: Any = Transport(
            [{"exception": ConnectionError(None, "abandon ship", Exception())}] * 2,
            connection_class=DummyConnection,
        )

        self.assertRaises(ConnectionError, t.perform_request, "GET", "/")
        self.assertEqual(0, len(t.connection_pool.connections))

    def test_resurrected_connection_will_be_marked_as_live_on_success(self) -> None:
        for method in ("GET", "HEAD"):
            t: Any = Transport([{}, {}], connection_class=DummyConnection)
            con1 = t.connection_pool.get_connection()
            con2 = t.connection_pool.get_connection()
            t.connection_pool.mark_dead(con1)
            t.connection_pool.mark_dead(con2)

            t.perform_request(method, "/")
            self.assertEqual(1, len(t.connection_pool.connections))
            self.assertEqual(1, len(t.connection_pool.dead_count))

    def test_sniff_will_use_seed_connections(self) -> None:
        t: Any = Transport([{"data": CLUSTER_NODES}], connection_class=DummyConnection)
        t.set_connections([{"data": "invalid"}])

        t.sniff_hosts()
        self.assertEqual(1, len(t.connection_pool.connections))
        self.assertEqual("http://1.1.1.1:123", t.get_connection().host)

    def test_sniff_on_start_fetches_and_uses_nodes_list(self) -> None:
        t: Any = Transport(
            [{"data": CLUSTER_NODES}],
            connection_class=DummyConnection,
            sniff_on_start=True,
        )
        self.assertEqual(1, len(t.connection_pool.connections))
        self.assertEqual("http://1.1.1.1:123", t.get_connection().host)

    def test_sniff_on_start_ignores_sniff_timeout(self) -> None:
        t: Any = Transport(
            [{"data": CLUSTER_NODES}],
            connection_class=DummyConnection,
            sniff_on_start=True,
            sniff_timeout=12,
        )
        self.assertEqual(
            (("GET", "/_nodes/_all/http"), {"timeout": None}),
            t.seed_connections[0].calls[0],
        )

    def test_sniff_uses_sniff_timeout(self) -> None:
        t: Any = Transport(
            [{"data": CLUSTER_NODES}],
            connection_class=DummyConnection,
            sniff_timeout=42,
        )
        t.sniff_hosts()
        self.assertEqual(
            (("GET", "/_nodes/_all/http"), {"timeout": 42}),
            t.seed_connections[0].calls[0],
        )

    def test_sniff_reuses_connection_instances_if_possible(self) -> None:
        t: Any = Transport(
            [{"data": CLUSTER_NODES}, {"host": "1.1.1.1", "port": 123}],
            connection_class=DummyConnection,
            randomize_hosts=False,
        )
        connection = t.connection_pool.connections[1]

        t.sniff_hosts()
        self.assertEqual(1, len(t.connection_pool.connections))
        self.assertIs(connection, t.get_connection())

    def test_sniff_on_fail_triggers_sniffing_on_fail(self) -> None:
        t: Any = Transport(
            [
                {"exception": ConnectionError(None, "abandon ship", Exception())},
                {"data": CLUSTER_NODES},
            ],
            connection_class=DummyConnection,
            sniff_on_connection_fail=True,
            max_retries=0,
            randomize_hosts=False,
        )

        self.assertRaises(ConnectionError, t.perform_request, "GET", "/")
        self.assertEqual(1, len(t.connection_pool.connections))
        self.assertEqual("http://1.1.1.1:123", t.get_connection().host)

    @patch("opensearchpy.transport.Transport.sniff_hosts")
    def test_sniff_on_fail_failing_does_not_prevent_retires(
        self, sniff_hosts: Any
    ) -> None:
        sniff_hosts.side_effect = [TransportError("sniff failed")]
        t: Any = Transport(
            [
                {"exception": ConnectionError(None, "abandon ship", Exception())},
                {"data": CLUSTER_NODES},
            ],
            connection_class=DummyConnection,
            sniff_on_connection_fail=True,
            max_retries=3,
            randomize_hosts=False,
        )

        conn_err, conn_data = t.connection_pool.connections
        response = t.perform_request("GET", "/")
        self.assertEqual(json.loads(CLUSTER_NODES), response)
        self.assertEqual(1, sniff_hosts.call_count)
        self.assertEqual(1, len(conn_err.calls))
        self.assertEqual(1, len(conn_data.calls))

    def test_sniff_after_n_seconds(self) -> None:
        t: Any = Transport(
            [{"data": CLUSTER_NODES}],
            connection_class=DummyConnection,
            sniffer_timeout=5,
        )

        for _ in range(4):
            t.perform_request("GET", "/")
        self.assertEqual(1, len(t.connection_pool.connections))
        self.assertIsInstance(t.get_connection(), DummyConnection)
        t.last_sniff = time.time() - 5.1

        t.perform_request("GET", "/")
        self.assertEqual(1, len(t.connection_pool.connections))
        self.assertEqual("http://1.1.1.1:123", t.get_connection().host)
        self.assertTrue(time.time() - 1 < t.last_sniff < time.time() + 0.01)

    def test_sniff_7x_publish_host(self) -> None:
        # Test the response shaped when a 7.x node has publish_host set
        # and the returend data is shaped in the fqdn/ip:port format.
        t: Any = Transport(
            [{"data": CLUSTER_NODES_7X_PUBLISH_HOST}],
            connection_class=DummyConnection,
            sniff_timeout=42,
        )
        t.sniff_hosts()
        # Ensure we parsed out the fqdn and port from the fqdn/ip:port string.
        self.assertEqual(
            t.connection_pool.connection_opts[0][1],
            {"host": "somehost.tld", "port": 123},
        )


class TestAllowedResponseMimetypes(TestCase):
    plugin_mimetype = PluginFormatSerializer.mimetype
    json_payload = '{"answer":42}'
    plugin_payload = "plugin-payload"

    def _transport(self, headers: Any, data: Any, **kwargs: Any) -> Any:
        self.plugin_serializer = PluginFormatSerializer()
        return Transport(
            [{"data": data, "headers": headers}],
            connection_class=DummyConnection,
            serializers={self.plugin_mimetype: self.plugin_serializer},
            **kwargs,
        )

    def test_json_response_still_decoded_without_custom_decoder(self) -> None:
        t = self._transport({"content-type": "application/json"}, self.json_payload)

        response = t.perform_request(
            "GET", "/public-search", allowed_mimetypes=("application/json",)
        )

        self.assertEqual({"answer": 42}, response)
        self.assertEqual(0, self.plugin_serializer.load_calls)

    def test_plugin_format_decoded_only_when_allowed_by_request(self) -> None:
        t = self._transport({"content-type": self.plugin_mimetype}, self.plugin_payload)

        response = t.perform_request(
            "GET",
            "/_plugins/internal",
            allowed_mimetypes=("application/json", self.plugin_mimetype),
        )

        self.assertEqual({"plugin_only": True, "raw": self.plugin_payload}, response)
        self.assertEqual(1, self.plugin_serializer.load_calls)

    def test_per_request_mapping_can_supply_decoder(self) -> None:
        t = self._transport({"content-type": self.plugin_mimetype}, self.plugin_payload)
        request_only = PluginFormatSerializer()

        response = t.perform_request(
            "GET",
            "/_plugins/internal",
            allowed_mimetypes={self.plugin_mimetype: request_only},
        )

        self.assertEqual({"plugin_only": True, "raw": self.plugin_payload}, response)
        self.assertEqual(1, request_only.load_calls)
        self.assertEqual(0, self.plugin_serializer.load_calls)

    def test_public_request_rejects_plugin_format_without_decoding(self) -> None:
        t = self._transport({"content-type": self.plugin_mimetype}, self.plugin_payload)

        with self.assertRaises(UnsupportedResponseFormatError) as caught:
            t.perform_request(
                "GET", "/public-search", allowed_mimetypes=("application/json",)
            )

        self.assertIsInstance(caught.exception, SerializationError)
        self.assertIn("not an allowed response format", str(caught.exception))
        self.assertEqual(0, self.plugin_serializer.load_calls)

    def test_response_without_content_type_uses_default_mimetype(self) -> None:
        t = self._transport({}, self.json_payload)

        response = t.perform_request(
            "GET", "/public-search", allowed_mimetypes=("application/json",)
        )

        self.assertEqual({"answer": 42}, response)
        self.assertEqual(0, self.plugin_serializer.load_calls)

    def test_missing_content_type_rejected_when_default_is_not_allowed(self) -> None:
        t = self._transport({}, self.json_payload)

        with self.assertRaises(UnsupportedResponseFormatError):
            t.perform_request(
                "GET",
                "/_plugins/internal",
                allowed_mimetypes=(self.plugin_mimetype,),
            )

        self.assertEqual(0, self.plugin_serializer.load_calls)

    def test_configured_default_mimetype_respects_request_policy(self) -> None:
        t = self._transport(
            {}, self.plugin_payload, default_mimetype=self.plugin_mimetype
        )

        with self.assertRaises(UnsupportedResponseFormatError):
            t.perform_request(
                "GET", "/public-search", allowed_mimetypes=("application/json",)
            )
        self.assertEqual(0, self.plugin_serializer.load_calls)

        response = t.perform_request(
            "GET", "/_plugins/internal", allowed_mimetypes=(self.plugin_mimetype,)
        )
        self.assertEqual({"plugin_only": True, "raw": self.plugin_payload}, response)
        self.assertEqual(1, self.plugin_serializer.load_calls)

    def test_omitting_allowed_mimetypes_keeps_legacy_behavior(self) -> None:
        t = self._transport({"content-type": self.plugin_mimetype}, self.plugin_payload)

        response = t.perform_request("GET", "/legacy")

        self.assertEqual({"plugin_only": True, "raw": self.plugin_payload}, response)
        self.assertEqual(1, self.plugin_serializer.load_calls)

    def test_charset_suffix_is_stripped_before_allowlist_check(self) -> None:
        t = self._transport(
            {"content-type": "application/json; charset=utf-8"}, self.json_payload
        )

        response = t.perform_request(
            "GET", "/public-search", allowed_mimetypes=("application/json",)
        )

        self.assertEqual({"answer": 42}, response)
        self.assertEqual(0, self.plugin_serializer.load_calls)

    def test_compatible_json_types_are_accepted(self) -> None:
        for content_type in (
            "application/vnd.elasticsearch+json",
            "application/vnd.elasticsearch+json;compatible-with=7",
            "APPLICATION/JSON; charset=UTF-8",
        ):
            t = self._transport({"content-type": content_type}, self.json_payload)
            response = t.perform_request(
                "GET", "/public-search", allowed_mimetypes=("application/json",)
            )
            self.assertEqual({"answer": 42}, response)
            self.assertEqual(0, self.plugin_serializer.load_calls)

    def test_empty_body_keeps_existing_semantics(self) -> None:
        t = self._transport({"content-type": self.plugin_mimetype}, "")

        response = t.perform_request(
            "GET", "/public-search", allowed_mimetypes=("application/json",)
        )

        self.assertEqual("", response)
        self.assertEqual(0, self.plugin_serializer.load_calls)

    def test_head_does_not_decode_a_rejected_type(self) -> None:
        t = self._transport({"content-type": self.plugin_mimetype}, "")

        response = t.perform_request(
            "HEAD", "/some-index", allowed_mimetypes=("application/json",)
        )

        self.assertTrue(response)
        self.assertEqual(0, self.plugin_serializer.load_calls)

    def test_rejected_decoding_is_not_retried_or_marks_node_dead(self) -> None:
        plugin_serializer = PluginFormatSerializer()
        t = Transport(
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

        with self.assertRaises(UnsupportedResponseFormatError):
            t.perform_request(
                "GET", "/_search", allowed_mimetypes=("application/json",)
            )

        self.assertEqual(2, len(t.connection_pool.connections))
        self.assertEqual({}, t.connection_pool.dead_count)
        self.assertEqual(0, plugin_serializer.load_calls)
        self.assertEqual(1, sum(len(c.calls) for c in t.connection_pool.connections))

    def test_policy_is_not_sent_as_query_parameter_or_header(self) -> None:
        t = self._transport({"content-type": "application/json"}, self.json_payload)

        t.perform_request(
            "GET",
            "/_search",
            params={"q": "x"},
            headers={"x-custom": "1"},
            allowed_mimetypes=("application/json",),
        )

        ((args, kwargs),) = t.get_connection().calls
        self.assertEqual({"q": "x"}, args[2])
        self.assertEqual("1", kwargs["headers"]["x-custom"])
        self.assertNotIn("allowed_mimetypes", kwargs)
        self.assertNotIn("allowed_mimetypes", kwargs["headers"])

    def test_ignored_status_response_body_respects_policy(self) -> None:
        t = self._transport(
            {"content-type": self.plugin_mimetype},
            self.plugin_payload,
            status=404,
        )

        with self.assertRaises(UnsupportedResponseFormatError):
            t.perform_request(
                "GET", "/_search", ignore=404, allowed_mimetypes=("application/json",)
            )

        self.assertEqual(0, self.plugin_serializer.load_calls)
        self.assertEqual(1, len(t.connection_pool.connections))

    def test_ignored_status_allowed_body_is_decoded(self) -> None:
        t = self._transport(
            {"content-type": "application/json"}, self.json_payload, status=404
        )

        response = t.perform_request(
            "GET", "/_search", ignore=404, allowed_mimetypes=("application/json",)
        )

        self.assertEqual({"answer": 42}, response)
        self.assertEqual(0, self.plugin_serializer.load_calls)


class TestTwoNodeResponsePolicy(TestCase):
    """Real Transport with two fake nodes, including a retryable failure."""

    plugin_mimetype = PluginFormatSerializer.mimetype
    json_payload = '{"answer":42}'
    plugin_payload = "plugin-payload"

    def _transport(self) -> Any:
        self.plugin_serializer = PluginFormatSerializer()
        t = Transport(
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
        self.failed, self.healthy = t.connection_pool.connections
        return t

    def test_public_query_retries_then_rejects_plugin_format_without_decoding(
        self,
    ) -> None:
        t = self._transport()

        with self.assertRaises(UnsupportedResponseFormatError):
            t.perform_request(
                "GET", "/_search", allowed_mimetypes=("application/json",)
            )

        self.assertEqual(1, len(self.failed.calls))
        self.assertEqual(1, len(self.healthy.calls))
        self.assertEqual(0, self.plugin_serializer.load_calls)
        self.assertEqual(1, len(t.connection_pool.connections))
        self.assertIn(self.failed, t.connection_pool.dead_count)
        self.assertNotIn(self.healthy, t.connection_pool.dead_count)

    def test_plugin_query_interleaved_with_retried_public_query(self) -> None:
        t = self._transport()

        plugin_response = t.perform_request(
            "POST",
            "/_plugins/_sql",
            allowed_mimetypes=(self.plugin_mimetype,),
        )
        self.assertEqual(
            {"plugin_only": True, "raw": self.plugin_payload}, plugin_response
        )
        self.assertEqual(1, self.plugin_serializer.load_calls)

        with self.assertRaises(UnsupportedResponseFormatError):
            t.perform_request(
                "GET", "/_search", allowed_mimetypes=("application/json",)
            )

        plugin_response = t.perform_request(
            "POST",
            "/_plugins/_sql",
            allowed_mimetypes=(self.plugin_mimetype,),
        )
        self.assertEqual(
            {"plugin_only": True, "raw": self.plugin_payload}, plugin_response
        )
        self.assertEqual(2, self.plugin_serializer.load_calls)


class TestNestedRequestPolicy(TestCase):
    """A connection nesting a request must restore the outer policy."""

    def test_inner_request_policy_is_restored(self) -> None:
        from opensearchpy.serializer import (
            current_allowed_mimetypes,
            reset_allowed_mimetypes,
            set_allowed_mimetypes,
        )

        outer = set_allowed_mimetypes(("application/json",), "application/json")
        try:
            inner = set_allowed_mimetypes(("text/plain",), "text/plain")
            try:
                self.assertEqual(("text/plain",), current_allowed_mimetypes())
            finally:
                reset_allowed_mimetypes(inner)
            self.assertEqual(("application/json",), current_allowed_mimetypes())
        finally:
            reset_allowed_mimetypes(outer)
        self.assertIsNone(current_allowed_mimetypes())


class TestClientEntryResponsePolicy(TestCase):
    """Public entry points default to JSON; plugin entry points do not."""

    plugin_mimetype = PluginFormatSerializer.mimetype
    json_payload = '{"answer":42}'
    plugin_payload = "plugin-payload"

    def _client(self, headers: Any, data: Any) -> Any:
        from opensearchpy import OpenSearch

        self.plugin_serializer = PluginFormatSerializer()
        client = OpenSearch(
            [{"host": "localhost", "port": 9200, "headers": headers, "data": data}],
            connection_class=DummyConnection,
            serializers={self.plugin_mimetype: self.plugin_serializer},
        )
        return client

    def test_search_rejects_plugin_format_by_default(self) -> None:
        client = self._client(
            {"content-type": self.plugin_mimetype}, self.plugin_payload
        )

        with self.assertRaises(UnsupportedResponseFormatError):
            client.search(body={"query": {"match_all": {}}})

        self.assertEqual(0, self.plugin_serializer.load_calls)

    def test_search_accepts_per_request_json_policy(self) -> None:
        client = self._client({"content-type": "application/json"}, self.json_payload)

        result = client.search(allowed_mimetypes=("application/json",))

        self.assertEqual({"answer": 42}, result)
        self.assertEqual(0, self.plugin_serializer.load_calls)

    def test_search_can_explicitly_allow_plugin_format(self) -> None:
        client = self._client(
            {"content-type": self.plugin_mimetype}, self.plugin_payload
        )

        result = client.search(allowed_mimetypes=(self.plugin_mimetype,))

        self.assertEqual({"plugin_only": True, "raw": self.plugin_payload}, result)
        self.assertEqual(1, self.plugin_serializer.load_calls)

    def test_plugin_endpoint_is_not_affected_by_public_search(self) -> None:
        client = self._client(
            {"content-type": self.plugin_mimetype}, self.plugin_payload
        )

        plugin_result = client.plugins.sql.query(body={"query": "SELECT 1"})
        self.assertEqual(
            {"plugin_only": True, "raw": self.plugin_payload}, plugin_result
        )
        self.assertEqual(1, self.plugin_serializer.load_calls)

        with self.assertRaises(UnsupportedResponseFormatError):
            client.search()

        self.assertEqual(1, self.plugin_serializer.load_calls)

    def test_low_level_http_get_defaults_to_json_policy(self) -> None:
        client = self._client(
            {"content-type": self.plugin_mimetype}, self.plugin_payload
        )

        with self.assertRaises(UnsupportedResponseFormatError):
            client.http.get("/some/path")

        self.assertEqual(0, self.plugin_serializer.load_calls)

    def test_low_level_http_get_can_allow_plugin_format(self) -> None:
        client = self._client(
            {"content-type": self.plugin_mimetype}, self.plugin_payload
        )

        result = client.http.get(
            "/_plugins/_sql", allowed_mimetypes=(self.plugin_mimetype,)
        )

        self.assertEqual({"plugin_only": True, "raw": self.plugin_payload}, result)
        self.assertEqual(1, self.plugin_serializer.load_calls)

    def test_low_level_http_head_keeps_boolean_semantics(self) -> None:
        client = self._client({"content-type": self.plugin_mimetype}, "")

        self.assertTrue(client.http.head("/some-index"))
        self.assertEqual(0, self.plugin_serializer.load_calls)

    def test_request_policy_never_reaches_the_wire(self) -> None:
        client = self._client({"content-type": "application/json"}, self.json_payload)

        client.search(
            params={"q": "x"},
            headers={"x-custom": "1"},
            allowed_mimetypes=("application/json",),
        )

        calls = client.transport.connection_pool.connections[0].calls
        args, kwargs = calls[-1]
        self.assertEqual({"q": "x"}, args[2])
        self.assertEqual("1", kwargs["headers"]["x-custom"])
        self.assertNotIn("allowed_mimetypes", kwargs["headers"])


class TestTextResponseEndpointsKeepWorking(TestCase):
    """Endpoints that normally answer with text keep a text-aware default."""

    def test_cat_and_hot_threads_allow_text_by_default(self) -> None:
        from opensearchpy import OpenSearch
        from test_opensearchpy.test_cases import DummyTransport

        recorded = []

        class RecordingTransport(DummyTransport):
            def perform_request(self, *args: Any, **kwargs: Any) -> Any:
                recorded.append(kwargs.copy())
                return super().perform_request(*args, **kwargs)

        client = OpenSearch(transport_class=RecordingTransport)
        client.cat.tasks()
        client.nodes.hot_threads()
        assert recorded[0]["allowed_mimetypes"] == (
            "application/json",
            "text/plain",
        )
        assert recorded[1]["allowed_mimetypes"] == (
            "application/json",
            "text/plain",
        )

    def test_search_defaults_to_json_only(self) -> None:
        from opensearchpy import OpenSearch
        from test_opensearchpy.test_cases import DummyTransport

        recorded = []

        class RecordingTransport(DummyTransport):
            def perform_request(self, *args: Any, **kwargs: Any) -> Any:
                recorded.append(kwargs.copy())
                return super().perform_request(*args, **kwargs)

        client = OpenSearch(transport_class=RecordingTransport)
        client.search()
        client.plugins.sql.query(body={"query": "SELECT 1"})
        assert recorded[0]["allowed_mimetypes"] == ("application/json",)
        assert recorded[1]["allowed_mimetypes"] is None
