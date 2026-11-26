# Copyright 2026 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Impersonation identity binding across calls, retries and pagination.

These tests use an in-process transport that records the headers and page
tokens of every request. No cluster or listening socket is involved.
"""

import json
import threading
import unittest
import urllib3

from kubernetes.client import ApiClient, Configuration, CoreV1Api
from kubernetes.utils.impersonation import (
    ImpersonationConfig,
    ImpersonationError,
    resolve_impersonation,
)
from kubernetes.watch import Watch

try:  # the async client needs aiohttp-retry, which some installs omit
    from kubernetes.aio.client.api_client import ApiClient as AsyncApiClient
    from kubernetes.aio.client.configuration import (
        Configuration as AsyncConfiguration,
    )
    HAS_ASYNC = True
except Exception:  # pragma: no cover - depends on optional dependency
    HAS_ASYNC = False


NAMESPACE_LIST = {
    "apiVersion": "v1",
    "kind": "NamespaceList",
    "items": [],
}


class RecordingTransport:
    """Stand-in for urllib3's pool that records each wire request."""

    def __init__(self):
        self.requests = []
        self.responses = []
        self.lock = threading.Lock()

    def queue(self, body, status=200, headers=None, retry_after=None):
        headers = dict(headers or {})
        if retry_after is not None:
            headers["Retry-After"] = str(retry_after)
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        self.responses.append((body, status, headers))

    def request(self, method, url, **kwargs):
        headers = kwargs.get("headers") or {}
        if hasattr(headers, "items"):
            # HTTPHeaderDict.items() keeps duplicate lines in urllib3 2.x.
            lines = list(headers.items())
        else:
            lines = list(headers)
        with self.lock:
            self.requests.append({
                "method": method,
                "url": url,
                "headers": lines,
            })
            body, status, response_headers = self.responses.pop(0)
        return urllib3.HTTPResponse(
            body=body, status=status, headers=response_headers,
            preload_content=False,
        )

    def header_values(self, name):
        values = []
        for request in self.requests:
            for key, value in request["headers"]:
                if key.lower() == name.lower():
                    values.append(value)
        return values


def make_client(transport=None, retries=None, client_go_retries=False,
                **configuration):
    configuration.setdefault("host", "http://api.test")
    configuration.setdefault("proxy", "")
    configuration.setdefault("no_proxy", "")
    config = Configuration(**configuration)
    if retries is not None:
        config.retries = retries
    if client_go_retries:
        config.client_go_retries = client_go_retries
    client = ApiClient(config)
    transport = transport or RecordingTransport()
    client.rest_client.pool_manager = transport
    return client, transport


class ImpersonationRequestTest(unittest.TestCase):
    def test_resolve_rejects_groups_without_user(self):
        with self.assertRaises(ImpersonationError):
            resolve_impersonation(groups=["dev"])

    def test_resolve_rejects_duplicate_single_value_headers(self):
        from kubernetes.utils.impersonation import ImpersonationRequest
        with self.assertRaises(ImpersonationError):
            ImpersonationRequest((
                ("Impersonate-User", "a"),
                ("Impersonate-User", "b"),
            ))

    def test_resolve_accepts_config_and_header_mappings(self):
        config = ImpersonationConfig(user="alice", groups=["dev", "ops"])
        snapshot = config.snapshot()
        self.assertEqual(("alice",), (snapshot.user,))
        self.assertEqual(("dev", "ops"), snapshot.groups)
        self.assertEqual(
            snapshot.headers,
            resolve_impersonation(
                user="alice", groups=["dev", "ops"]).headers)


class SharedClientInterleavingTest(unittest.TestCase):
    """A shared client runs a restricted and an ordinary call interleaved."""

    def setUp(self):
        self.client, self.transport = make_client()
        self.client.impersonation = None

    def test_restricted_and_ordinary_calls_do_not_inherit_identity(self):
        # Which logical call each recorded request belongs to.
        self.transport.queue(NAMESPACE_LIST)
        self.transport.queue(NAMESPACE_LIST)
        self.transport.queue(NAMESPACE_LIST)

        api = CoreV1Api(self.client)
        api.list_namespace()  # ordinary call, client default

        claim = self.client.bind_impersonation(
            ImpersonationConfig(user="auditor", groups=["restricted"]))
        with claim:
            api.list_namespace()

        api.list_namespace()  # ordinary call after the restricted one

        users = self.transport.header_values("Impersonate-User")
        groups = self.transport.header_values("Impersonate-Group")
        self.assertEqual(["auditor"], users)
        self.assertEqual(["restricted"], groups)

        # The ordinary calls carry no impersonation at all.
        for index in (0, 2):
            request = self.transport.requests[index]
            names = {name.lower() for name, _ in request["headers"]}
            self.assertFalse(
                any(name.startswith("impersonate-") for name in names),
                request["headers"])

    def test_restricted_page_sequence_keeps_one_approval(self):
        pages = [
            {
                "apiVersion": "v1", "kind": "NamespaceList", "items": [],
                "metadata": {"continue": "page-2"},
            },
            {
                "apiVersion": "v1", "kind": "NamespaceList", "items": [],
                "metadata": {"continue": "page-3"},
            },
            {
                "apiVersion": "v1", "kind": "NamespaceList", "items": [],
                "metadata": {},
            },
        ]
        for page in pages:
            self.transport.queue(page)

        claim = self.client.bind_impersonation({"user": "auditor"})
        api = CoreV1Api(self.client)
        token = None
        seen_tokens = []
        while True:
            with claim:
                result = api.list_namespace(
                    _continue=token, limit=2)
            seen_tokens.append(token)
            token = result.metadata._continue
            if not token:
                break
        self.assertEqual(3, len(seen_tokens))

        self.assertEqual([None, "page-2", "page-3"], seen_tokens)
        self.assertEqual(3, len(self.transport.requests))
        self.assertEqual(
            ["auditor"] * 3,
            self.transport.header_values("Impersonate-User"))
        for request in self.transport.requests:
            self.assertIn("limit=2", request["url"])

    def test_mutating_the_config_after_binding_does_not_change_pages(self):
        for page in ({"items": [], "metadata": {"continue": "p2"}},
                     {"items": []}):
            self.transport.queue({"apiVersion": "v1",
                                  "kind": "NamespaceList", **page})

        config = {"user": "auditor", "groups": ["restricted"]}
        claim = self.client.bind_impersonation(config)
        config["user"] = "mallory"  # later change, must not apply

        api = CoreV1Api(self.client)
        with claim:
            api.list_namespace(limit=2)
        with claim:
            api.list_namespace(_continue="p2", limit=2)

        self.assertEqual(
            ["auditor", "auditor"],
            self.transport.header_values("Impersonate-User"))

    def test_client_default_is_never_written_by_a_call(self):
        self.client.impersonation = {"user": "service"}
        self.transport.queue(NAMESPACE_LIST)

        with self.client.bind_impersonation({"user": "auditor"}):
            CoreV1Api(self.client).list_namespace()

        self.assertEqual("service", self.client.impersonation.user)
        self.assertEqual(["auditor"],
                         self.transport.header_values("Impersonate-User"))


class RetryKeepsApprovalTest(unittest.TestCase):
    def test_retry_repeats_approved_snapshot(self):
        configuration = {
            "client_go_retries": True,
            "retries": 2,
        }
        client, transport = make_client(**configuration)
        transport.queue({"message": "retry"}, status=429, retry_after=0)
        transport.queue(NAMESPACE_LIST)

        claim = client.bind_impersonation(
            {"user": "auditor", "groups": ["restricted"]})
        with claim:
            CoreV1Api(client).list_namespace()

        self.assertEqual(2, len(transport.requests))
        for request in transport.requests:
            self.assertIn(("Impersonate-User", "auditor"),
                          request["headers"])
            self.assertIn(("Impersonate-Group", "restricted"),
                          request["headers"])

    def test_retry_after_opt_out_does_not_reintroduce_default(self):
        client, transport = make_client(
            client_go_retries=True, retries=1)
        client.impersonation = {"user": "service"}
        transport.queue({"message": "retry"}, status=429, retry_after=0)
        transport.queue(NAMESPACE_LIST)

        with client.bind_impersonation(None):
            CoreV1Api(client).list_namespace()

        self.assertEqual(2, len(transport.requests))
        for request in transport.requests:
            self.assertEqual([], [
                value for name, value in request["headers"]
                if name.lower().startswith("impersonate-")])
        # The client default survives the opt-out block.
        self.assertEqual("service", client.impersonation.user)


class WatchResumeKeepsApprovalTest(unittest.TestCase):
    def test_watch_restart_reuses_the_snapshot(self):
        from unittest import mock

        client, transport = make_client()
        client.impersonation = {"user": "service"}
        api = CoreV1Api(client)
        calls = []

        def make_response(lines):
            response = mock.Mock()
            response.status = 200
            response.headers = {}
            response.stream = mock.Mock(return_value=lines)
            response.close = mock.Mock()
            response.release_conn = mock.Mock()
            return response

        expired = make_response([
            b'{"type":"ERROR","object":{"code":410,"reason":"Expired",'
            b'"message":"continue"}}\n'
        ])
        resumed = make_response([
            b'{"type":"ADDED","object":{"metadata":{"name":"n1",'
            b'"resourceVersion":"2"}}}\n'
        ])

        def list_namespace(**kwargs):
            calls.append(kwargs)
            return expired if len(calls) == 1 else resumed

        list_namespace.__doc__ = ":rtype: V1NamespaceList\n"
        list_namespace.api_client = api.api_client

        watcher = Watch()
        claim = client.bind_impersonation(
            {"user": "auditor", "groups": ["restricted"]})
        with claim:
            events = []
            for event in watcher.stream(list_namespace,
                                        resource_version="1"):
                events.append(event)
                break

        self.assertEqual(2, len(calls), calls)
        for kwargs in calls:
            headers = kwargs["_headers"]
            self.assertEqual("auditor", headers["Impersonate-User"])
            self.assertIn("restricted", headers["Impersonate-Group"])

        # The shared default never took over, even between resumes.
        self.assertEqual("service", client.impersonation.user)

    def test_watch_without_binding_uses_client_default(self):
        from unittest import mock

        client, transport = make_client()
        client.impersonation = {"user": "service"}
        api = CoreV1Api(client)
        calls = []

        def list_namespace(**kwargs):
            calls.append(kwargs)
            response = mock.Mock()
            response.status = 200
            response.headers = {}
            response.stream = mock.Mock(return_value=[
                b'{"type":"ADDED","object":{"metadata":{"name":"n1",'
                b'"resourceVersion":"1"}}}\n'
            ])
            response.close = mock.Mock()
            response.release_conn = mock.Mock()
            return response

        list_namespace.__doc__ = ":rtype: V1NamespaceList\n"
        list_namespace.api_client = api.api_client

        for _ in Watch().stream(list_namespace):
            break

        self.assertEqual("service", calls[0]["_headers"]["Impersonate-User"])


class DynamicClientIdentityTest(unittest.TestCase):
    def test_dynamic_requests_use_the_active_identity(self):
        from kubernetes.dynamic import DynamicClient
        from kubernetes.dynamic.discovery import EagerDiscoverer

        client, transport = make_client()
        client.impersonation = {"user": "service"}
        transport.queue({"kind": "APIGroupList", "groups": []})

        with client.bind_impersonation({"user": "auditor"}):
            dynamic = DynamicClient(
                client, discoverer=_OfflineDiscoverer)

        transport.queue({"kind": "APIGroupList", "groups": []})
        with client.bind_impersonation({"user": "auditor"}):
            dynamic.request("get", "/apis")

        self.assertEqual(["auditor"],
                         transport.header_values("Impersonate-User"))
        # Outside the block the client default applies again.
        transport.queue({"kind": "APIGroupList", "groups": []})
        dynamic.request("get", "/apis")
        self.assertEqual(["auditor", "service"],
                         transport.header_values("Impersonate-User"))


class _OfflineDiscoverer:
    """Discoverer stand-in that never contacts the cluster."""

    def __init__(self, client, cache_file=None):
        self.client = client

    def get(self, **kwargs):
        raise KeyError(kwargs)


class ThreadSharedClientTest(unittest.TestCase):
    def test_threads_do_not_share_an_active_binding(self):
        client, transport = make_client()
        barrier = threading.Barrier(2)
        seen = {}

        def worker(name, identity):
            barrier.wait()
            claim = client.bind_impersonation(identity)
            with claim:
                barrier.wait()
                transport.queue(NAMESPACE_LIST)
                CoreV1Api(client).list_namespace()
                seen[name] = transport.header_values("Impersonate-User")[-1]

        threads = [
            threading.Thread(target=worker,
                             args=("a", {"user": "auditor-a"})),
            threading.Thread(target=worker,
                             args=("b", {"user": "auditor-b"})),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        self.assertEqual({"a": "auditor-a", "b": "auditor-b"}, seen)
        self.assertEqual({"auditor-a", "auditor-b"},
                         set(transport.header_values("Impersonate-User")))
        # The client default was never modified, so a later call is ordinary.
        transport.queue(NAMESPACE_LIST)
        CoreV1Api(client).list_namespace()
        self.assertEqual(2, len(transport.header_values("Impersonate-User")))


class PrecedenceTest(unittest.TestCase):
    def test_explicit_override_and_header_inputs(self):
        client, transport = make_client()
        client.impersonation = {"user": "service"}
        transport.queue(NAMESPACE_LIST)

        serialized = client.param_serialize(
            "GET", "/api/v1/namespaces",
            header_params={"Impersonate-User": "from-header"},
            auth_settings=None,
            _impersonation={"user": "from-override"},
        )
        self.assertEqual("from-override",
                         serialized[2]["Impersonate-User"])

        has_header = client.param_serialize(
            "GET", "/api/v1/namespaces",
            header_params={"Impersonate-User": "from-header"},
            auth_settings=None,
        )
        self.assertEqual("from-header",
                         has_header[2]["Impersonate-User"])

    def test_configuration_default_is_used_when_client_has_none(self):
        configuration = Configuration(
            host="http://api.test", proxy="", no_proxy="")
        configuration.impersonation = {"user": "config-user"}
        client = ApiClient(configuration)
        transport = RecordingTransport()
        client.rest_client.pool_manager = transport
        transport.queue(NAMESPACE_LIST)

        CoreV1Api(client).list_namespace()

        self.assertEqual(["config-user"],
                         transport.header_values("Impersonate-User"))

    def test_conflicting_nested_binding_is_rejected(self):
        client, _ = make_client()
        with self.assertRaises(ImpersonationError):
            with client.bind_impersonation({"user": "a"}):
                with client.bind_impersonation({"user": "b"}):
                    pass

    def test_multiple_groups_and_extra_values_are_separate_lines(self):
        client, transport = make_client()
        client.impersonation = {
            "user": "auditor",
            "groups": ["dev", "ops"],
            "uid": "uid-1",
            "extra": {"scope": ["read", "list"]},
        }
        transport.queue(NAMESPACE_LIST)
        CoreV1Api(client).list_namespace()

        headers = transport.requests[0]["headers"]
        self.assertIn(("Impersonate-Group", "dev"), headers)
        self.assertIn(("Impersonate-Group", "ops"), headers)
        self.assertIn(("Impersonate-Extra-scope", "read"), headers)
        self.assertIn(("Impersonate-Extra-scope", "list"), headers)
        self.assertIn(("Impersonate-Uid", "uid-1"), headers)


class AsyncRecordingResponse:
    status = 200
    reason = "OK"
    headers = {"Content-Type": "application/json"}
    data = json.dumps(NAMESPACE_LIST).encode()

    async def read(self):
        return self.data

    def getheaders(self):
        return self.headers

    def close(self):
        pass


class AsyncRecordingTransport:
    """Stand-in for the aiohttp session used through RESTClientObject.

    Keeping the real ``RESTClientObject.request`` in the path exercises the
    header expansion it performs for repeated impersonation lines.
    """

    def __init__(self):
        self.requests = []

    async def request(self, method=None, url=None, headers=None, **kwargs):
        self.requests.append({
            "method": method,
            "url": url,
            "headers": list(headers.items()) if hasattr(headers, "items")
            else list(headers),
        })
        return AsyncRecordingResponse()

    async def close(self):
        pass

    def header_values(self, name):
        return [value for request in self.requests
                for key, value in request["headers"]
                if key.lower() == name.lower()]


@unittest.skipUnless(HAS_ASYNC, "kubernetes.aio dependencies are not installed")
class AsyncSharedClientTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.configuration = AsyncConfiguration(
            host="http://api.test", proxy="")
        self.client = AsyncApiClient(self.configuration)
        self.transport = AsyncRecordingTransport()
        self.client.rest_client.pool_manager = self.transport

    async def asyncTearDown(self):
        await self.client.close()

    async def test_concurrent_tasks_keep_their_own_identity(self):
        import asyncio

        from kubernetes.aio.client import CoreV1Api as AsyncCoreV1Api

        ready = asyncio.Event()
        release = asyncio.Event()

        async def call(identity, gate):
            async with self.client.bind_impersonation(identity):
                if gate:
                    ready.set()
                    await release.wait()
                await AsyncCoreV1Api(self.client).list_namespace()

        restricted = asyncio.create_task(
            call({"user": "auditor"}, True))
        await ready.wait()
        ordinary = asyncio.create_task(call(None, False))
        release.set()
        await asyncio.gather(restricted, ordinary)

        self.assertEqual(["auditor"],
                         self.transport.header_values("Impersonate-User"))
        # One of the two requests carried no impersonation at all.
        self.assertEqual(1, sum(
            1 for request in self.transport.requests
            if not any(name.lower().startswith("impersonate-")
                       for name, _ in request["headers"])))

    async def test_ordinary_task_does_not_inherit_previous_identity(self):
        from kubernetes.aio.client import CoreV1Api as AsyncCoreV1Api

        async with self.client.bind_impersonation({"user": "auditor"}):
            await AsyncCoreV1Api(self.client).list_namespace()
        await AsyncCoreV1Api(self.client).list_namespace()

        self.assertEqual(["auditor"],
                         self.transport.header_values("Impersonate-User"))
        self.assertEqual(1, sum(
            1 for request in self.transport.requests
            if not any(name.lower().startswith("impersonate-")
                       for name, _ in request["headers"])))

    async def test_extra_values_reach_transport_as_separate_lines(self):
        from kubernetes.aio.client import CoreV1Api as AsyncCoreV1Api

        self.client.impersonation = {
            "user": "auditor",
            "groups": ["dev", "ops"],
            "extra": {"scope": ["read", "list"]},
        }
        await AsyncCoreV1Api(self.client).list_namespace()

        self.assertEqual(["dev", "ops"],
                         self.transport.header_values("Impersonate-Group"))
        self.assertEqual(["read", "list"],
                         self.transport.header_values(
                             "Impersonate-Extra-scope"))


if __name__ == "__main__":
    unittest.main()
