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

"""Recording-service tests for dry-run permits.

``RecordingTransport`` replaces only the urllib3 pool manager beneath the
real ``RESTClientObject``.  ``ApiClient.param_serialize`` and the REST
layer still build paths, query strings, and JSON bodies, so the records
below are exactly the requests the client would put on the wire.  The
service commits a write only when the request carries no ``dryRun`` query
value.  ``DryRunPermitHttpTest`` repeats the flow over a real local socket
when the environment permits port binding.
"""

import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import unittest
from urllib.parse import parse_qsl, urlsplit

from kubernetes.client import (
    ApiClient,
    Configuration,
    V1ConfigMap,
    V1ObjectMeta,
)
from kubernetes.client.exceptions import ApiValueError
from kubernetes.utils.dry_run import (
    CommitApproval,
    DryRunPermit,
    DryRunRetry,
    DryRunSession,
    PermitMismatch,
)

RESOURCE = "/api/v1/namespaces/default/configmaps/sample"


def _config_map(data):
    return V1ConfigMap(
        api_version="v1",
        kind="ConfigMap",
        metadata=V1ObjectMeta(
            name="sample", namespace="default", resource_version="7"),
        data=dict(data),
    )


class _Response:
    def __init__(self, status, body, headers=None):
        self.status = status
        self.reason = "OK" if status < 400 else "Failure"
        self.headers = dict(headers or {})
        self.data = body

    def read(self):
        return self.data


class RecordingTransport:
    """A recording stand-in for the urllib3 pool manager.

    Swapping this layer still exercises ``ApiClient.param_serialize`` and
    ``RESTClientObject``: URLs, headers, and the JSON body recorded below
    are what the real transport would receive.  The service applies a write
    to its stored object only when the URL has no ``dryRun`` value.
    """

    def __init__(self, stored, statuses=None):
        self.stored = copy.deepcopy(stored)
        self.statuses = list(statuses or [200])
        self.requests = []
        self.mutations_committed = 0

    def clear(self):
        pass

    def request(self, method, url, fields=None, timeout=None,
                headers=None, preload_content=None, body=None,
                **kwargs):
        path, pairs = urlsplit(url).path, parse_qsl(
            urlsplit(url).query, keep_blank_values=True)
        dry_run = [value for key, value in pairs if key == "dryRun"]
        raw_body = body
        if isinstance(raw_body, (bytes, bytearray)):
            raw_body = raw_body.decode("utf-8")
        parsed_body = json.loads(raw_body) if raw_body else None
        self.requests.append({
            "method": method,
            "url": url,
            "path": path,
            "query": pairs,
            "dry_run": dry_run,
            "raw_body": raw_body,
            "body": parsed_body,
            "headers": dict(headers or {}),
        })
        index = len(self.requests) - 1
        status = self.statuses[min(index, len(self.statuses) - 1)]

        if status < 400 and not dry_run:
            self.stored = copy.deepcopy(parsed_body)
            self.mutations_committed += 1
        if status < 400:
            payload = copy.deepcopy(parsed_body)
            # The marker is a real ConfigMap field so ApiClient can
            # deserialize it into V1ConfigMap.
            payload.setdefault("metadata", {})["labels"] = {
                "preview": "true" if dry_run else "false",
            }
            return _Response(status, json.dumps(payload).encode())
        return _Response(
            status, b'{"message": "transient failure"}',
            {"Retry-After": "0"} if status == 503 else {},
        )


class DryRunPermitTest(unittest.TestCase):
    def setUp(self):
        stored = _config_map({"mode": "off"}).to_dict(serialize=True)
        self.transport = RecordingTransport(stored, statuses=[200])
        self.api_client = ApiClient(Configuration(
            host="http://kubernetes.test", proxy="", no_proxy=""))
        # The real RESTClientObject stays in place so its body and header
        # serialization is part of what the recording service sees.
        self.api_client.rest_client.pool_manager = self.transport
        self.session = DryRunSession(self.api_client)

    def tearDown(self):
        self.api_client.close()

    def _stored_data(self):
        return self.transport.stored["data"]

    def test_successful_preview_retry_and_separately_approved_update(self):
        staged = _config_map({"mode": "on"})
        preview_permit = DryRunPermit.preview(RESOURCE, "replace", staged)

        # First attempt is transient; the retry uses the same permit and
        # keeps the preview meaning on the wire.
        self.transport.statuses = [503, 200]
        preview = self.session.send(
            preview_permit,
            response_type="V1ConfigMap",
            retry=DryRunRetry(max_attempts=2),
        )

        self.assertTrue(preview.ok)
        self.assertTrue(preview.is_preview)
        self.assertTrue(preview.preview_only)
        self.assertTrue(preview.retried)
        self.assertFalse(preview.committed)
        self.assertEqual(2, len(self.transport.requests))
        for record in self.transport.requests:
            with self.subTest(url=record["url"]):
                self.assertEqual("PUT", record["method"])
                self.assertEqual(RESOURCE, record["path"])
                self.assertEqual(["All"], record["dry_run"])
                self.assertEqual({"mode": "on"}, record["body"]["data"])
        self.assertEqual(["All"], preview.query_parameters["dryRun"])
        self.assertEqual(
            "dryRun=All",
            urlsplit(self.transport.requests[0]["url"]).query,
        )
        self.assertEqual({"mode": "on"}, preview.body["data"])
        self.assertEqual(
            json.dumps({"apiVersion": "v1", "kind": "ConfigMap",
                        "metadata": {"name": "sample", "namespace": "default",
                                     "resourceVersion": "7"},
                        "data": {"mode": "on"}},
                       sort_keys=True),
            json.dumps(self.transport.requests[-1]["body"], sort_keys=True))
        self.assertEqual("V1ConfigMap", type(preview.data).__name__)
        self.assertEqual({"preview": "true"}, preview.data.metadata.labels)
        # A successful preview must not persist the change.
        self.assertEqual({"mode": "off"}, self._stored_data())
        self.assertEqual(0, self.transport.mutations_committed)

        # The staged value changes after the preview.  The old preview no
        # longer covers it and must not authorize the write.
        staged.data["mode"] = "aggressive"
        review = preview.review(body=staged)
        self.assertFalse(review.matches)
        self.assertIn("body changed", review.reasons)
        with self.assertRaises(PermitMismatch) as raised:
            self.session.build(preview_permit, body=staged)
        self.assertIn("body changed", raised.exception.reasons)
        with self.assertRaises(PermitMismatch):
            CommitApproval.for_preview(
                preview, approver="release-manager",
                reference="CHG-42", body=staged)
        self.assertEqual(2, len(self.transport.requests))

        # Preview the edited value again, then obtain a separate approval
        # that is bound to exactly that previewed change.
        self.transport.statuses = [200]
        refreshed = self.session.send(
            DryRunPermit.preview(RESOURCE, "replace", staged),
            response_type="V1ConfigMap",
        )
        approval = CommitApproval.for_preview(
            refreshed, approver="release-manager", reference="CHG-42")
        commit_permit = DryRunPermit.commit(
            RESOURCE, "replace", staged, approval=approval)
        commit = self.session.send(
            commit_permit, response_type="V1ConfigMap")

        self.assertTrue(commit.ok)
        self.assertTrue(commit.is_commit)
        self.assertTrue(commit.committed)
        self.assertFalse(commit.is_preview)
        self.assertEqual("PUT", commit.executed_method)
        self.assertEqual("replace", commit.executed_action)
        last = self.transport.requests[-1]
        self.assertEqual("PUT", last["method"])
        self.assertEqual([], last["dry_run"])
        self.assertEqual({"mode": "aggressive"}, last["body"]["data"])
        self.assertNotIn("dryRun", commit.query_parameters)
        self.assertEqual(
            {"preview": "false"}, commit.data.metadata.labels)
        self.assertEqual(approval, commit.approval)
        self.assertEqual("CHG-42", commit.approval_reference)
        self.assertEqual({"mode": "aggressive"}, self._stored_data())
        self.assertEqual(1, self.transport.mutations_committed)
        self.assertEqual(
            {
                "action": "replace",
                "method": "PUT",
                "path": RESOURCE,
                "status": 200,
                "dryRun": [],
            },
            commit.executed,
        )

    def test_commit_approval_is_bound_to_the_previewed_change(self):
        preview_permit = DryRunPermit.preview(
            RESOURCE, "replace", _config_map({"mode": "on"}))
        preview = self.session.send(
            preview_permit, response_type="V1ConfigMap")
        approval = CommitApproval.for_preview(
            preview, approver="release-manager", reference="CHG-7")

        # Editing the body after approval is detected when the commit
        # permit is built, before any request is sent.
        edited = _config_map({"mode": "off"})
        with self.assertRaises(PermitMismatch) as raised:
            DryRunPermit.commit(
                RESOURCE, "replace", edited, approval=approval)
        self.assertIn("change does not match", str(raised.exception))
        self.assertEqual(1, len(self.transport.requests))

        with self.assertRaises(TypeError):
            DryRunPermit.commit(
                RESOURCE, "replace", _config_map({"mode": "on"}),
                approval=preview)

    def test_retry_rejects_changed_body_before_second_attempt(self):
        first = _config_map({"mode": "on"})
        preview_permit = DryRunPermit.preview(RESOURCE, "replace", first)
        self.transport.statuses = [503, 200]

        def body_factory(attempt):
            if attempt == 0:
                return first
            return _config_map({"mode": "changed-on-retry"})

        with self.assertRaises(PermitMismatch) as raised:
            self.session.send(
                preview_permit,
                body_factory=body_factory,
                retry=DryRunRetry(max_attempts=2),
            )
        self.assertIn("body changed", raised.exception.reasons)
        self.assertEqual(1, len(self.transport.requests))
        self.assertEqual(["All"], self.transport.requests[0]["dry_run"])
        self.assertEqual({"mode": "off"}, self._stored_data())

    def test_preview_retry_stays_preview_on_the_wire(self):
        permit = DryRunPermit.preview(
            RESOURCE, "replace", _config_map({"mode": "on"}))
        self.transport.statuses = [503, 503, 200]

        exchange = self.session.send(
            permit, retry=DryRunRetry(max_attempts=3))
        self.assertTrue(exchange.ok)
        self.assertEqual(3, len(exchange.attempts))
        self.assertEqual(3, len(self.transport.requests))
        for record in self.transport.requests:
            self.assertEqual(["All"], record["dry_run"])
        self.assertEqual({"mode": "off"}, self._stored_data())
        self.assertEqual(0, self.transport.mutations_committed)

    def test_query_and_action_drift_are_explained(self):
        permit = DryRunPermit.preview(
            RESOURCE, "replace", _config_map({"mode": "on"}),
            query_params=[("fieldManager", "release-page")])
        request = self.session.build(permit)

        self.assertEqual(
            ["release-page"], request.query_parameters["fieldManager"])
        self.assertEqual(["All"], request.query_parameters["dryRun"])
        self.assertIn("dryRun=All", request.url)

        check = permit.check(
            url=request.url.replace("dryRun=All", "dryRun=Preview"),
            body=request.body)
        self.assertFalse(check.matches)
        self.assertIn("preview permit requires exactly dryRun=All",
                      check.reasons[0])

        changed_query = request.url.replace(
            "fieldManager=release-page", "fieldManager=other")
        check = permit.check(url=changed_query, body=request.body)
        self.assertFalse(check.matches)
        self.assertIn("query parameters changed", check.reasons)

        check = permit.check(
            url=request.url, body=request.body, method="PATCH")
        self.assertFalse(check.matches)
        self.assertIn("method PATCH does not match permit method PUT",
                      check.reasons)

        check = permit.check(
            url=request.url, body=request.body, action="patch")
        self.assertFalse(check.matches)
        self.assertIn(
            "action 'patch' does not match permit action 'replace'",
            check.reasons)

        commit = DryRunPermit.commit(
            RESOURCE, "replace", _config_map({"mode": "on"}),
            query_params=[("fieldManager", "release-page")],
            approval=CommitApproval.for_preview(
                self.session.send(
                    DryRunPermit.preview(
                        RESOURCE, "replace", _config_map({"mode": "on"}),
                        query_params=[("fieldManager", "release-page")]),
                    response_type="V1ConfigMap"),
                approver="release-manager", reference="CHG-7"),
        )
        commit_request = self.session.build(commit)
        self.assertEqual(
            ["release-page"],
            commit_request.query_parameters["fieldManager"])
        self.assertNotIn("dryRun", commit_request.query_parameters)
        with self.assertRaises(ApiValueError):
            self.session.build(commit, query_params=[("dryRun", "All")])

    def test_action_and_verb_mapping(self):
        cases = [
            ("replace_namespaced_config_map", "PUT"),
            ("create_namespaced_config_map", "POST"),
            ("patch_namespaced_config_map", "PATCH"),
            ("delete_namespaced_config_map", "DELETE"),
            ("apply", "PATCH"),
        ]
        for action, expected in cases:
            with self.subTest(action=action):
                permit = DryRunPermit.preview(
                    RESOURCE, action, _config_map({"mode": "on"}))
                self.assertEqual(expected, permit.method)
                request = self.session.build(permit)
                self.assertEqual(expected, request.method)
                self.assertEqual(["All"],
                                 request.query_parameters["dryRun"])

        with self.assertRaises(ValueError):
            DryRunPermit.preview(RESOURCE, "read", {})

    def test_direct_delete_and_patch_use_explicit_verbs(self):
        # A delete or patch action must keep its own verb; a replace permit
        # cannot stand in for it.
        for action, method in (("delete", "DELETE"), ("patch", "PATCH")):
            with self.subTest(action=action):
                permit = DryRunPermit.preview(
                    RESOURCE, action, {"metadata": {"name": "sample"}})
                request = self.session.build(permit)
                self.assertEqual(method, request.method)
                self.assertEqual(["All"],
                                 request.query_parameters["dryRun"])

        replace = DryRunPermit.preview(
            RESOURCE, "replace", _config_map({"mode": "on"}))
        request = self.session.build(replace)
        check = replace.check(
            url=request.url, body=request.body, method="DELETE")
        self.assertFalse(check.matches)
        self.assertIn("method DELETE does not match permit method PUT",
                      check.reasons)

    def test_preview_rejects_caller_supplied_dry_run(self):
        permit = DryRunPermit.preview(
            RESOURCE, "replace", _config_map({"mode": "on"}))
        with self.assertRaises(ApiValueError):
            self.session.build(permit, query_params=[("dryRun", "None")])
        with self.assertRaises(ValueError):
            DryRunPermit.preview(
                RESOURCE, "replace", _config_map({"mode": "on"}),
                query_params=[("dryRun", "All")])
        self.assertEqual([], self.transport.requests)

    def test_preview_permit_body_cannot_be_overridden_to_none(self):
        permit = DryRunPermit.preview(
            RESOURCE, "replace", _config_map({"mode": "on"}))
        with self.assertRaises(PermitMismatch):
            self.session.build(permit, body=None)
        self.assertEqual([], self.transport.requests)

    def test_permit_requires_concrete_resource_path(self):
        # A permit binds one concrete resource; a templated path could
        # expand to a different resource under the same approval.
        with self.assertRaises(ValueError):
            DryRunPermit.preview(
                "/api/v1/namespaces/{namespace}/configmaps/sample",
                "replace", _config_map({"mode": "on"}))

    def test_commit_rejects_different_change_before_send(self):
        staged = _config_map({"mode": "on"})
        preview = self.session.send(DryRunPermit.preview(
            RESOURCE, "replace", staged), response_type="V1ConfigMap")
        approval = CommitApproval.for_preview(
            preview, approver="release-manager", reference="CHG-8")

        with self.assertRaises(PermitMismatch):
            self.session.send(DryRunPermit.commit(
                RESOURCE, "replace", _config_map({"mode": "other"}),
                approval=approval))
        # Rejected while building the permit, before the commit request.
        self.assertEqual(1, len(self.transport.requests))
        self.assertEqual({"mode": "off"}, self._stored_data())

    def test_exchange_records_snapshot_of_sent_body(self):
        staged = _config_map({"mode": "on"})
        exchange = self.session.send(
            DryRunPermit.preview(RESOURCE, "replace", staged),
            response_type="V1ConfigMap",
        )
        sent_digest = exchange.body_digest

        # Editing the caller's object after sending must not rewrite the
        # record or make the exchange look like it sent something else.
        staged.data["mode"] = "after-send"
        self.assertEqual({"mode": "on"}, exchange.body["data"])
        self.assertEqual(sent_digest, exchange.body_digest)
        self.assertTrue(exchange.body_matches_permit)
        self.assertTrue(exchange.review().matches)

    def test_build_snapshots_body_against_later_edits(self):
        staged = _config_map({"mode": "on"})
        permit = DryRunPermit.preview(RESOURCE, "replace", staged)
        request = self.session.build(permit)
        staged.data["mode"] = "edited-after-build"
        self.assertEqual({"mode": "on"}, request.body["data"])
        self.assertTrue(request.recheck().matches)

    def test_send_request_after_caller_edits_body(self):
        staged = _config_map({"mode": "on"})
        permit = DryRunPermit.preview(RESOURCE, "replace", staged)
        request = self.session.build(permit)

        request.body["data"]["mode"] = "edited-after-build"
        with self.assertRaises(PermitMismatch) as raised:
            self.session.send_request(request)
        self.assertIn("body changed", raised.exception.reasons)
        self.assertEqual([], self.transport.requests)

    def test_failed_preview_is_not_evidence_for_approval(self):
        permit = DryRunPermit.preview(
            RESOURCE, "replace", _config_map({"mode": "on"}))
        self.transport.statuses = [422]
        preview = self.session.send(permit)

        self.assertFalse(preview.ok)
        self.assertFalse(preview.committed)
        with self.assertRaises(PermitMismatch):
            CommitApproval.for_preview(
                preview, approver="release-manager", reference="CHG-9")
        with self.assertRaises(ValueError):
            preview.review()  # failed previews are not reviewable
        self.assertEqual({"mode": "off"}, self._stored_data())
        self.assertEqual(0, self.transport.mutations_committed)


class DryRunPermitExportTest(unittest.TestCase):
    def test_importable_from_kubernetes_utils(self):
        from kubernetes import utils

        for name in (
            "CommitApproval",
            "DRY_RUN_ALL",
            "DryRunExchange",
            "DryRunPermit",
            "DryRunRequest",
            "DryRunRetry",
            "DryRunSession",
            "PermitCheck",
            "PermitMismatch",
            "review_preview",
        ):
            with self.subTest(name=name):
                self.assertTrue(hasattr(utils, name))
                self.assertIn(name, utils.__all__)

        self.assertEqual("All", utils.DRY_RUN_ALL)


class _HttpRecordingHandler(BaseHTTPRequestHandler):
    """A real HTTP service that records requests and honors ``dryRun``."""

    def do_PUT(self):
        self._handle()

    do_POST = do_PUT
    do_PATCH = do_PUT
    do_DELETE = do_PUT

    def _handle(self):
        server = self.server
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        pairs = parse_qsl(urlsplit(self.path).query, keep_blank_values=True)
        dry_run = [value for key, value in pairs if key == "dryRun"]
        body = json.loads(raw) if raw else None
        with server.lock:
            server.requests.append({
                "method": self.command,
                "path": self.path,
                "query": pairs,
                "dry_run": dry_run,
                "body": body,
            })
            index = len(server.requests) - 1
            status = server.statuses[min(index, len(server.statuses) - 1)]
            if status < 400 and not dry_run:
                server.stored = copy.deepcopy(body)
                server.mutations_committed += 1

        if status < 400:
            payload = copy.deepcopy(body)
            payload.setdefault("metadata", {})["labels"] = {
                "preview": "true" if dry_run else "false",
            }
            response = json.dumps(payload).encode()
        else:
            response = b'{"message": "transient failure"}'
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        if status == 503:
            self.send_header("Retry-After", "0")
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format, *args):
        pass


class DryRunPermitHttpTest(unittest.TestCase):
    """The same flow over a real socket with the real ``ApiClient``.

    Port binding is unavailable in some sandboxes; the class skips only in
    that case, not on assertion failures.
    """

    @classmethod
    def setUpClass(cls):
        try:
            server = ThreadingHTTPServer(
                ("127.0.0.1", 0), _HttpRecordingHandler)
        except PermissionError as error:
            # Some sandboxes disable local port binding.  Skip only that
            # environment restriction; assertion failures still fail.
            raise unittest.SkipTest(
                "local port binding is unavailable: {}".format(error))
        cls.server = server
        server.requests = []
        server.statuses = [200]
        server.lock = threading.Lock()
        server.mutations_committed = 0
        server.stored = _config_map({"mode": "off"}).to_dict(serialize=True)
        cls.thread = threading.Thread(target=server.serve_forever)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "server", None) is None:
            return
        cls.server.shutdown()
        cls.thread.join()
        cls.server.server_close()

    def setUp(self):
        server = self.server
        with server.lock:
            server.requests.clear()
            server.statuses = [200]
            server.mutations_committed = 0
            server.stored = _config_map(
                {"mode": "off"}).to_dict(serialize=True)
        self.api_client = ApiClient(Configuration(
            host="http://127.0.0.1:{}".format(server.server_port),
            proxy="", no_proxy=""))
        self.session = DryRunSession(self.api_client)

    def tearDown(self):
        self.api_client.close()

    def test_preview_retry_and_approved_update_over_http(self):
        staged = _config_map({"mode": "on"})
        self.server.statuses = [503, 200]
        preview = self.session.send(
            DryRunPermit.preview(RESOURCE, "replace", staged),
            response_type="V1ConfigMap",
            retry=DryRunRetry(max_attempts=2),
        )

        self.assertTrue(preview.ok)
        self.assertTrue(preview.retried)
        self.assertEqual(2, len(self.server.requests))
        for record in self.server.requests:
            self.assertEqual("PUT", record["method"])
            self.assertEqual(RESOURCE, record["path"])
            self.assertEqual(["All"], record["dry_run"])
            self.assertEqual({"mode": "on"}, record["body"]["data"])
        self.assertEqual(2, len(preview.attempts))
        for attempt in preview.attempts:
            self.assertEqual({"mode": "on"}, attempt.sent_body["data"])
        self.assertTrue(preview.body_matches_permit)
        self.assertEqual({"mode": "off"}, self.server.stored["data"])
        self.assertEqual(0, self.server.mutations_committed)

        staged.data["mode"] = "aggressive"
        self.assertFalse(preview.review(body=staged).matches)
        with self.assertRaises(PermitMismatch):
            CommitApproval.for_preview(
                preview, approver="release-manager", reference="CHG-42",
                body=staged)

        self.server.statuses = [200]
        refreshed = self.session.send(
            DryRunPermit.preview(RESOURCE, "replace", staged),
            response_type="V1ConfigMap",
        )
        approval = CommitApproval.for_preview(
            refreshed, approver="release-manager", reference="CHG-42")
        commit = self.session.send(
            DryRunPermit.commit(
                RESOURCE, "replace", staged, approval=approval),
            response_type="V1ConfigMap",
        )

        self.assertTrue(commit.committed)
        self.assertEqual("PUT", commit.executed_method)
        self.assertEqual([], commit.dry_run_values)
        last = self.server.requests[-1]
        self.assertEqual([], last["dry_run"])
        self.assertEqual({"mode": "aggressive"}, last["body"]["data"])
        self.assertEqual({"mode": "aggressive"}, self.server.stored["data"])
        self.assertEqual(1, self.server.mutations_committed)

if __name__ == "__main__":
    unittest.main()
