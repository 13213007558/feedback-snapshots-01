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

import datetime
import threading
import unittest

from kubernetes.config.audit import (AuditEvent, AuditLog,
                                      SelectionProvenance,
                                      EVENT_CREDENTIAL_REFRESH,
                                      EVENT_CREDENTIAL_REFRESH_FAILED,
                                      EVENT_REQUEST, EVENT_SELECTION)
from kubernetes.config.dateutil import UTC

SECRET_TOKEN = "super-secret-token-value"
SECRET_PASSWORD = "super-secret-password"


class SelectionProvenanceTest(unittest.TestCase):

    def _provenance(self):
        return SelectionProvenance(
            context="ctx-a",
            cluster="cluster-a",
            user="user-a",
            config_path="/cfg/a.yaml",
            cluster_path="/cfg/a.yaml",
            user_path="/cfg/b.yaml",
            auth_method="token",
            credential_generation=2)

    def test_diagnostic_dict_contains_only_allowed_identifiers(self):
        data = self._provenance().diagnostic_dict()
        self.assertEqual(data, {
            "context": "ctx-a",
            "cluster": "cluster-a",
            "user": "user-a",
            "config_path": "/cfg/a.yaml",
            "cluster_path": "/cfg/a.yaml",
            "user_path": "/cfg/b.yaml",
            "auth_method": "token",
            "credential_generation": 2,
        })

    def test_none_fields_are_omitted(self):
        data = SelectionProvenance(context="ctx-a").diagnostic_dict()
        self.assertEqual(data, {"context": "ctx-a"})

    def test_with_generation_preserves_sources(self):
        original = self._provenance()
        rotated = original.with_generation(3)
        self.assertEqual(3, rotated.credential_generation)
        # Source identifiers are carried over unchanged.
        self.assertEqual(original.context, rotated.context)
        self.assertEqual(original.user_path, rotated.user_path)
        self.assertEqual(original.cluster, rotated.cluster)

    def test_equality_is_based_on_diagnostic_content(self):
        self.assertEqual(self._provenance(), self._provenance())


class AuditLogTest(unittest.TestCase):

    def setUp(self):
        self.audit_log = AuditLog()
        self.provenance = SelectionProvenance(
            context="ctx-a", cluster="cluster-a", user="user-a",
            credential_generation=1)

    def test_records_selection_request_and_refresh(self):
        self.audit_log.record_selection(self.provenance)
        self.audit_log.record_request(self.provenance)
        self.audit_log.record_credential_refresh(self.provenance)

        types = [event.event_type for event in self.audit_log.events()]
        self.assertEqual(
            [EVENT_SELECTION, EVENT_REQUEST, EVENT_CREDENTIAL_REFRESH],
            types)

    def test_failed_refresh_is_marked_and_keeps_message(self):
        error = RuntimeError("credential endpoint unreachable")
        self.audit_log.record_credential_refresh(self.provenance)
        self.audit_log.record_credential_refresh_failed(
            self.provenance, error)

        failed = self.audit_log.events(
            event_type=EVENT_CREDENTIAL_REFRESH_FAILED)
        self.assertEqual(1, len(failed))
        self.assertEqual("failed", failed[0].status)
        self.assertIn("unreachable", failed[0].error)

    def test_filtering_by_event_type_and_context(self):
        other = SelectionProvenance(context="ctx-b",
                                    credential_generation=1)
        self.audit_log.record_request(self.provenance)
        self.audit_log.record_request(other)

        requests = self.audit_log.events(event_type=EVENT_REQUEST)
        self.assertEqual(2, len(requests))
        ctx_a = self.audit_log.events(context="ctx-a")
        self.assertEqual(1, len(ctx_a))
        self.assertEqual("ctx-a", ctx_a[0].provenance.context)

    def test_diagnostics_never_include_secret_material(self):
        # Even if a caller mistakenly put secret-ish data somewhere, the
        # diagnostic surface only emits the allow-listed provenance keys.
        self.audit_log.record_request(self.provenance)
        for record in self.audit_log.diagnostics():
            flattened = repr(record)
            self.assertNotIn(SECRET_TOKEN, flattened)
            self.assertNotIn(SECRET_PASSWORD, flattened)
            self.assertEqual(
                set(record["provenance"]),
                set(record["provenance"]).intersection(
                    {"context", "cluster", "user", "config_path",
                     "cluster_path", "user_path", "auth_method",
                     "credential_generation"}))

    def test_max_events_bounds_memory(self):
        bounded = AuditLog(max_events=3)
        for _ in range(10):
            bounded.record_request(self.provenance)
        self.assertEqual(3, len(bounded.events()))

    def test_last_event_returns_most_recent_match(self):
        self.audit_log.record_selection(self.provenance)
        self.audit_log.record_request(self.provenance)
        self.assertEqual(
            EVENT_REQUEST, self.audit_log.last_event().event_type)
        self.assertEqual(
            EVENT_SELECTION,
            self.audit_log.last_event(EVENT_SELECTION).event_type)

    def test_clear_empties_the_log(self):
        self.audit_log.record_request(self.provenance)
        self.audit_log.clear()
        self.assertEqual([], self.audit_log.events())

    def test_thread_safe_concurrent_recording(self):
        def worker():
            for _ in range(200):
                self.audit_log.record_request(self.provenance)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual(1000, len(self.audit_log.events()))


class AuditEventTest(unittest.TestCase):

    def test_diagnostic_dict_is_shareable(self):
        provenance = SelectionProvenance(
            context="ctx-a", credential_generation=7)
        event = AuditEvent(
            EVENT_CREDENTIAL_REFRESH_FAILED, provenance,
            datetime.datetime.now(tz=UTC),
            status="failed", error="boom")
        data = event.diagnostic_dict()
        self.assertEqual(EVENT_CREDENTIAL_REFRESH_FAILED,
                         data["event_type"])
        self.assertEqual("failed", data["status"])
        self.assertEqual("boom", data["error"])
        self.assertEqual(7, data["provenance"]["credential_generation"])
        self.assertIn("timestamp", data)


if __name__ == "__main__":
    unittest.main()
