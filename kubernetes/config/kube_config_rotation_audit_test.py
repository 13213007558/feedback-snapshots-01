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

"""End-to-end provenance/audit behaviour across a kubeconfig rotation.

Two synthetic kubeconfig files are loaded through the real
``KubeConfigMerger``/``KubeConfigLoader``.  A credential is refreshed through
a real exec subprocess so that a refresh can be paused and made to fail late.
The assertions prove that:

* every request is attributable to the config and credential generation it
  actually used;
* a refresh failure that returns after the active selection has moved on still
  attributes to the provenance captured when that refresh was started;
* shared diagnostics expose only allow-listed source identifiers, never the
  full config or token material.
"""

import base64
import os
import sys
import tempfile
import threading
import time
import unittest

import yaml

from kubernetes.client import Configuration
from kubernetes.config.audit import (AuditLog,
                                     EVENT_CREDENTIAL_REFRESH,
                                     EVENT_CREDENTIAL_REFRESH_FAILED,
                                     EVENT_REQUEST, EVENT_SELECTION)
from kubernetes.config import record_request_for_configuration
from kubernetes.config.kube_config import (KubeConfigLoader, KubeConfigMerger)

OLD_CONTEXT = "workload-context"
NEW_CONTEXT = "workload-context-v2"
OLD_CLUSTER = "workload-cluster"
NEW_CLUSTER = "workload-cluster-v2"
OLD_USER = "workload-user"
NEW_USER = "workload-user-v2"
OLD_SERVER = "https://cluster-old.example.test"
NEW_SERVER = "https://cluster-new.example.test"
OLD_TOKEN = "old-generation-token"
NEW_TOKEN = "new-generation-token"


def _b64(value):
    return base64.standard_b64encode(value.encode()).decode()


class RotationAuditTest(unittest.TestCase):

    def setUp(self):
        self.tempdir = tempfile.mkdtemp()
        # The exec helper emits a token on demand but blocks until a control
        # file appears, letting us pause a refresh mid-flight.
        self.release_file = os.path.join(self.tempdir, "release")
        self.fail_file = os.path.join(self.tempdir, "fail")
        self.helper = self._write_exec_helper()
        self.old_config_path = os.path.join(
            self.tempdir, "old-kubeconfig.yaml")
        self.new_config_path = os.path.join(
            self.tempdir, "new-kubeconfig.yaml")
        self.audit_log = AuditLog()

    def tearDown(self):
        # Make sure any blocked helper process can always exit.
        self._release()
        for path in (self.old_config_path, self.new_config_path,
                     self.helper, self.release_file, self.fail_file):
            if os.path.exists(path):
                os.remove(path)
        os.rmdir(self.tempdir)

    def _write_exec_helper(self):
        helper = os.path.join(self.tempdir, "credential-helper.py")
        script = (
            "import json, os, sys, time\n"
            "release = sys.argv[1]\n"
            "fail_flag = sys.argv[2]\n"
            "token = sys.argv[3]\n"
            "deadline = time.time() + 10\n"
            "while not os.path.exists(release) and time.time() < deadline:\n"
            "    time.sleep(0.01)\n"
            "if os.path.exists(fail_flag):\n"
            "    sys.stderr.write('credential acquisition failed')\n"
            "    sys.exit(1)\n"
            "print(json.dumps({\n"
            "    'apiVersion': 'client.authentication.k8s.io/v1',\n"
            "    'kind': 'ExecCredential',\n"
            "    'status': {'token': token}\n"
            "}))\n"
        )
        with open(helper, "w") as handle:
            handle.write(script)
        return helper

    def _exec_user(self, name, token):
        return {
            "name": name,
            "user": {
                "exec": {
                    "apiVersion": "client.authentication.k8s.io/v1",
                    "command": sys.executable,
                    "args": [self.helper, self.release_file,
                             self.fail_file, token],
                }
            },
        }

    def _write_configs(self):
        old_config = {
            "apiVersion": "v1",
            "kind": "Config",
            "current-context": OLD_CONTEXT,
            "clusters": [{
                "name": OLD_CLUSTER,
                "cluster": {"server": OLD_SERVER,
                            "certificate-authority-data": _b64("old-ca")},
            }],
            "contexts": [{
                "name": OLD_CONTEXT,
                "context": {"cluster": OLD_CLUSTER, "user": OLD_USER},
            }],
            "users": [self._exec_user(OLD_USER, OLD_TOKEN)],
        }
        # The new file adds the rotated context, cluster and user, but a
        # second context deliberately references the *old* user material.
        # Half of the rotation succeeding therefore must not be treated as the
        # new configuration being usable.
        new_config = {
            "apiVersion": "v1",
            "kind": "Config",
            "current-context": NEW_CONTEXT,
            "clusters": [{
                "name": NEW_CLUSTER,
                "cluster": {"server": NEW_SERVER,
                            "certificate-authority-data": _b64("new-ca")},
            }],
            "contexts": [
                {
                    "name": NEW_CONTEXT,
                    "context": {"cluster": NEW_CLUSTER,
                                "user": NEW_USER},
                },
                {
                    # Cross-references user material defined in the old file.
                    "name": "borrows-old-user",
                    "context": {"cluster": NEW_CLUSTER,
                                "user": OLD_USER},
                },
            ],
            "users": [self._exec_user(NEW_USER, NEW_TOKEN)],
        }
        with open(self.old_config_path, "w") as handle:
            yaml.safe_dump(old_config, handle)
        with open(self.new_config_path, "w") as handle:
            yaml.safe_dump(new_config, handle)

    def _merged_loader(self, context):
        merged = KubeConfigMerger(
            "%s%s%s" % (self.old_config_path, os.pathsep,
                        self.new_config_path))
        return KubeConfigLoader(
            config_dict=merged.config,
            active_context=context,
            audit_log=self.audit_log)

    def _release(self):
        if not os.path.exists(self.release_file):
            open(self.release_file, "w").close()

    def _block(self):
        if os.path.exists(self.release_file):
            os.remove(self.release_file)

    def test_requests_and_late_refresh_failure_are_attributable(self):
        self._write_configs()

        # 1. Load the old configuration and issue a successful request while
        #    the exec helper runs to completion.
        self._release()
        old_loader = self._merged_loader(OLD_CONTEXT)
        old_client_config = Configuration()
        old_loader.load_and_set(old_client_config)

        self.assertEqual(OLD_SERVER, old_client_config.host)
        old_provenance = record_request_for_configuration(
            old_client_config)
        self.assertEqual(OLD_CONTEXT, old_provenance.context)
        self.assertEqual(OLD_USER, old_provenance.user)
        self.assertEqual(1, old_provenance.credential_generation)
        self.assertIn("Bearer %s" % OLD_TOKEN,
                      old_client_config.api_key["BearerToken"])

        # 2. Begin rotating to the new generation. Block the helper so the new
        #    credential acquisition pauses before it returns.  The exec loader
        #    logs and swallows a failed plugin, but the audit failure event is
        #    still emitted; signal completion via an event.
        self._block()
        new_loader = self._merged_loader(NEW_CONTEXT)
        new_client_config = Configuration()
        rotation_done = threading.Event()

        def rotate():
            new_loader.load_and_set(new_client_config)
            rotation_done.set()

        rotation = threading.Thread(target=rotate)
        rotation.start()

        # Wait until the in-flight refresh has been recorded as started.
        deadline = time.time() + 5
        started = self.audit_log.events(EVENT_CREDENTIAL_REFRESH)
        while not started and time.time() < deadline:
            time.sleep(0.01)
            started = self.audit_log.events(EVENT_CREDENTIAL_REFRESH)
        self.assertTrue(started, "expected a credential refresh to start")

        # The start event is frozen against the new selection at decision time.
        # Each loader owns its generation counter, so the new loader's first
        # credential acquisition is generation one.
        start_event = started[-1]
        self.assertEqual(NEW_CONTEXT, start_event.provenance.context)
        self.assertEqual(NEW_USER, start_event.provenance.user)
        self.assertEqual(
            self.new_config_path, start_event.provenance.user_path)
        self.assertEqual(1, start_event.provenance.credential_generation)

        # 3. While the new refresh is still paused, the old request remains
        #    attributable to the configuration it was created with.
        still_old = record_request_for_configuration(old_client_config)
        self.assertEqual(OLD_CONTEXT, still_old.context)
        self.assertEqual(1, still_old.credential_generation)

        # 4. Make the paused acquisition fail, then let it return.
        open(self.fail_file, "w").close()
        self._release()
        self.assertTrue(rotation_done.wait(timeout=5))
        rotation.join(timeout=5)
        self.assertFalse(rotation.is_alive())

        # The failed acquisition left no token configured on the new client.
        self.assertNotIn("BearerToken", new_client_config.api_key)

        # 5. The late failure maps back to the new-context selection captured
        #    when the refresh started, not to the old in-flight request.
        failures = self.audit_log.events(EVENT_CREDENTIAL_REFRESH_FAILED)
        self.assertEqual(1, len(failures))
        failed = failures[0]
        self.assertEqual("failed", failed.status)
        self.assertIn("credential acquisition failed",
                      failed.error)
        self.assertEqual(NEW_CONTEXT, failed.provenance.context)
        self.assertEqual(NEW_USER, failed.provenance.user)
        self.assertEqual(1, failed.provenance.credential_generation)

        # 6. Rotation is retried cleanly on a fresh loader; its request uses
        #    generation one and the new token/server.  Clear the failure flag
        #    only after the failed helper process has fully exited, so the
        #    retry cannot observe a stale flag.
        self.assertTrue(rotation_done.wait(timeout=5))
        rotation.join(timeout=5)
        # Give the helper subprocess a moment to finish after load_and_set.
        time.sleep(0.2)
        os.remove(self.fail_file)
        self._release()
        retry_loader = self._merged_loader(NEW_CONTEXT)
        retry_client_config = Configuration()
        retry_loader.load_and_set(retry_client_config)
        retry_provenance = record_request_for_configuration(
            retry_client_config)

        self.assertEqual(NEW_SERVER, retry_client_config.host)
        self.assertEqual(NEW_CONTEXT, retry_provenance.context)
        self.assertEqual(NEW_USER, retry_provenance.user)
        self.assertEqual(1, retry_provenance.credential_generation)
        self.assertIn("Bearer %s" % NEW_TOKEN,
                      retry_client_config.api_key["BearerToken"])

        # 7. Cross-check requests, diagnostics and provenance as a whole.
        request_contexts = [
            event.provenance.context
            for event in self.audit_log.events(EVENT_REQUEST)]
        self.assertEqual(
            [OLD_CONTEXT, OLD_CONTEXT, NEW_CONTEXT], request_contexts)

        diagnostics = self.audit_log.diagnostics()
        serialized = repr(diagnostics)
        self.assertNotIn(OLD_TOKEN, serialized)
        self.assertNotIn(NEW_TOKEN, serialized)
        self.assertNotIn("old-ca", serialized)
        self.assertNotIn("new-ca", serialized)
        allowed = {"event_id", "event_type", "timestamp", "status", "error",
                   "provenance"}
        allowed_provenance = {"context", "cluster", "user", "config_path",
                              "cluster_path", "user_path", "auth_method",
                              "credential_generation"}
        for record in diagnostics:
            self.assertTrue(set(record).issubset(allowed))
            self.assertTrue(
                set(record["provenance"]).issubset(allowed_provenance))

    def test_context_referencing_foreign_user_records_its_source(self):
        self._write_configs()
        self._release()
        loader = self._merged_loader("borrows-old-user")
        client_config = Configuration()
        loader.load_and_set(client_config)
        provenance = record_request_for_configuration(client_config)

        # The context lives in the new file but its user material is sourced
        # from the old file; both source identifiers must be recorded.
        self.assertEqual("borrows-old-user", provenance.context)
        self.assertEqual(OLD_USER, provenance.user)
        self.assertEqual(self.old_config_path, provenance.user_path)

        selection = self.audit_log.events(EVENT_SELECTION)[-1]
        self.assertEqual(
            self.old_config_path, selection.provenance.user_path)


if __name__ == "__main__":
    unittest.main()
