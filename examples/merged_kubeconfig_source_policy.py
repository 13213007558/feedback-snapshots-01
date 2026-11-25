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

"""Approve kubeconfig files per capability and audit what was used.

A merged kubeconfig is not one trust domain.  A context, the cluster it
describes and the user it authenticates as may come from three different
files.  This example builds two local files:

* ``team-a.yaml`` may describe clusters and authenticate.
* ``shared-clusters.yaml`` may only describe clusters.

A context in ``team-a.yaml`` points at a user named ``team-user`` that is
actually defined in ``shared-clusters.yaml``.  Approving ``team-a.yaml`` for
exec does not let the context run that user's authentication plugin, because
the plugin was not approved through its own file.

Run from the repository root:

    python examples/merged_kubeconfig_source_policy.py
"""

import os
import sys
import tempfile

import yaml

from kubernetes import config
from kubernetes.config import (KubeConfigSourceError, KubeConfigSourcePolicy)


def write_config(directory, name, content):
    path = os.path.join(directory, name)
    with open(path, "w") as stream:
        yaml.safe_dump(content, stream)
    return path


def write_plugin(directory, log_path):
    plugin = os.path.join(directory, "fake-credential-plugin.py")
    with open(plugin, "w") as stream:
        stream.write(
            "#!%s\n"
            "import json\n"
            "import os\n"
            "import sys\n"
            "log = os.environ.get('FAKE_PLUGIN_LOG')\n"
            "if log:\n"
            "    with open(log, 'a') as handle:\n"
            "        handle.write('executed\\n')\n"
            "json.dump({\n"
            "    'apiVersion': 'client.authentication.k8s.io/v1beta1',\n"
            "    'kind': 'ExecCredential',\n"
            "    'status': {'token': 'demo-token'},\n"
            "}, sys.stdout)\n" % sys.executable)
    os.chmod(plugin, 0o755)
    return plugin


def main():
    directory = tempfile.mkdtemp()
    log_path = os.path.join(directory, "plugin.log")
    plugin = write_plugin(directory, log_path)

    team_file = write_config(directory, "team-a.yaml", {
        "clusters": [{
            "name": "cluster-a",
            "cluster": {"server": "https://a.example.test"},
        }],
        "contexts": [{
            "name": "team-context",
            "context": {"cluster": "cluster-a", "user": "team-user"},
        }],
        "current-context": "team-context",
    })
    shared_file = write_config(directory, "shared-clusters.yaml", {
        "users": [{
            "name": "team-user",
            "user": {"exec": {
                "apiVersion": "client.authentication.k8s.io/v1beta1",
                "command": plugin,
                "env": [{"name": "FAKE_PLUGIN_LOG", "value": log_path}],
            }},
        }],
    })
    kubeconfig = os.pathsep.join([team_file, shared_file])

    # --- Read-only approval ------------------------------------------------
    # The shared file may describe clusters but not authenticate or exec.
    read_only = KubeConfigSourcePolicy()
    read_only.approve(team_file, "describe", "authenticate", "exec")
    read_only.approve(shared_file, "describe")

    audit = config.KubeConfigAudit()
    try:
        config.new_client_from_config(
            config_file=kubeconfig, context="team-context",
            source_policy=read_only, audit=audit)
    except KubeConfigSourceError as error:
        record = audit.last_record.to_dict()
        print("denied:", error)
        print("denied source:", record["denied"]["source"])
        print("exec spawned:", record["exec"]["spawned"])
    assert not os.path.exists(log_path), "read-only source ran the plugin"
    print("plugin log exists:", os.path.exists(log_path))

    # --- Fully approved merge ---------------------------------------------
    approved = KubeConfigSourcePolicy()
    approved.approve(team_file, "describe", "authenticate", "exec")
    approved.approve(shared_file, "describe", "authenticate", "exec")

    audit = config.KubeConfigAudit()
    client = config.new_client_from_config(
        config_file=kubeconfig, context="team-context",
        source_policy=approved, audit=audit)
    record = audit.last_record.to_dict()
    print("host:", client.configuration.host)
    print("identity:", record["identity"])
    print("exec spawned:", record["exec"]["spawned"])
    print("cluster source:", record["cluster"]["source_realpath"])
    print("user source:", record["user"]["source_realpath"])


if __name__ == "__main__":
    main()
