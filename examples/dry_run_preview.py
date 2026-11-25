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

"""Preview a ConfigMap update, then obtain a separate approval to write."""

from kubernetes import client, config
from kubernetes.utils.dry_run import (
    CommitApproval,
    DryRunPermit,
    DryRunSession,
)


def main():
    config.load_kube_config()
    api_client = client.ApiClient()
    session = DryRunSession(api_client)

    resource = "/api/v1/namespaces/default/configmaps/sample"
    body = client.V1ConfigMap(
        api_version="v1",
        kind="ConfigMap",
        metadata=client.V1ObjectMeta(name="sample", namespace="default"),
        data={"mode": "on"},
    )

    # 1. Preview.  The server receives dryRun=All.
    preview = session.send(
        DryRunPermit.preview(resource, "replace", body),
        response_type="V1ConfigMap",
    )
    print("preview:", preview.describe())
    print("sent query:", preview.query_parameters)
    print("sent body:", preview.body)

    # 2. The preview result is evidence for comparison only.  If the
    #    change is edited afterwards, review reports it.
    if not preview.review(body=body).matches:
        print("change no longer matches the preview; preview it again")
        return

    # 3. A separate approval can request the real write.  Its change
    #    digest must match the previewed change.
    approval = CommitApproval.for_preview(
        preview, approver="release-manager", reference="CHG-42")
    commit = session.send(
        DryRunPermit.commit(resource, "replace", body, approval=approval),
        response_type="V1ConfigMap",
    )
    print("committed:", commit.committed)
    print("server executed:", commit.executed)


if __name__ == "__main__":
    main()
