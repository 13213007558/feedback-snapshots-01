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

"""Run a restricted and an ordinary call on one shared client, offline.

This example replaces the urllib3 pool with a recorder, so it needs no
cluster. It prints the Impersonate-* headers and page tokens of every wire
request and shows that the ordinary calls never inherit the restricted
identity, and that pagination keeps the identity that was approved for the
first page.

    python -m examples.impersonation_identity
"""

import json

import urllib3

from kubernetes import client
from kubernetes.utils.impersonation import ImpersonationConfig


NAMESPACE_LIST = {"apiVersion": "v1", "kind": "NamespaceList", "items": []}


class RecordingPool:
    """Records every request instead of sending it."""

    def __init__(self):
        self.requests = []
        self.responses = []

    def queue(self, body):
        if isinstance(body, dict):
            body = json.dumps(body).encode()
        self.responses.append(body)

    def request(self, method, url, **kwargs):
        self.requests.append((method, url, kwargs.get("headers", {})))
        return urllib3.HTTPResponse(
            body=self.responses.pop(0), status=200,
            headers={"Content-Type": "application/json"},
            preload_content=False,
        )


def impersonation_headers(headers):
    values = {}
    for name, value in headers.items():
        lowered = name.lower()
        if lowered.startswith("impersonate-"):
            values.setdefault(name, []).append(value)
    return values


def main():
    configuration = client.Configuration(
        host="http://api.example.test", proxy="", no_proxy="")
    api_client = client.ApiClient(configuration)
    pool = RecordingPool()
    api_client.rest_client.pool_manager = pool

    api = client.CoreV1Api(api_client)

    # Page 1 and page 2 of an approved, impersonated list call.
    pool.queue(dict(NAMESPACE_LIST, metadata={"continue": "page-2"}))
    pool.queue(dict(NAMESPACE_LIST, metadata={}))
    claim = api_client.bind_impersonation(ImpersonationConfig(
        user="auditor", groups=["restricted"]))
    with claim:
        first = api.list_namespace(limit=1)
    with claim:
        api.list_namespace(_continue=first.metadata._continue, limit=1)

    # An ordinary call in between must not inherit that identity.
    pool.queue(dict(NAMESPACE_LIST, metadata={}))
    api.list_namespace()

    for method, url, headers in pool.requests:
        print(method, url)
        print("  headers:", impersonation_headers(headers))


if __name__ == "__main__":
    main()
