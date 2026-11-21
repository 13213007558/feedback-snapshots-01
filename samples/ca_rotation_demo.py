# SPDX-License-Identifier: Apache-2.0
#
# Simple end-to-end demonstration of a CA rotation without restarting the
# search service: the live connection pool is swapped atomically, new
# requests visibly use the new generation, and requests already delegated to
# the old pool finish there.
#
# Run with:  python samples/ca_rotation_demo.py

import json
import ssl
import threading
import time

from opensearchpy import (
    ConnectionPolicy,
    ConnectionPolicyError,
    OpenSearch,
    Transport,
)
from opensearchpy.connection import Connection


def tagged_context(name):
    """A local certificate context carrying a human-readable identity."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.name = name
    return context


class FakeSearchConnection(Connection):
    """Pretends to be an HTTPS connection that records its policy generation."""

    def __init__(self, **kwargs):
        self.context = kwargs.get("ssl_context")
        self.identity = kwargs.get("identity")
        self.block = kwargs.pop("block", False)
        self.started = threading.Event()
        self.finish = threading.Event()
        self.closed = False
        super().__init__(**kwargs)

    def perform_request(self, method, url, *args, **kwargs):
        if self.block:
            self.started.set()
            self.finish.wait(10)
            time.sleep(0.2)  # make the overlap observable
        body = {
            "connection": self.identity,
            "generation": self.generation,
            "ca_context": getattr(self.context, "name", None),
        }
        return 200, {"content-type": "application/json"}, json.dumps(body)

    def close(self):
        self.closed = True


def main():
    client = OpenSearch(
        hosts=[{"host": "search.internal", "port": 9200, "identity": "node-a"}],
        connection_class=FakeSearchConnection,
        transport_class=Transport,
        use_ssl=True,
        randomize_hosts=False,
    )
    transport = client.transport

    print("original pool:", transport.connection_pool)
    print("  request ->", client.search(index="logs", body={"query": {"match_all": {}}}))

    # A request that is already delegated to the original pool.
    old_connection = transport.connection_pool.connections[0]
    old_connection.block = True
    in_flight = []

    def delegated_request():
        in_flight.append(client.info())

    worker = threading.Thread(target=delegated_request)
    worker.start()
    old_connection.started.wait(5)

    # Rotate to the company CA in place.
    new_pool = transport.reload_connection_policy(
        ConnectionPolicy(
            hosts=[{"host": "search.internal", "port": 9200, "identity": "node-b"}],
            generation="company-ca-2026",
            label="company-ca-2026",
            options={"use_ssl": True, "ssl_context": tagged_context("company-ca-2026")},
        )
    )
    print("\nafter successful switch:", new_pool)
    print("  request ->", client.search(index="logs", body={"query": {"match_all": {}}}))
    print("  old connection closed while delegated request runs?", old_connection.closed)

    old_connection.finish.set()
    worker.join(5)
    print("  delegated request ->", in_flight[0])

    # A policy that cannot be loaded leaves the live pool untouched.
    try:
        transport.reload_connection_policy(
            ConnectionPolicy(
                hosts=[{"host": "search.internal", "port": 9200}],
                generation="broken",
                options={"verify_certs": True, "ca_certs": "/missing/company-ca.pem"},
            )
        )
    except ConnectionPolicyError as e:
        print("\nrejected policy:", e)
    print("  still serving from:", transport.generation)
    print("  request ->", client.search(index="logs", body={"query": {"match_all": {}}}))
    print("  old connection closed now?", old_connection.closed)


if __name__ == "__main__":
    main()
