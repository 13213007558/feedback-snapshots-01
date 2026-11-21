# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.

from typing import Any

import pytest

from opensearchpy.exceptions import ImproperlyConfigured
from opensearchpy.host_allowlist import HostAllowlist


def test_ip_address_and_network_entries() -> None:
    policy = HostAllowlist(["10.0.0.0/8", "192.0.2.10", "fd00::/8"])

    assert policy.allows("10.20.30.40")
    assert policy.allows("192.0.2.10")
    assert policy.allows("fd00::5")
    assert not policy.allows("192.0.2.11")
    assert not policy.allows("11.0.0.1")
    assert not policy.allows("fe80::1")


def test_hostname_and_wildcard_matching() -> None:
    policy = HostAllowlist(["opensearch.internal", "*.search.internal"])

    assert policy.allows("opensearch.internal")
    assert policy.allows("OPENSEARCH.INTERNAL.")
    assert policy.allows("node-1.search.internal")
    # A wildcard matches subdomains only, not the suffix itself.
    assert not policy.allows("search.internal")
    # Suffix matching must respect the dot boundary.
    assert not policy.allows("evilsearch.internal")
    assert not policy.allows("opensearch.internal.example.com")


def test_empty_and_invalid_entries_are_rejected() -> None:
    with pytest.raises(ImproperlyConfigured):
        HostAllowlist([])
    with pytest.raises(ImproperlyConfigured):
        HostAllowlist([""])
    with pytest.raises(ImproperlyConfigured):
        HostAllowlist(["http://10.0.0.1:9200"])
    with pytest.raises(ImproperlyConfigured):
        HostAllowlist(["10.0.0.0/not-a-mask"])
    with pytest.raises(ImproperlyConfigured):
        HostAllowlist(["*."])


def test_single_string_is_accepted_as_one_entry() -> None:
    policy = HostAllowlist("10.1.2.3")  # type: ignore[arg-type]

    assert policy.allows("10.1.2.3")
    assert not policy.allows("10.1.2.4")


def test_filter_keeps_only_approved_connection_options() -> None:
    policy = HostAllowlist(["10.0.0.0/8"])
    hosts: Any = [
        {"host": "10.1.1.1", "port": 9200},
        {"host": "203.0.113.5", "port": 9200},
        {"port": 9200},
    ]

    assert policy.filter(hosts) == [{"host": "10.1.1.1", "port": 9200}]
