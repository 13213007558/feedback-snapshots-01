# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.

import ipaddress
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from .exceptions import ImproperlyConfigured

IpAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IpNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def _strip_brackets(host: str) -> str:
    host = host.strip()
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


def _normalize_host(host: str) -> str:
    """Normalize a host for comparison without resolving DNS names."""
    host = _strip_brackets(host).strip().lower()
    if len(host) > 1 and host.endswith("."):
        host = host[:-1]
    return host


def _parse_ip(value: str) -> Optional[IpAddress]:
    try:
        return ipaddress.ip_address(_strip_brackets(value))
    except ValueError:
        return None


class HostAllowlist:
    """
    Network access policy for hosts returned by node discovery.

    Entries may be:

    * an IP address, for example ``10.1.2.3`` or ``fd00::1``
    * a network in CIDR notation, for example ``10.0.0.0/8`` or ``fd00::/8``
    * an exact hostname, for example ``opensearch.internal``
    * a wildcard suffix, for example ``*.search.internal``. A wildcard only
      matches subdomains below the suffix, not the suffix itself.

    Matching is purely lexical; hostnames are never resolved to IP addresses,
    so a lookup cannot be used to reach a network outside the allowlist.
    Entries are matched against the host part of a connection only, not its
    port or URL scheme.
    """

    def __init__(self, allowed_hosts: Iterable[str]) -> None:
        if isinstance(allowed_hosts, str):
            allowed_hosts = [allowed_hosts]

        hosts: List[str] = []
        networks: List[IpNetwork] = []
        suffixes: List[str] = []

        for raw in allowed_hosts:
            if not isinstance(raw, str):
                raise ImproperlyConfigured(
                    "allowed_hosts entries must be strings, got {!r}".format(raw)
                )
            entry = _normalize_host(raw)
            if not entry:
                raise ImproperlyConfigured("allowed_hosts entries must not be empty")
            if "://" in entry:
                raise ImproperlyConfigured(
                    "allowed_hosts entries must be hosts or networks, not URLs: {!r}".format(
                        raw
                    )
                )

            if "/" in entry:
                try:
                    networks.append(ipaddress.ip_network(entry, strict=False))
                except ValueError:
                    raise ImproperlyConfigured(
                        "Invalid network in allowed_hosts: {!r}".format(raw)
                    ) from None
                continue

            address = _parse_ip(entry)
            if address is not None:
                hosts.append(str(address))
                continue

            if entry.startswith("*"):
                suffix = entry[1:]
                if not suffix.startswith(".") or len(suffix) < 2:
                    raise ImproperlyConfigured(
                        "Invalid wildcard in allowed_hosts: {!r}".format(raw)
                    )
                suffixes.append(suffix)
                continue

            if ":" in entry:
                raise ImproperlyConfigured(
                    "Invalid address in allowed_hosts: {!r}".format(raw)
                )
            hosts.append(entry)

        if not hosts and not networks and not suffixes:
            raise ImproperlyConfigured("allowed_hosts must contain at least one entry")

        self._hosts: Tuple[str, ...] = tuple(hosts)
        self._networks: Tuple[IpNetwork, ...] = tuple(networks)
        self._suffixes: Tuple[str, ...] = tuple(suffixes)

    def allows(self, host: Optional[str]) -> bool:
        """Return whether ``host`` is inside the approved network area."""
        if not host or not isinstance(host, str):
            return False

        normalized = _normalize_host(host)
        if not normalized:
            return False

        if normalized in self._hosts:
            return True

        address = _parse_ip(normalized)
        if address is not None:
            return any(
                address.version == network.version and address in network
                for network in self._networks
            )

        return any(normalized.endswith(suffix) for suffix in self._suffixes)

    def filter(self, hosts: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Return the connection option dictionaries approved by this policy."""
        return [host for host in hosts if self.allows(host.get("host"))]

    def __repr__(self) -> str:
        return "<{}: hosts={!r} networks={!r} suffixes={!r}>".format(
            type(self).__name__,
            self._hosts,
            tuple(str(network) for network in self._networks),
            self._suffixes,
        )


__all__ = ["HostAllowlist"]
