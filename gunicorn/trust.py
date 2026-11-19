#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

"""Proxy trust resolved for one listening socket.

A peer address alone cannot say whether the forwarding headers or the PROXY
protocol framing it sends should be believed: the same client can reach a
public listener directly and an internal listener through a load balancer.
Trust is therefore resolved from the listening socket that accepted the
connection.  A listener with no entry of its own uses the global setting.
"""

import functools
import ipaddress
import re


def normalize_bind_key(bind):
    """Canonical form of a bind string, config key or bound address.

    ``unix:/path``, ``unix:///path`` and a bare socket path name the same
    listener; so do ``tcp://host:port``, ``host:port`` and the address
    ``getsockname()`` returns.  Keys in ``*_by_bind`` are normalized the
    same way, so either spelling may be used.
    """
    if isinstance(bind, bytes):
        bind = bind.decode("latin-1")
    if isinstance(bind, int):
        return "fd://%d" % bind
    if isinstance(bind, tuple):
        host, port = bind[0], bind[1]
        host = str(host)
        if ":" in host:
            return "[%s]:%s" % (host, port)
        return "%s:%s" % (host, port)

    value = str(bind).strip()
    if not value:
        return value

    if value.lower().startswith("fd://"):
        return "fd://" + value[5:]

    if value.lower().startswith("unix:"):
        path = re.split(r"unix:(//)?", value, maxsplit=1)[-1]
        return "unix:" + path

    if value.lower().startswith("tcp://"):
        value = value[6:]

    # A bare path (or abstract name) names a UNIX socket, not a host.
    if value.startswith("/") or value.startswith("\x00"):
        return "unix:" + value

    if "[" in value and "]" in value:
        host = value.split("]")[0][1:]
        rest = value.split("]")[1]
        port = rest[1:] if rest.startswith(":") else "8000"
        return "[%s]:%s" % (host, port or "8000")

    if ":" in value:
        host, port = value.rsplit(":", 1)
        if port:
            return "%s:%s" % (host.lower(), port)

    return "%s:8000" % value.lower()


def listener_bind_keys(listener):
    """Every key a ``*_by_bind`` mapping may use for this listener.

    The bind string from the configuration comes first, then the address the
    socket actually bound.  The latter is what an inherited (``fd://`` or
    systemd) socket has to be keyed by, since its original spelling is gone.
    """
    if listener is None:
        return ()

    keys = []
    spec = getattr(listener, "bind_spec", None)
    if isinstance(spec, bytes):
        spec = spec.decode("latin-1")
    if isinstance(spec, str) and spec.strip():
        keys.append(spec)

    try:
        address = listener.getsockname()
    except (AttributeError, OSError, TypeError):
        address = getattr(listener, "cfg_addr", None)
    if isinstance(address, (str, bytes, tuple, int)):
        keys.append(address)

    seen = set()
    unique = []
    for key in keys:
        normalized = normalize_bind_key(key)
        if normalized and normalized not in seen:
            seen.add(normalized)
            unique.append(normalized)
    return tuple(unique)


def _allow_list(value):
    """Normalize an allow list without trusting the type of a partial config."""
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return []


@functools.lru_cache(maxsize=64)
def _networks_cached(allow_list):
    return tuple(ipaddress.ip_network(address)
                 for address in allow_list if address != "*")


def _networks(allow_list):
    return _networks_cached(tuple(allow_list))


def peer_in_allow_list(peer_addr, allow_list, networks):
    """Whether an accepted peer is in an allow list.

    Non-tuple peers come from a UNIX socket and carry no IP address.  They are
    trusted, as they have always been for ``forwarded_allow_ips`` and
    ``proxy_allow_ips``.
    """
    if not isinstance(peer_addr, tuple):
        return True
    if "*" in allow_list:
        return True
    try:
        peer = ipaddress.ip_address(peer_addr[0])
    except (ValueError, TypeError):
        return False
    for network in networks:
        if peer in network:
            return True
    return False


class ListenerTrust:
    """The proxy trust granted to peers of one listening socket."""

    __slots__ = (
        "forwarded_allow_ips", "proxy_allow_ips",
        "_forwarded_networks", "_proxy_networks",
        "forwarded_overridden", "proxy_overridden",
    )

    def __init__(self, forwarded_allow_ips, proxy_allow_ips,
                 forwarded_overridden=False, proxy_overridden=False):
        self.forwarded_allow_ips = _allow_list(forwarded_allow_ips)
        self.proxy_allow_ips = _allow_list(proxy_allow_ips)
        self.forwarded_overridden = forwarded_overridden
        self.proxy_overridden = proxy_overridden
        # Resolution happens once per connection, not once per request.
        self._forwarded_networks = _networks(self.forwarded_allow_ips)
        self._proxy_networks = _networks(self.proxy_allow_ips)

    def trusts_forwarded(self, peer_addr):
        """Whether this peer may set forwarded and secure-scheme headers."""
        return peer_in_allow_list(
            peer_addr, self.forwarded_allow_ips, self._forwarded_networks)

    def trusts_proxy(self, peer_addr):
        """Whether this peer may send PROXY protocol framing."""
        return peer_in_allow_list(
            peer_addr, self.proxy_allow_ips, self._proxy_networks)


def _override(mapping, keys):
    if not isinstance(mapping, dict):
        return None
    for key in keys:
        if key in mapping:
            return mapping[key]
    return None


def resolve(cfg, listener=None):
    """Resolve the trust of ``listener``, or ``None`` when there is none.

    A missing mapping entry falls back to the corresponding global setting.
    An entry that is present but empty (``""`` or ``[]``) is kept: it trusts
    no peer and deliberately does not fall back.
    """
    if listener is None:
        return None

    forwarded_map = getattr(cfg, "forwarded_allow_ips_by_bind", None)
    proxy_map = getattr(cfg, "proxy_allow_ips_by_bind", None)
    if isinstance(forwarded_map, dict) or isinstance(proxy_map, dict):
        keys = listener_bind_keys(listener)
    else:
        keys = ()
    mapped_forwarded = _override(forwarded_map, keys)
    mapped_proxy = _override(proxy_map, keys)

    forwarded = (mapped_forwarded if mapped_forwarded is not None
                 else getattr(cfg, "forwarded_allow_ips", []))
    proxy = (mapped_proxy if mapped_proxy is not None
             else getattr(cfg, "proxy_allow_ips", []))

    return ListenerTrust(
        forwarded, proxy,
        forwarded_overridden=mapped_forwarded is not None,
        proxy_overridden=mapped_proxy is not None,
    )


def resolve_or_default(cfg, listener=None):
    """Like :func:`resolve`, with a trust object built from the global
    settings when there is no listener to key on (tests, embedders)."""
    resolved = resolve(cfg, listener)
    if resolved is not None:
        return resolved
    return ListenerTrust(
        getattr(cfg, "forwarded_allow_ips", []),
        getattr(cfg, "proxy_allow_ips", []),
    )


__all__ = [
    "ListenerTrust", "listener_bind_keys", "normalize_bind_key",
    "peer_in_allow_list", "resolve", "resolve_or_default",
]
