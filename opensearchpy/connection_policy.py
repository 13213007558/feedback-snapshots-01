# SPDX-License-Identifier: Apache-2.0
#
# The OpenSearch Contributors require contributions made to
# this file be licensed under the Apache-2.0 license or a
# compatible open source license.
#
# Modifications Copyright OpenSearch Contributors. See
# GitHub history for details.


import os
import ssl
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple, Type, Union

from .exceptions import ImproperlyConfigured

Generation = Union[int, str]

_TLS_OPTION_KEYS = frozenset(
    {
        "ca_certs",
        "client_cert",
        "client_key",
        "ssl_context",
        "verify_certs",
        "ssl_show_warn",
        "ssl_assert_hostname",
        "ssl_assert_fingerprint",
        "ssl_version",
    }
)

# Keys that describe the policy itself.  Everything else in a policy mapping
# is forwarded to the connection class.
POLICY_FIELDS = frozenset(
    {
        "hosts",
        "generation",
        "connection_class",
        "connection_pool_class",
        "label",
        "options",
    }
)


class ConnectionPolicy:
    """A complete, validated description of how connections are built.

    A policy is deliberately self contained: it carries the hosts, the
    connection classes and every keyword argument (for example
    ``ssl_context`` and ``ca_certs``) that is needed to construct a fresh
    generation of connections.  :meth:`~opensearchpy.Transport.reload_connection_policy`
    builds and validates a new pool from a policy *before* making it visible,
    which is what makes a CA rotation atomic from the application's point of
    view.

    ``generation`` is an application visible identifier for the policy.  It
    can be any non-empty string or integer.  When omitted the transport
    allocates a monotonically increasing integer for the policy.
    """

    def __init__(
        self,
        hosts: Any = None,
        generation: Optional[Generation] = None,
        connection_class: Optional[Type[Any]] = None,
        connection_pool_class: Optional[Type[Any]] = None,
        label: Optional[str] = None,
        options: Optional[Mapping[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        self.hosts: Optional[Sequence[Mapping[str, Any]]] = (
            None if hosts is None else self._coerce_hosts(hosts)
        )
        self.generation = generation
        self.connection_class = connection_class
        self.connection_pool_class = connection_pool_class
        self.label = label or (str(generation) if generation is not None else None)

        merged: Dict[str, Any] = dict(options or {})
        merged.update(kwargs)
        self.options: Dict[str, Any] = merged

    @staticmethod
    def _coerce_hosts(hosts: Any) -> Tuple[Mapping[str, Any], ...]:
        if isinstance(hosts, (str, bytes, Mapping)):
            hosts = [hosts]

        normalized = []
        for host in hosts:
            if isinstance(host, str):
                # Import lazily to avoid a client <-> transport import cycle.
                from .client.utils import _normalize_hosts

                normalized.append(_normalize_hosts(host)[0])
            elif isinstance(host, Mapping):
                normalized.append(dict(host))
            else:
                raise ImproperlyConfigured(
                    f"Invalid host entry in connection policy: {host!r}"
                )

        if not normalized:
            raise ImproperlyConfigured(
                "A connection policy must define at least one host."
            )
        return tuple(normalized)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "ConnectionPolicy":
        data = dict(value)
        nested_options = data.pop("options", None)
        known = {key: data.pop(key) for key in list(data) if key in POLICY_FIELDS}
        # Anything else is treated as a connection keyword, exactly like the
        # keyword arguments accepted by ``OpenSearch(...)``.
        if nested_options:
            merged = dict(nested_options)
            merged.update(data)
            data = merged
        return cls(options=data, **known)

    def with_generation(self, generation: Generation) -> "ConnectionPolicy":
        return ConnectionPolicy(
            hosts=self.hosts,
            generation=generation,
            connection_class=self.connection_class,
            connection_pool_class=self.connection_pool_class,
            label=self.label,
            options=self.options,
        )

    def validate(self, base: Optional[Mapping[str, Any]] = None) -> None:
        """Validate the policy without touching the live connection pool.

        Only checks that are unambiguous are performed here.  File and
        certificate validation happens naturally while the replacement
        connections are being constructed; if any of it fails the old pool is
        never replaced.
        """
        if not self.hosts:
            raise ImproperlyConfigured(
                "A connection policy must define at least one host."
            )
        if self.generation is not None and not (
            isinstance(self.generation, str) and self.generation
            or isinstance(self.generation, int)
        ):
            raise ImproperlyConfigured(
                "Connection policy generation must be a non-empty string or an integer."
            )

        effective = self.connection_kwargs(base)
        ssl_context = effective.get("ssl_context")
        if ssl_context is not None and not isinstance(ssl_context, ssl.SSLContext):
            raise ImproperlyConfigured(
                "Connection policy 'ssl_context' must be an ssl.SSLContext instance."
            )

        if effective.get("verify_certs"):
            for name in ("ca_certs", "client_cert", "client_key"):
                path = effective.get(name)
                if path is None:
                    continue
                try:
                    path = os.fspath(path)
                except TypeError:
                    raise ImproperlyConfigured(
                        f"Connection policy '{name}' must be a filesystem path."
                    )
                if not os.path.exists(path):
                    raise ImproperlyConfigured(
                        f"Connection policy '{name}' does not exist: {path}"
                    )

    def connection_kwargs(self, base: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """Combine transport-wide options with this policy's options.

        If the policy supplies any TLS option it owns the whole TLS
        configuration: stale CA paths/client certificates from the previous
        generation are dropped rather than silently retained.
        """
        kwargs: Dict[str, Any] = dict(base or {})
        if _TLS_OPTION_KEYS.intersection(self.options):
            for key in _TLS_OPTION_KEYS:
                kwargs.pop(key, None)
        kwargs.update(self.options)
        return kwargs

    def __repr__(self) -> str:
        return (
            f"<{type(self).__name__} generation={self.generation!r} "
            f"label={self.label!r} hosts={len(self.hosts or ())}>"
        )


__all__ = ["ConnectionPolicy", "Generation", "POLICY_FIELDS"]
