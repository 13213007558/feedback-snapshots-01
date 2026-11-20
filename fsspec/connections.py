"""Process-local registry of named filesystem connections.

A *connection* (or connection alias) is a name configured in the process which
maps to a filesystem.  Deferred-open objects such as
:class:`fsspec.core.OpenFile` can record the name instead of the filesystem
itself, so pickling them does not copy credentials or long-lived sessions.
The name is resolved again in the worker, using that worker's own
configuration.
"""

from __future__ import annotations

import os
import threading
from collections.abc import Callable, Mapping
from typing import Any

from .config import conf
from .exceptions import ConnectionNotConfigured
from .registry import filesystem
from .spec import AbstractFileSystem

__all__ = [
    "clear_connections",
    "get_connection",
    "register_connection",
    "registered_connections",
    "unregister_connection",
]

_lock = threading.RLock()
_registry: dict[str, dict[str, Any]] = {}
# Pid in which ``_registry`` was last used; a forked child must not inherit
# the parent's configured aliases (and thus its credentials).
_registry_pid = os.getpid()


def _check_fork():
    global _registry_pid
    pid = os.getpid()
    if pid != _registry_pid:
        _registry.clear()
        _registry_pid = pid


def _validate_name(name):
    if not isinstance(name, str) or not name:
        raise ValueError("Connection name must be a non-empty string")
    return name


def register_connection(name, fs=None, protocol=None, replace=True, **storage_options):
    """Register a named connection in the current process.

    Parameters
    ----------
    name: str
        Alias to record in deferred-open objects and to look up when they are
        restored.
    fs: filesystem instance, callable or None
        A filesystem instance to reuse, or a zero-argument callable returning a
        filesystem.  When omitted, ``protocol`` and ``storage_options`` describe
        how to create the filesystem on lookup.
    protocol: str or None
        Filesystem protocol used when ``fs`` is not given.
    replace: bool
        Whether re-registering an existing name replaces it (default True).
        Pass False to protect an existing connection.
    **storage_options:
        Passed to the protocol's filesystem constructor.

    Notes
    -----
    The registry is local to the process.  Registering a connection does not
    make it available to other processes; each worker must configure the
    aliases it accepts.
    """
    _validate_name(name)
    _check_fork()
    if fs is not None and (protocol is not None or storage_options):
        raise ValueError("Provide either fs or protocol/storage_options, not both")
    if fs is None and protocol is None:
        raise ValueError("Provide fs or protocol for the connection")

    entry = {"fs": fs, "protocol": protocol, "storage_options": dict(storage_options)}
    with _lock:
        if name in _registry and not replace:
            raise ValueError(f"Connection {name!r} is already registered")
        _registry[name] = entry
    if fs is not None and not _is_factory(fs):
        _mark_connection(fs, name)


def unregister_connection(name):
    """Remove a registered connection.

    Returns
    -------
    bool
        Whether an entry was removed.  Connections supplied only through
        ``fsspec.config.conf["connections"]`` are not affected.
    """
    _validate_name(name)
    with _lock:
        _check_fork()
        entry = _registry.pop(name, None)
    if entry is not None:
        fs = entry.get("fs")
        if fs is not None and not _is_factory(fs):
            _unmark_connection(fs, name)
    return entry is not None


def clear_connections():
    """Remove all programmatically registered connections (mainly for tests)."""
    with _lock:
        entries = list(_registry.items())
        _registry.clear()
        globals()["_registry_pid"] = os.getpid()
    for name, entry in entries:
        fs = entry.get("fs")
        if fs is not None and not _is_factory(fs):
            _unmark_connection(fs, name)


def _config_entry(name):
    connections = conf.get("connections")
    if not isinstance(connections, Mapping):
        return None
    entry = connections.get(name)
    if entry is None:
        return None
    if isinstance(entry, str):
        return {"protocol": entry}
    if isinstance(entry, AbstractFileSystem) or (
        callable(entry) and not isinstance(entry, Mapping)
    ):
        return {"fs": entry}
    if not isinstance(entry, Mapping):
        raise ValueError(
            f"Connection {name!r} must be a mapping, filesystem or protocol name"
        )
    return dict(entry)


def _is_factory(obj):
    return isinstance(obj, Callable) and not isinstance(obj, AbstractFileSystem)


def _mark_connection(fs, name):
    """Record that ``fs`` is reachable under ``name`` in this process."""
    names = getattr(fs, "_connection_names", None)
    if names is None:
        names = set()
        fs._connection_names = names
    names.add(name)
    # A filesystem shared by several names keeps the first alias for plain
    # instance pickling, so the choice remains stable across re-registration.
    # Deferred-open objects carry their own alias explicitly.
    if getattr(fs, "_connection_name", None) is None:
        fs._connection_name = name


def _unmark_connection(fs, name):
    """Forget an alias when it is removed from the registry."""
    names = getattr(fs, "_connection_names", None)
    if not names:
        return
    names.discard(name)
    if getattr(fs, "_connection_name", None) == name:
        if names:
            fs._connection_name = sorted(names)[0]
        else:
            fs.__dict__.pop("_connection_name", None)
            fs.__dict__.pop("_connection_names", None)


def _materialize(name, entry):
    if entry.get("fs") is not None:
        fs = entry["fs"]
        if _is_factory(fs):
            fs = fs()
    else:
        protocol = entry.get("protocol")
        if not protocol:
            raise ValueError(f"Connection {name!r} does not define a protocol")
        options = dict(entry.get("storage_options") or {})
        # Also accept constructor options directly in the connection mapping,
        # which is convenient for small JSON/INI configuration files.
        options.update(
            {
                k: v
                for k, v in entry.items()
                if k not in {"fs", "protocol", "storage_options"}
            }
        )
        fs = filesystem(protocol, **options)
    # Mark the instance so that pickling it (and file objects which refer to
    # it) can record the alias rather than the constructor arguments, which
    # may contain credentials.
    _mark_connection(fs, name)
    return fs


def get_connection(name):
    """Return the filesystem configured under ``name`` in this process.

    Raises
    ------
    ConnectionNotConfigured
        If neither the registry nor ``fsspec.config.conf["connections"]``
        defines the name.
    """
    _validate_name(name)
    with _lock:
        _check_fork()
        entry = _registry.get(name)
    if entry is None:
        entry = _config_entry(name)
    if entry is None:
        raise ConnectionNotConfigured(
            f"Connection {name!r} is not configured in this process; "
            "register it with fsspec.register_connection() or add it to "
            "fsspec.config.conf['connections']"
        )
    return _materialize(name, entry)


def registered_connections():
    """Return the sorted names available in this process."""
    with _lock:
        _check_fork()
        names = set(_registry)
    configured = conf.get("connections")
    if isinstance(configured, Mapping):
        names.update(configured)
    return tuple(sorted(names))


def _connection_fs(name):
    """Resolver used when pickling a filesystem obtained from a connection.

    Only the name travels in the payload; the worker resolves it against its
    own configuration.
    """
    return get_connection(name)
