#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

"""
Dirty Capability Policy

Every dirty app declares the actions it exposes to callers. The dirty
arbiter checks a request against that declaration before it is queued for a
worker, so a request for an action an app does not expose never reaches the
worker pool.

The declaration comes from the ``capabilities`` attribute of the dirty app
class. The ``dirty_capabilities`` setting can override it per app, which is
what makes the policy reloadable: the main arbiter rebuilds the policy from
the reloaded configuration and sends the new snapshot to the dirty arbiter.
"""

import socket
import time

from .app import get_app_capabilities_attribute, parse_dirty_app_spec
from .errors import DirtyError, DirtyProtocolError
from .protocol import DirtyProtocol, make_policy_message


def normalize_capabilities(value):
    """
    Normalize a capability declaration.

    ``None`` means the app does not restrict its public actions (the
    historical behaviour). An empty iterable means it exposes nothing. A
    ``"*"`` entry means the same as ``None``.

    Raises:
        TypeError: the declaration is not a string or an iterable of strings
        ValueError: an entry is not a string
    """
    if value is None:
        return None

    if isinstance(value, str):
        value = [value]
    elif isinstance(value, (bytes, bytearray)):
        raise TypeError("capabilities must be an iterable of strings")

    try:
        entries = list(value)
    except TypeError:
        raise TypeError("capabilities must be an iterable of strings") from None

    capabilities = set()
    for entry in entries:
        if not isinstance(entry, str):
            raise ValueError(
                f"capability names must be strings, got {type(entry).__name__}"
            )
        entry = entry.strip()
        if not entry:
            continue
        if entry == "*":
            return None
        capabilities.add(entry)

    return frozenset(capabilities)


def resolve_capabilities(import_path, overrides=None, log=None):
    """Resolve the capability declaration for one app import path."""
    if overrides and import_path in overrides:
        declared = overrides[import_path]
    else:
        try:
            declared = get_app_capabilities_attribute(import_path)
        except Exception as e:  # the app class may not be importable yet
            if log is not None:
                log.warning(
                    "Could not read capabilities attribute from %s: %s",
                    import_path, e
                )
            declared = None

    try:
        return normalize_capabilities(declared)
    except (TypeError, ValueError) as e:
        if log is not None:
            log.warning("Invalid capabilities for %s: %s", import_path, e)
        # Fail closed: a broken declaration must not widen the public scope.
        return frozenset()


class CapabilityPolicy:
    """
    Immutable snapshot of the public capabilities of the registered apps.

    ``apps`` maps an app import path to a frozenset of exposed actions, or
    to ``None`` when the app does not restrict its public actions. An app
    missing from the snapshot is not part of the registered dirty app set;
    it is allowed through so the existing "no workers for this app" path
    still answers it.
    """

    __slots__ = ("_apps",)

    def __init__(self, apps=None):
        normalized = {}
        if apps and isinstance(apps, dict):
            for app_path, capabilities in apps.items():
                if not isinstance(app_path, str):
                    continue
                normalized[app_path] = normalize_capabilities(capabilities)
        self._apps = normalized

    @classmethod
    def allow_all(cls):
        """Return a policy that does not restrict any app."""
        return cls()

    def allows(self, app_path, action):
        """Return whether ``action`` may be invoked on ``app_path``."""
        if app_path not in self._apps:
            return True
        capabilities = self._apps[app_path]
        if capabilities is None:
            return True
        return action in capabilities

    def capabilities_for(self, app_path):
        """Return the declared set for an app, or None when unrestricted."""
        return self._apps.get(app_path)

    def to_dict(self):
        """Return a wire-friendly snapshot (app path -> list or None)."""
        return {
            app_path: None if capabilities is None else sorted(capabilities)
            for app_path, capabilities in self._apps.items()
        }

    def __len__(self):
        return len(self._apps)


def build_capability_policy(cfg, log=None):
    """
    Build a policy from the configured dirty apps.

    The config override wins over the class attribute, matching how the
    ``workers`` attribute can be overridden with the ``:N`` spec suffix.
    """
    apps = getattr(cfg, "dirty_apps", None) or []
    if not isinstance(apps, (list, tuple)):
        apps = []
    overrides = getattr(cfg, "dirty_capabilities", None)
    if not isinstance(overrides, dict):
        overrides = {}

    policy = {}
    for spec in apps:
        try:
            import_path, _ = parse_dirty_app_spec(spec)
        except DirtyError as e:
            if log is not None:
                log.warning("Ignoring invalid dirty app spec %s: %s", spec, e)
            continue
        policy[import_path] = resolve_capabilities(import_path, overrides, log)

    return CapabilityPolicy(policy)


def send_capability_policy(socket_path, policy, timeout=5.0):
    """
    Send a policy snapshot to a running dirty arbiter and return its reply.

    The call is synchronous and bounded by ``timeout`` so it can be used
    from the main arbiter's signal loop. The dirty arbiter replaces its
    snapshot with one assignment, so requests that already passed the check
    keep running while later requests see the new policy.
    """
    if not isinstance(policy, CapabilityPolicy):
        policy = CapabilityPolicy(policy)

    request_id = time.time_ns() & 0xFFFFFFFFFFFFFFFF
    message = make_policy_message(request_id, policy.to_dict())

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(socket_path)
        DirtyProtocol.write_message(sock, message)
        response = DirtyProtocol.read_message(sock)
    finally:
        sock.close()

    if response.get("type") == DirtyProtocol.MSG_TYPE_ERROR:
        raise DirtyError.from_dict(response.get("error", {}))
    if response.get("type") != DirtyProtocol.MSG_TYPE_RESPONSE:
        raise DirtyProtocolError(
            f"Unexpected reply to capability policy update: {response.get('type')}"
        )
    return response.get("result") or {}
