#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

"""
Control Socket Command Policy

The control socket is opened to clients by file permissions. That lets an
operator grant access to a socket without saying what the holder may do, so a
process that only needs to watch workers also gets reload and shutdown.

Enabling ``control_socket_policy`` adds a per-connection command check. The
Unix peer credentials (uid, primary gid and supplementary groups) select a
role; each role lists command patterns it may run and, for reads, the response
fields it may see. A client with no role, or no matching pattern, gets
``permission_denied`` before the command is executed. An unknown command is
still reported as ``unknown_command``, so a reader can tell "not allowed" from
"does not exist" without guessing.

The policy is off by default: without ``control_socket_policy`` the file mode
is the only check, as before.
"""

import fnmatch
import grp
import os
import pwd
import socket
import struct
from dataclasses import dataclass, field


# The role names match the two clients the control socket is usually shared
# with: a monitor that only reads, and an operator that may manage workers.
MONITOR = "monitor"
OPERATOR = "operator"

# Everything an operator may run. The list is explicit so a new command has to
# be added here before an operator can use it, instead of becoming reachable
# the moment its handler lands.
OPERATOR_COMMANDS = (
    "show workers",
    "show all",
    "show dirty",
    "show stats",
    "show listeners",
    "show config",
    "help",
    "reload",
    "reopen",
    "shutdown",
    "shutdown graceful",
    "shutdown quick",
    "worker add",
    "worker remove",
    "worker kill",
    "dirty add",
    "dirty remove",
)

# A monitor reads liveness only. It cannot see the configuration or the paths
# of loaded apps, and cannot change anything.
MONITOR_COMMANDS = (
    "show workers",
    "show all",
    "show dirty",
    "show stats",
    "show listeners",
    "help",
)

# Fields a monitor may read from each reply. A tuple lists the keys kept in
# each worker or listener entry; None keeps the whole value. Anything not
# listed is removed before the response leaves the arbiter, so a field added
# to a handler later does not become visible to monitors by accident.
MONITOR_FIELDS = {
    "show workers": {
        "workers": ("pid", "age", "booted", "last_heartbeat"),
        "count": None,
    },
    "show all": {
        "arbiter": ("pid", "type", "role"),
        "web_workers": ("pid", "type", "age", "booted", "last_heartbeat"),
        "web_worker_count": None,
        "dirty_arbiter": ("pid", "type", "role"),
        "dirty_workers": ("pid", "type", "age", "booted", "last_heartbeat"),
        "dirty_worker_count": None,
    },
    "show dirty": {
        "enabled": None,
        "pid": None,
        "workers": ("pid", "age", "booted", "last_heartbeat"),
        "apps": ("worker_count", "current_workers"),
    },
    "show stats": {
        "uptime": None,
        "pid": None,
        "workers_current": None,
        "workers_target": None,
        "workers_spawned": None,
        "workers_killed": None,
        "reloads": None,
    },
    "show listeners": {
        "listeners": ("address", "type"),
        "count": None,
    },
    # help is filtered against the role's own command patterns.
    "help": None,
}


class PolicyError(Exception):
    """A requested policy is not valid."""


class AccessDenied(Exception):
    """The peer's role may not run this command."""

    code = "permission_denied"


class UnknownCommand(Exception):
    """The command does not exist, whatever the peer's role."""

    code = "unknown_command"


@dataclass
class Role:
    """What one role may run and see."""

    name: str
    commands: tuple
    fields: dict = field(default_factory=dict)
    restrict_fields: bool = False
    privilege: int = 0

    def allows(self, command):
        """Return True when ``command`` matches one of the role's patterns."""
        return any(fnmatch.fnmatchcase(command, pattern)
                   for pattern in self.commands)


def _build_roles():
    monitor = Role(
        name=MONITOR,
        commands=MONITOR_COMMANDS,
        fields=dict(MONITOR_FIELDS),
        restrict_fields=True,
        privilege=0,
    )
    operator = Role(name=OPERATOR, commands=OPERATOR_COMMANDS, privilege=1)
    return {role.name: role for role in (monitor, operator)}


ROLE_DEFINITIONS = _build_roles()


class ControlPolicy:
    """Resolve a peer to a role and check commands against it.

    ``roles`` is the mapping from role name to a list of user or group
    selectors, as read from ``control_socket_policy``. A selector is a user
    name, a group name (prefixed with ``@``), a numeric uid, or ``*``. When
    several roles match, the most privileged one applies, so a process that
    is both a monitor and an operator keeps the operator rights and the order
    of the setting does not change the result.
    """

    def __init__(self, roles, role_definitions=None):
        if not isinstance(roles, dict) or not roles:
            raise PolicyError(
                "control_socket_policy must map a role to a list of users or "
                "groups, for example {'monitor': ['@monitor']}")
        definitions = role_definitions or ROLE_DEFINITIONS
        self._assignments = []
        for name, selectors in roles.items():
            if name not in definitions:
                raise PolicyError(
                    "Unknown control socket role %r; use one of: %s"
                    % (name, ", ".join(sorted(definitions))))
            cleaned = self._normalise_selectors(name, selectors)
            self._assignments.append((definitions[name], cleaned))
        self._assignments.sort(key=lambda item: item[0].privilege,
                               reverse=True)

    @staticmethod
    def _normalise_selectors(name, selectors):
        if isinstance(selectors, (str, int)):
            selectors = [selectors]
        if not isinstance(selectors, (list, tuple)):
            raise PolicyError("Role %r must list users or groups" % name)
        cleaned = []
        for selector in selectors:
            if isinstance(selector, int):
                cleaned.append(("uid", selector))
                continue
            selector = str(selector).strip()
            if not selector:
                continue
            if selector == "*":
                cleaned.append(("any", None))
            elif selector.startswith("@"):
                cleaned.append(("gid", _lookup_gid(selector[1:])))
            elif selector.lstrip("-").isdigit():
                cleaned.append(("uid", int(selector)))
            else:
                cleaned.append(("uid", _lookup_uid(selector)))
        if not cleaned:
            raise PolicyError("Role %r matches no user or group" % name)
        return cleaned

    def role_for(self, credentials):
        """Return the role for a peer, or None when it matches no role."""
        if credentials is None:
            return None
        for role, selectors in self._assignments:
            for kind, value in selectors:
                if kind == "any":
                    return role
                if kind == "uid" and credentials.uid == value:
                    return role
                if kind == "gid" and credentials.in_group(value):
                    return role
        return None

    def check(self, role, command):
        """Raise AccessDenied when ``role`` may not run ``command``."""
        if role is None:
            raise AccessDenied(
                "No control socket role is configured for this user")
        if not role.allows(command):
            raise AccessDenied(
                "Role %r may not run %r" % (role.name, command))

    def filter_result(self, role, command, result):  # pylint: disable=too-many-return-statements
        """Trim a handler reply to the fields ``role`` may read.

        A role without a field rule for the command (operator) keeps the whole
        reply. A monitor gets only the fields listed for that command.
        """
        if role is None:
            return {}
        if not role.restrict_fields:
            return result
        if command == "help" or command.startswith("help "):
            return _filter_help(role, result)
        if command not in role.fields:
            return {}
        rule = role.fields[command]
        if rule is None:
            return result
        if not isinstance(result, dict):
            return result
        filtered = {}
        for key, allowed in rule.items():
            if key not in result:
                continue
            value = result[key]
            if allowed is None:
                filtered[key] = value
            elif isinstance(value, list):
                filtered[key] = [_filter_item(item, allowed) for item in value]
            elif isinstance(value, dict):
                filtered[key] = _filter_item(value, allowed)
            else:
                filtered[key] = value
        return filtered


def _filter_item(item, allowed):
    if not isinstance(item, dict):
        return item
    return {key: value for key, value in item.items() if key in allowed}


def _filter_help(role, result):
    if not isinstance(result, dict):
        return {}
    commands = result.get("commands", {})
    return {
        "commands": {
            command: description
            for command, description in commands.items()
            if role.allows(command)
        }
    }


def _lookup_uid(value):
    if str(value).lstrip("-").isdigit():
        return int(value)
    try:
        return pwd.getpwnam(str(value)).pw_uid
    except KeyError:
        raise PolicyError("No such user: %r" % value) from None


def _lookup_gid(value):
    if str(value).lstrip("-").isdigit():
        return int(value)
    try:
        return grp.getgrnam(str(value)).gr_gid
    except KeyError:
        raise PolicyError("No such group: %r" % value) from None


@dataclass(frozen=True)
class PeerCredentials:
    """Unix peer credentials of one control connection."""

    pid: int
    uid: int
    gid: int
    groups: tuple = ()

    def in_group(self, gid):
        return gid == self.gid or gid in self.groups


def peer_credentials(sock):  # pylint: disable=too-many-return-statements
    """Read the peer credentials of a connected Unix socket.

    Supports Linux ``SO_PEERCRED`` and the BSD/macOS ``LOCAL_PEERCRED``. The
    supplementary groups are looked up from the local user database and are
    only used for group selectors; a failed lookup leaves the list empty.
    """
    if sock is None:
        return None
    if hasattr(socket, "SO_PEERCRED"):
        try:
            data = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                   struct.calcsize("3i"))
            pid, uid, gid = struct.unpack("3i", data)
        except OSError:
            return None
        groups = _lookup_groups(uid, gid)
        return PeerCredentials(pid=pid, uid=uid, gid=gid, groups=groups)
    if not hasattr(socket, "LOCAL_PEERCRED"):
        return None
    try:
        # struct xucred: version (u_int), uid (uid_t), ngroups (short),
        # padding, then groups[] at offset 12.
        data = sock.getsockopt(0, socket.LOCAL_PEERCRED,
                               struct.calcsize("IIH"))
    except OSError:
        return None
    _version, uid, ngroups = struct.unpack("IIH", data)
    try:
        data = sock.getsockopt(0, socket.LOCAL_PEERCRED,
                               struct.calcsize("3I%uI" % ngroups))
    except OSError:
        return None
    groups = struct.unpack("%uI" % ngroups, data[12:12 + 4 * ngroups])
    # A peer with no recorded group must not match the root group by
    # accident, so use an impossible gid instead of 0.
    gid = groups[0] if groups else -1
    return PeerCredentials(pid=0, uid=uid, gid=gid,
                           groups=_lookup_groups(uid, gid))


def _lookup_groups(uid, gid):
    try:
        entry = pwd.getpwuid(uid)
    except KeyError:
        return ()
    try:
        return tuple(os.getgrouplist(entry.pw_name, gid))
    except (AttributeError, OSError):
        return ()
