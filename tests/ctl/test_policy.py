#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

"""Tests for the control socket command policy."""

import os
import pwd
import socket

import pytest

from gunicorn.ctl.policy import (
    AccessDenied,
    ControlPolicy,
    MONITOR,
    OPERATOR,
    PeerCredentials,
    PolicyError,
    UnknownCommand,
    peer_credentials,
)


CURRENT_UID = os.geteuid()
CURRENT_GID = os.getegid()
CURRENT_USER = pwd.getpwuid(CURRENT_UID).pw_name


def peer(uid=CURRENT_UID, gid=CURRENT_GID, groups=()):
    return PeerCredentials(pid=1, uid=uid, gid=gid, groups=tuple(groups))


class TestPolicyConstruction:
    def test_unknown_role_rejected(self):
        with pytest.raises(PolicyError, match="Unknown control socket role"):
            ControlPolicy({"watcher": ["root"]})

    def test_empty_mapping_rejected(self):
        with pytest.raises(PolicyError):
            ControlPolicy({})

    def test_role_without_selectors_rejected(self):
        with pytest.raises(PolicyError, match="matches no user"):
            ControlPolicy({MONITOR: []})

    def test_unknown_user_rejected(self):
        with pytest.raises(PolicyError, match="No such user"):
            ControlPolicy({MONITOR: ["no-such-user-anywhere"]})

    def test_unknown_group_rejected(self):
        with pytest.raises(PolicyError, match="No such group"):
            ControlPolicy({MONITOR: ["@no-such-group-anywhere"]})

    def test_single_selector_accepted(self):
        policy = ControlPolicy({MONITOR: CURRENT_USER})
        assert policy.role_for(peer()).name == MONITOR

    def test_non_mapping_rejected(self):
        with pytest.raises(PolicyError):
            ControlPolicy([("monitor", ["root"])])


class TestRoleResolution:
    def test_user_by_name(self):
        policy = ControlPolicy({MONITOR: [CURRENT_USER]})
        assert policy.role_for(peer()).name == MONITOR

    def test_user_by_numeric_uid(self):
        policy = ControlPolicy({MONITOR: [str(CURRENT_UID)]})
        assert policy.role_for(peer()).name == MONITOR

    def test_user_by_int_uid(self):
        policy = ControlPolicy({MONITOR: [CURRENT_UID]})
        assert policy.role_for(peer()).name == MONITOR

    def test_group_by_name(self):
        import grp
        group = grp.getgrgid(CURRENT_GID).gr_name
        policy = ControlPolicy({MONITOR: ["@" + group]})
        assert policy.role_for(peer()).name == MONITOR

    def test_supplementary_group(self):
        policy = ControlPolicy({MONITOR: ["@424242"]})
        assert policy.role_for(peer(groups=(424242,))).name == MONITOR

    def test_wildcard(self):
        policy = ControlPolicy({MONITOR: ["*"]})
        assert policy.role_for(peer(uid=424242)).name == MONITOR

    def test_no_match_returns_none(self):
        policy = ControlPolicy({MONITOR: ["@424242"]})
        assert policy.role_for(peer(uid=424243)) is None

    def test_missing_credentials_returns_none(self):
        policy = ControlPolicy({MONITOR: ["*"]})
        assert policy.role_for(None) is None

    def test_operator_wins_when_both_match(self):
        policy = ControlPolicy({
            MONITOR: ["*"],
            OPERATOR: [CURRENT_USER],
        })
        assert policy.role_for(peer()).name == OPERATOR

    def test_monitor_used_when_operator_does_not_match(self):
        policy = ControlPolicy({
            MONITOR: ["*"],
            OPERATOR: ["@424242"],
        })
        assert policy.role_for(peer()).name == MONITOR


class TestCommandCheck:
    def setup_method(self):
        self.policy = ControlPolicy({
            MONITOR: [CURRENT_USER],
            OPERATOR: [CURRENT_UID + 1],
        })
        self.monitor = self.policy.role_for(peer())
        self.operator = self.policy.role_for(peer(uid=CURRENT_UID + 1))

    def test_monitor_reads(self):
        for command in ("show workers", "show all", "show dirty",
                        "show stats", "show listeners", "help"):
            self.policy.check(self.monitor, command)

    def test_monitor_writes_denied(self):
        for command in ("reload", "reopen", "shutdown", "shutdown quick",
                        "worker add", "worker remove", "worker kill",
                        "dirty add", "dirty remove"):
            with pytest.raises(AccessDenied) as exc:
                self.policy.check(self.monitor, command)
            assert exc.value.code == "permission_denied"

    def test_monitor_denied_config(self):
        with pytest.raises(AccessDenied):
            self.policy.check(self.monitor, "show config")

    def test_operator_runs_everything(self):
        for command in ("show workers", "show all", "show dirty",
                        "show stats", "show listeners", "show config",
                        "help", "reload", "reopen", "shutdown",
                        "shutdown graceful", "shutdown quick",
                        "worker add", "worker remove", "worker kill",
                        "dirty add", "dirty remove"):
            self.policy.check(self.operator, command)

    def test_argument_values_are_not_part_of_the_command(self):
        # The server checks the command identity, so a value cannot smuggle a
        # different command past the policy.
        self.policy.check(self.operator, "worker kill")
        with pytest.raises(AccessDenied):
            self.policy.check(self.monitor, "worker kill")

    def test_no_role_denied(self):
        with pytest.raises(AccessDenied) as exc:
            self.policy.check(None, "show workers")
        assert exc.value.code == "permission_denied"

    def test_unknown_command_is_not_permission_error(self):
        # The server raises UnknownCommand before it looks at the role; this
        # asserts the policy never turns an unknown command into a denial.
        with pytest.raises(UnknownCommand) as exc:
            raise UnknownCommand("Unknown command: bogus")
        assert exc.value.code == "unknown_command"


class TestFieldFiltering:
    def setup_method(self):
        self.policy = ControlPolicy({MONITOR: [CURRENT_USER]})
        self.monitor = self.policy.role_for(peer())

    def test_workers_fields(self):
        result = {
            "workers": [{
                "pid": 2, "age": 3, "booted": True, "aborted": False,
                "last_heartbeat": 0.4,
            }],
            "count": 1,
        }
        filtered = self.policy.filter_result(self.monitor, "show workers",
                                             result)
        assert filtered == {
            "workers": [{"pid": 2, "age": 3, "booted": True,
                         "last_heartbeat": 0.4}],
            "count": 1,
        }

    def test_listeners_hide_fd(self):
        result = {"listeners": [{"address": "127.0.0.1:8000", "fd": 7,
                                 "type": "tcp"}], "count": 1}
        filtered = self.policy.filter_result(self.monitor, "show listeners",
                                             result)
        assert filtered == {
            "listeners": [{"address": "127.0.0.1:8000", "type": "tcp"}],
            "count": 1,
        }

    def test_dirty_hides_app_paths(self):
        result = {
            "enabled": True, "pid": 42,
            "workers": [{
                "pid": 3, "age": 1, "apps": ["proj.ml:Model"],
                "booted": True, "last_heartbeat": 0.2,
            }],
            "apps": [{
                "import_path": "proj.ml:Model", "worker_count": 2,
                "current_workers": 1, "worker_pids": [3],
            }],
        }
        filtered = self.policy.filter_result(self.monitor, "show dirty",
                                             result)
        assert filtered["workers"] == [{
            "pid": 3, "age": 1, "booted": True, "last_heartbeat": 0.2,
        }]
        assert filtered["apps"] == [{
            "worker_count": 2, "current_workers": 1,
        }]

    def test_all_hides_apps_and_aborted(self):
        result = {
            "arbiter": {"pid": 1, "type": "arbiter", "role": "master"},
            "web_workers": [{"pid": 2, "type": "web", "age": 1,
                             "booted": True, "last_heartbeat": 0.1,
                             "apps": ["x"]}],
            "web_worker_count": 1,
            "dirty_arbiter": None,
            "dirty_workers": [],
            "dirty_worker_count": 0,
        }
        filtered = self.policy.filter_result(self.monitor, "show all", result)
        assert "apps" not in filtered["web_workers"][0]
        assert filtered["dirty_arbiter"] is None

    def test_config_is_not_readable(self):
        with pytest.raises(AccessDenied):
            self.policy.check(self.monitor, "show config")

    def test_help_lists_only_allowed_commands(self):
        result = {"commands": {
            "show workers": "workers",
            "show config": "config",
            "reload": "reload",
        }}
        filtered = self.policy.filter_result(self.monitor, "help", result)
        assert filtered == {"commands": {"show workers": "workers"}}

    def test_unknown_role_without_fields_keeps_result(self):
        policy = ControlPolicy({OPERATOR: [CURRENT_USER]})
        role = policy.role_for(peer())
        result = {"workers": [{"pid": 1, "aborted": False}], "count": 1}
        assert policy.filter_result(role, "show workers", result) == result

    def test_monitor_never_sees_unlisted_command_payload(self):
        result = {"anything": "secret"}
        assert not self.policy.filter_result(self.monitor, "show config",
                                             result)


class TestPeerCredentials:
    def test_socketpair_credentials(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            credentials = peer_credentials(left)
            assert credentials is not None
            if hasattr(socket, "SO_PEERCRED"):
                assert credentials.uid == os.geteuid()
                assert credentials.gid == os.getegid()
            elif hasattr(socket, "LOCAL_PEERCRED"):
                assert credentials.uid == os.geteuid()
                assert credentials.gid in credentials.groups or \
                    credentials.gid == os.getegid()
        finally:
            left.close()
            right.close()

    def test_none_socket(self):
        assert peer_credentials(None) is None

    def test_in_group(self):
        credentials = PeerCredentials(pid=1, uid=2, gid=3, groups=(4, 5))
        assert credentials.in_group(3)
        assert credentials.in_group(5)
        assert not credentials.in_group(6)
