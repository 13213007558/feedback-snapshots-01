#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.

import os
from unittest import mock

import pytest

from gunicorn.config import Config
from gunicorn.envfilter import (
    filtered_environ, is_allowed, strip_worker_environ)


@pytest.mark.parametrize("name,allowlist,denylist,expected", [
    # empty rules pass everything through
    ("DB_PASSWORD", [], [], True),
    # denylist exact name and glob
    ("DB_PASSWORD", [], ["DB_PASSWORD"], False),
    ("DB_PASSWORD", [], ["*PASSWORD*"], False),
    ("DB_PASSWORD", [], ["*KEY*"], True),
    # non-empty allowlist filters everything not matching
    ("APP_NAME", ["APP_*"], [], True),
    ("PATH", ["APP_*"], [], False),
    # exact names work without glob characters
    ("PATH", ["PATH"], [], True),
    # denylist always wins
    ("APP_KEY", ["APP_*"], ["*KEY*"], False),
    ("APP_NAME", ["APP_*"], ["*KEY*"], True),
    # matching is case sensitive
    ("db_password", [], ["*PASSWORD*"], True),
    ("app_name", ["APP_*"], [], False),
])
def test_is_allowed(name, allowlist, denylist, expected):
    assert is_allowed(name, allowlist, denylist) is expected


def test_filtered_environ_returns_filtered_copy():
    environ = {
        "APP_NAME": "demo",
        "APP_SECRET": "credential",
        "PATH": "/usr/bin",
    }
    result = filtered_environ([], ["*SECRET*"], environ)
    assert result == {"APP_NAME": "demo", "PATH": "/usr/bin"}
    # the original mapping is untouched
    assert environ["APP_SECRET"] == "credential"


def test_filtered_environ_defaults_to_process_environ(monkeypatch):
    monkeypatch.setenv("APP_NAME", "demo")
    monkeypatch.setenv("DEPLOY_SECRET", "credential")
    result = filtered_environ([], ["*SECRET*"])
    assert "APP_NAME" in result
    assert "DEPLOY_SECRET" not in result


def test_strip_worker_environ_removes_and_reports():
    environ = {
        "APP_NAME": "demo",
        "DEPLOY_SECRET": "credential",
        "API_TOKEN": "token",
    }

    class Cfg:
        worker_env_allowlist = []
        worker_env_denylist = ["*SECRET*", "*TOKEN*"]

    removed = strip_worker_environ(Cfg(), environ)
    assert removed == ["API_TOKEN", "DEPLOY_SECRET"]
    assert "DEPLOY_SECRET" not in environ
    assert "API_TOKEN" not in environ
    assert environ["APP_NAME"] == "demo"


def test_strip_worker_environ_idempotent():
    environ = {"DEPLOY_SECRET": "credential"}

    class Cfg:
        worker_env_allowlist = []
        worker_env_denylist = ["*SECRET*"]

    assert strip_worker_environ(Cfg(), environ) == ["DEPLOY_SECRET"]
    assert strip_worker_environ(Cfg(), environ) == []


def test_settings_validate_to_string_lists():
    cfg = Config()
    cfg.set("worker_env_denylist", ["*SECRET*"])
    cfg.set("worker_env_allowlist", "APP_*")
    assert cfg.worker_env_denylist == ["*SECRET*"]
    assert cfg.worker_env_allowlist == ["APP_*"]


def test_worker_init_strips_raw_env_after_it_is_reapplied(monkeypatch):
    """Worker.init_process re-applies raw_env in the child; the filter that
    runs right after it must remove a forbidden variable again."""
    from gunicorn.workers import base as worker_base

    monkeypatch.setenv("APP_NAME", "demo")
    monkeypatch.setenv("DEPLOY_SECRET", "credential")

    class Cfg:
        env = {"DEPLOY_SECRET": "credential"}
        worker_env_allowlist = []
        worker_env_denylist = ["*SECRET*"]
        uid = os.geteuid()
        gid = os.getegid()
        initgroups = False
        max_requests = 0
        max_requests_jitter = 0
        reload = False

    worker = worker_base.Worker.__new__(worker_base.Worker)
    worker.cfg = Cfg()
    worker.sockets = []
    worker.tmp = mock.Mock()
    worker.log = mock.Mock()
    worker.reloader = None
    worker.booted = False

    def fail_after_filter():
        # stop init_process once the environment filter has run, before it
        # reaches signal setup and the application load
        raise SystemExit(0)

    monkeypatch.setattr(worker_base.util, "set_owner_process",
                        lambda *a, **kw: None)
    monkeypatch.setattr(worker_base.util, "seed", lambda: None)
    monkeypatch.setattr(worker_base.util, "set_non_blocking", lambda fd: None)
    monkeypatch.setattr(worker_base.util, "close_on_exec", lambda fd: None)
    monkeypatch.setattr(worker, "init_signals", lambda: None)
    monkeypatch.setattr(worker, "load_wsgi", fail_after_filter)

    with pytest.raises(SystemExit):
        worker.init_process()

    assert os.environ["APP_NAME"] == "demo"
    assert "DEPLOY_SECRET" not in os.environ
