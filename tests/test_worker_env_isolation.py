#
# This file is part of gunicorn released under the MIT license.
# See the NOTICE for more information.
"""End-to-end checks of the worker environment rules with real forked
processes, but without sockets or a running HTTP application."""

import json
import os
import signal
import time
from unittest import mock

import gunicorn.arbiter
import gunicorn.app.base

# Variables planted for the tests; the prefix keeps them unambiguous against
# the environment pytest itself runs with.
SECRET_KEY = "TESTFACTOR_DEPLOY_SECRET"
PUBLIC_KEY = "TESTFACTOR_APP_NAME"
RELOAD_PUBLIC_KEY = "TESTFACTOR_APP_REGION"
EXTRA_SECRET_KEY = "TESTFACTOR_ROTATED_TOKEN"
ALL_TEST_KEYS = (SECRET_KEY, PUBLIC_KEY, RELOAD_PUBLIC_KEY, EXTRA_SECRET_KEY)


class SnapshotWorker:
    """Fake worker: snapshot os.environ at application init time, then either
    exit or stay alive until SIGTERM like a worker serving requests."""

    snapshot_dir = None
    hold = False

    def __init__(self, age, ppid, sockets, app, timeout, cfg, log):
        self.age = age
        self.pid = None
        self.cfg = cfg
        self.log = log
        self.sockets = sockets
        self.tmp = mock.Mock()
        self.booted = False
        self.aborted = False

    def init_process(self):
        # this is the application initialization point: every worker signal
        # handler is still the inherited master default here
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        snapshot = dict(os.environ)
        path = os.path.join(self.snapshot_dir, "gen%s.json" % self.age)
        with open(path, "w") as handle:
            json.dump(snapshot, handle)
            handle.flush()
            os.fsync(handle.fileno())
        if not self.hold:
            os._exit(0)
        # emulate a long-lived worker: leave only when SIGTERM arrives
        while True:
            time.sleep(0.05)

    def run(self):
        raise NotImplementedError()


class FirstBootApp(gunicorn.app.base.BaseApplication):
    denylist = ["TESTFACTOR_DEPLOY_SECRET"]

    def init(self, parser, opts, args):
        pass

    def load(self):
        return lambda environ, start_response: None

    def load_config(self):
        self.cfg.set("workers", 1)
        self.cfg.set("worker_class", SnapshotWorker)
        self.cfg.set("worker_env_denylist", self.denylist)


class ReloadApp(FirstBootApp):
    denylist = [
        "TESTFACTOR_DEPLOY_SECRET",
        "TESTFACTOR_ROTATED_TOKEN",
    ]


class RawEnvApp(FirstBootApp):
    def load_config(self):
        super().load_config()
        # a credential handed to gunicorn itself through raw_env
        self.cfg.set("raw_env", ["TESTFACTOR_DEPLOY_SECRET=from-raw-env"])


def wait_for_snapshot(path, timeout=10.0):
    deadline = time.monotonic() + timeout
    while not os.path.exists(path):
        if time.monotonic() > deadline:
            raise AssertionError("worker snapshot never appeared: %s" % path)
        time.sleep(0.02)
    with open(path) as handle:
        return json.load(handle)


def reap_pid(pid):
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        try:
            return os.waitpid(pid, 0)
        except ChildProcessError:
            return None
        except InterruptedError:
            continue
    raise AssertionError("worker pid %s did not exit" % pid)


@mock.patch("gunicorn.sock.close_sockets")
@mock.patch("gunicorn.sock.create_sockets", return_value=[])
def test_first_boot_strips_secrets_before_worker_app_init(create_sockets,
                                                          close_sockets,
                                                          tmp_path):
    os.environ[SECRET_KEY] = "master-only-credential"
    os.environ[PUBLIC_KEY] = "visible-to-workers"
    SnapshotWorker.snapshot_dir = str(tmp_path)
    SnapshotWorker.hold = False
    try:
        app = FirstBootApp()

        arbiter = gunicorn.arbiter.Arbiter(app)
        # master initialization (Arbiter.setup) runs with the credential in
        # place, so the master's own initialization is unaffected
        assert os.environ[SECRET_KEY] == "master-only-credential"
        assert os.environ[PUBLIC_KEY] == "visible-to-workers"

        arbiter.pidfile = None
        arbiter.start()
        arbiter.manage_workers()
        try:
            # once the master has booted, the secret is gone from its
            # environment before the first worker fork
            assert SECRET_KEY not in os.environ
            assert os.environ[PUBLIC_KEY] == "visible-to-workers"

            worker_pid, _ = next(iter(arbiter.WORKERS.items()))
            reap_pid(worker_pid)
            snapshot = wait_for_snapshot(str(tmp_path / "gen1.json"))

            # the forked worker never saw the secret, while normal
            # configuration is still inherited
            assert SECRET_KEY not in snapshot
            assert snapshot[PUBLIC_KEY] == "visible-to-workers"
        finally:
            arbiter.stop()
    finally:
        for key in ALL_TEST_KEYS:
            os.environ.pop(key, None)


@mock.patch("gunicorn.sock.close_sockets")
@mock.patch("gunicorn.sock.create_sockets", return_value=[])
def test_reload_gives_each_worker_generation_its_approved_env(
        create_sockets, close_sockets, tmp_path):
    os.environ[SECRET_KEY] = "gen0-secret"
    os.environ[PUBLIC_KEY] = "shared-config"
    os.environ[RELOAD_PUBLIC_KEY] = "region-a"
    SnapshotWorker.snapshot_dir = str(tmp_path)
    SnapshotWorker.hold = True
    try:
        app = FirstBootApp()

        arbiter = gunicorn.arbiter.Arbiter(app)
        arbiter.pidfile = None
        arbiter.start()
        arbiter.manage_workers()
        try:
            old_worker = next(iter(arbiter.WORKERS.values()))
            old_pid = old_worker.pid
            gen0 = wait_for_snapshot(str(tmp_path / "gen1.json"))

            # generation 0 (still serving) keeps the config it was approved
            # for: the shared value, none of the secret
            assert gen0[PUBLIC_KEY] == "shared-config"
            assert gen0[RELOAD_PUBLIC_KEY] == "region-a"
            assert SECRET_KEY not in gen0

            # the master reloads with changed rules and changed public config;
            # the long-lived generation 0 worker is untouched until it is
            # retired at the end of the reload
            os.environ[RELOAD_PUBLIC_KEY] = "region-b"
            os.environ[EXTRA_SECRET_KEY] = "rotated-secret"
            reload_app = ReloadApp()
            arbiter.app = reload_app
            SnapshotWorker.hold = False
            arbiter.reload()

            # generation 0 was terminated gracefully after the new worker
            # booted, and its frozen snapshot still shows its own generation
            reap_pid(old_pid)
            assert gen0[RELOAD_PUBLIC_KEY] == "region-a"
            assert EXTRA_SECRET_KEY not in gen0

            # the generation 1 worker snapshots and exits on its own; it is
            # already reaped by the time reload() returns, so reap any pid
            # still registered before reading its snapshot from disk
            for pid in list(arbiter.WORKERS):
                reap_pid(pid)
            gen1 = wait_for_snapshot(str(tmp_path / "gen2.json"))

            # generation 1 reads the new public config and neither secret,
            # old or newly introduced
            assert gen1[PUBLIC_KEY] == "shared-config"
            assert gen1[RELOAD_PUBLIC_KEY] == "region-b"
            assert SECRET_KEY not in gen1
            assert EXTRA_SECRET_KEY not in gen1
        finally:
            arbiter.stop()
    finally:
        for key in ALL_TEST_KEYS:
            os.environ.pop(key, None)


@mock.patch("gunicorn.sock.close_sockets")
@mock.patch("gunicorn.sock.create_sockets", return_value=[])
def test_raw_env_secret_is_stripped_inside_worker(create_sockets,
                                                  close_sockets,
                                                  tmp_path):
    os.environ.pop(SECRET_KEY, None)
    os.environ[PUBLIC_KEY] = "visible-to-workers"
    SnapshotWorker.snapshot_dir = str(tmp_path)
    SnapshotWorker.hold = False
    try:
        arbiter = gunicorn.arbiter.Arbiter(RawEnvApp())
        arbiter.pidfile = None
        arbiter.start()
        arbiter.manage_workers()
        try:
            worker_pid, _ = next(iter(arbiter.WORKERS.items()))
            reap_pid(worker_pid)
            snapshot = wait_for_snapshot(str(tmp_path / "gen1.json"))

            # raw_env re-applies the variable inside the worker after the
            # master stripped its own copy; the worker-side filter removes it
            # again before the application is loaded
            assert SECRET_KEY not in snapshot
            assert snapshot[PUBLIC_KEY] == "visible-to-workers"
        finally:
            arbiter.stop()
    finally:
        for key in ALL_TEST_KEYS:
            os.environ.pop(key, None)
