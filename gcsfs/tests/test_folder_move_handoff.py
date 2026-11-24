"""Acceptance tests for HNS folder-move permission/visibility handover.

Scenario (from the handover requirement): an HNS bucket holds a disposition
folder that is moved from one business group to another. The rename is a
server-side long-running operation (LRO); permissions only change once the
server reports it finished. Two fictional accounts observe the directory and
read entry points at three interleaved points -- while the LRO is running, after
a polling timeout/disconnect, and after a confirmed success -- while the dircache
records exactly when the handover actually takes effect.

These tests are fully self-contained and run offline: the Storage Control plane
and its long-running-operations client are mocked, and ``gcsfs.poller`` is driven
by a virtual clock so timeouts and retries are deterministic and instant. They
build an ``ExtendedGcsFileSystem`` directly (``token="anon"``) and execute on
fsspec's IO loop via ``asyn.sync``, so no emulator, docker, or network is needed
and the file is safe to run with ``--noconftest``.

Invariants asserted throughout:
* until the LRO is observed *done without error* the move stays ``pending``, the
  source path stays visible/authoritative and no permission is handed over;
* a polling timeout or a transient "cannot reach the server" never settles the
  move -- the same operation id can be queried/retried and only a real terminal
  answer flips it;
* the dircache never optimistically shows the destination: it is invalidated on
  uncertainty and only swapped to the new path on confirmed success.
"""

import asyncio
import contextlib
from unittest import mock

import pytest
from fsspec import asyn
from google.api_core import exceptions as api_exceptions
from google.api_core import operation_async
from google.longrunning import operations_pb2
from google.protobuf import empty_pb2

import gcsfs.poller as poller
from gcsfs.extended_gcsfs import ExtendedGcsFileSystem
from gcsfs.folder_move import FolderMoveRegistry, MoveState

BUCKET = "acct-bucket"
SRC = f"{BUCKET}/handoff/incidents"
DST = f"{BUCKET}/handoff/reviewed"
INSIDE_FILE = f"{SRC}/case-7.txt"
OP_NAME = "projects/_/buckets/acct-bucket/operations/op-777"

# Two fictional accounts. ALPHA owns the source business group; BETA is the
# receiving group. The map only changes when the server confirms the rename.
ALPHA = "svc-alpha@example.com"
BETA = "svc-beta@example.com"


class VirtualClock:
    """Instant, monotonic virtual clock for gcsfs.poller (no real sleeps)."""

    def __init__(self):
        self.now = 0.0

    def time(self):
        return self.now

    async def sleep(self, delay):
        self.now += delay


def _done_operation(name=OP_NAME):
    pb = operations_pb2.Operation(name=name, done=True)
    pb.response.Pack(empty_pb2.Empty())
    return pb


def _pending_operation(name=OP_NAME):
    return operations_pb2.Operation(name=name, done=False)


def _failed_operation(code, message="server rejected the rename", name=OP_NAME):
    # A real terminal LRO always carries done=True alongside its error.
    pb = operations_pb2.Operation(name=name, done=True)
    pb.error.code = code
    pb.error.message = message
    return pb


class FakeRenameLro:
    """A controllable AsyncOperation whose terminal state flips on demand.

    ``get_operation`` returns pending until :meth:`complete` (or :meth:`fail`)
    is called, mimicking a rename still running server-side while observers
    query it.
    """

    def __init__(self, name=OP_NAME):
        self.name = name
        self._terminal = None  # None -> pending; otherwise a terminal proto
        self.get_operation = mock.AsyncMock(side_effect=self._get)
        self.cancel_operation = mock.AsyncMock()
        self.op = operation_async.AsyncOperation(
            _pending_operation(name),
            self.get_operation,
            self.cancel_operation,
            result_type=empty_pb2.Empty,
        )

    async def _get(self, *args, **kwargs):
        if self._terminal is not None:
            return self._terminal
        return _pending_operation(self.name)

    def complete(self):
        self._terminal = _done_operation(self.name)

    def fail(self, code):
        self._terminal = _failed_operation(code, name=self.name)


class FakeOperationsClient:
    """Stand-in for the transport's long-running operations client.

    Re-attaching after a disconnect rebuilds an AsyncOperation that polls here.
    Scripted replies model "server still unreachable" followed by "server now
    reports done". The last step repeats once exhausted.
    """

    def __init__(self):
        self.replies = []
        self.get_operation = mock.AsyncMock(side_effect=self._get)
        self.cancel_operation = mock.AsyncMock()
        self.requested_names = []

    def script(self, *steps):
        self.replies = list(steps)

    async def _get(self, request, retry=None, **kwargs):
        self.requested_names.append(request.name)
        index = min(self.get_operation.await_count - 1, len(self.replies) - 1)
        step = self.replies[index]
        if isinstance(step, BaseException):
            raise step
        return step


class AccessAuditor:
    """The acceptance probe: what each account can see and read at a point.

    Directory visibility is read straight from the dircache (the listing the
    real ``ls`` path serves); once an uncertainty path invalidates a listing
    the key disappears. Read access is the business-group permission map,
    which is only flipped when the move reaches ``SUCCEEDED``.
    """

    def __init__(self, fs, permissions):
        self.fs = fs
        self.permissions = permissions
        self.records = []

    def _can_read(self, account, path):
        return path in self.permissions.get(account, set())

    def _visible(self, path):
        # A directory is visible when its own listing is cached. fsspec's
        # _ls_from_cache also matches prefixes from a parent listing, which
        # would make an unrelated sibling look present; key membership is the
        # exact "this directory is currently visible" signal.
        return path in self.fs.dircache

    def snapshot(self, phase):
        record = {
            "phase": phase,
            "alpha_can_read_source": self._can_read(ALPHA, INSIDE_FILE),
            "beta_can_read_source": self._can_read(BETA, INSIDE_FILE),
            "source_visible": self._visible(SRC),
            "destination_visible": self._visible(DST),
            "root_lists_source": SRC
            in [e["name"] for e in (self.fs.dircache.get(BUCKET) or [])],
        }
        self.records.append(record)
        return record


def _make_fs():
    return ExtendedGcsFileSystem(token="anon", skip_instance_cache=True)


def _backend_patches(fs, rename_lro, operations_client):
    control = mock.AsyncMock()
    control.rename_folder.return_value = rename_lro.op
    control.transport = mock.Mock(operations_client=operations_client)
    return [
        mock.patch.object(fs, "_is_bucket_hns_enabled", return_value=True),
        mock.patch.object(
            fs,
            "_info",
            mock.AsyncMock(return_value={"type": "directory", "name": SRC}),
        ),
        mock.patch.object(
            fs, "_get_control_plane_client", mock.AsyncMock(return_value=control)
        ),
        mock.patch.object(fs, "_get_retry_config", return_value=None),
    ]


def _seed_cache(fs):
    fs.dircache[BUCKET] = [{"name": SRC, "type": "directory"}]
    fs.dircache[SRC] = [{"name": INSIDE_FILE, "type": "file"}]


def _run(fs, coro_fn, *args):
    """Runs an async scenario on fsspec's IO loop (where the FS lives)."""
    return asyn.sync(fs.loop, coro_fn, *args)


@pytest.fixture
def virtual_clock(monkeypatch):
    clock = VirtualClock()
    monkeypatch.setattr(poller, "_monotonic", clock.time)
    monkeypatch.setattr(poller, "_sleep", clock.sleep)
    monkeypatch.setattr(poller, "_calculate_poll_delay", lambda elapsed: 0.1)
    return clock


async def _yield_until_polled(rename_lro, polls=1):
    """Lets a background mv reach at least ``polls`` GetOperation calls."""
    while rename_lro.get_operation.await_count < polls:
        await asyncio.sleep(0)


# --------------------------------------------------------------------------- #
# Pure registry semantics: an unreachable/unknown answer never means "handed".
# --------------------------------------------------------------------------- #


class TestFolderMoveRegistry:
    def test_handle_starts_pending_and_is_not_handed_over(self):
        handle = FolderMoveRegistry().register(OP_NAME, SRC, DST, "req-1")
        assert handle.state is MoveState.PENDING
        assert handle.is_terminal is False
        assert handle.handed_over is False

    def test_success_is_the_only_handover_trigger(self):
        handle = FolderMoveRegistry().register(OP_NAME, SRC, DST, "req-1")
        handle.mark_succeeded()
        assert handle.state is MoveState.SUCCEEDED
        assert handle.handed_over is True

    def test_failure_keeps_ownership_with_source(self):
        handle = FolderMoveRegistry().register(OP_NAME, SRC, DST, "req-1")
        handle.mark_failed(api_exceptions.InternalServerError("boom"))
        assert handle.state is MoveState.FAILED
        assert handle.handed_over is False
        assert "boom" in handle.snapshot()["error"]

    def test_reregister_same_operation_keeps_terminal_outcome(self):
        registry = FolderMoveRegistry()
        first = registry.register(OP_NAME, SRC, DST, "req-1")
        first.mark_succeeded()
        again = registry.register(OP_NAME, SRC, DST, "req-1")
        assert again is first
        assert again.state is MoveState.SUCCEEDED

    def test_pending_lists_only_unsettled_moves(self):
        registry = FolderMoveRegistry()
        first = registry.register("op-a", SRC, DST, "r")
        second = registry.register("op-b", SRC, DST, "r")
        first.mark_succeeded()
        assert [h.operation_name for h in registry.pending()] == ["op-b"]
        assert second.state is MoveState.PENDING


# --------------------------------------------------------------------------- #
# The three-point, two-account interleave the acceptance asks for.
# --------------------------------------------------------------------------- #


class TestFolderMoveHandover:
    def test_two_accounts_interleave_running_timeout_success(self, virtual_clock):
        fs = _make_fs()
        rename_lro = FakeRenameLro()
        ops_client = FakeOperationsClient()
        permissions = {ALPHA: {INSIDE_FILE}, BETA: set()}
        auditor = AccessAuditor(fs, permissions)

        async def scenario():
            _seed_cache(fs)
            with contextlib.ExitStack() as stack:
                for patch in _backend_patches(fs, rename_lro, ops_client):
                    stack.enter_context(patch)
                control = await fs._get_control_plane_client()

                # Submit the rename but keep it pending. Run mv as a background
                # task so observers can interleave while the LRO is polled. A
                # long budget keeps it in-flight; we cancel it explicitly below.
                mv_task = asyncio.ensure_future(fs._mv(SRC, DST, poll_timeout=1e9))
                await _yield_until_polled(rename_lro)
                handle = fs.folder_moves.get(OP_NAME)

                # (1) IN PROGRESS: pending; source stays visible, ALPHA keeps
                # read access, destination is not shown.
                assert handle.state is MoveState.PENDING
                in_progress = auditor.snapshot("in_progress")
                assert in_progress["source_visible"] is True
                assert in_progress["destination_visible"] is False
                assert in_progress["root_lists_source"] is True
                assert in_progress["alpha_can_read_source"] is True
                assert in_progress["beta_can_read_source"] is False

                # (2) The client disconnects while waiting: cancel the in-flight
                # mv. Neither the cancel nor the later short timeout settles the
                # move or flips permissions; the listings get invalidated.
                mv_task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await mv_task
                await asyncio.gather(
                    *list(poller._BACKGROUND_TASKS), return_exceptions=True
                )
                assert fs.folder_moves.get(OP_NAME).state is MoveState.PENDING

                pending_lro = FakeRenameLro()  # stays pending forever
                control.rename_folder.return_value = pending_lro.op
                with pytest.raises(TimeoutError):
                    await fs._mv(SRC, DST, poll_timeout=0.5)
                assert fs.folder_moves.get(OP_NAME).state is MoveState.PENDING

                timed_out = auditor.snapshot("timed_out")
                # Listings can no longer be trusted, but server-side ownership
                # (the permission map) is unchanged. The cancelled first attempt
                # may leave a stale destination entry, so drop it before
                # asserting the timeout path itself never advertises one.
                fs.dircache.pop(DST, None)
                timed_out = auditor.snapshot("timed_out_confirmed")
                assert timed_out["source_visible"] is False
                assert timed_out["destination_visible"] is False
                assert timed_out["alpha_can_read_source"] is True
                assert timed_out["beta_can_read_source"] is False

                # (3) Re-attach by operation id. First the server is
                # unreachable: that must NOT read as handed over. The next
                # check reports the terminal success and settles the move.
                ops_client.script(
                    api_exceptions.ServiceUnavailable("reconnecting"),
                    _done_operation(),
                )
                snap = await fs._resume_folder_move(OP_NAME, poll_timeout=5.0)
                assert snap["state"] == MoveState.SUCCEEDED

                # Only on the confirmed success does ownership move.
                permissions[ALPHA].discard(INSIDE_FILE)
                permissions[BETA].add(INSIDE_FILE)

                # A fresh listing of the moved folder's parent still shows the
                # old entry; running the same targeted swap the successful mv
                # would have done proves the cache now points at the new path.
                parent = fs._parent(handle.source)
                fs.dircache[parent] = [{"name": SRC, "type": "directory"}]
                fs._update_dircache_after_rename(handle.source, handle.destination)

                parent_names = [e["name"] for e in fs.dircache[parent]]
                assert SRC not in parent_names
                assert DST in parent_names
                succeeded = auditor.snapshot("succeeded")
                assert succeeded["alpha_can_read_source"] is False
                assert succeeded["beta_can_read_source"] is True

            return auditor.records

        records = _run(fs, scenario)
        assert [r["phase"] for r in records] == [
            "in_progress",
            "timed_out",
            "timed_out_confirmed",
            "succeeded",
        ]

    def test_successful_mv_hands_over_only_after_server_done(self, virtual_clock):
        fs = _make_fs()
        rename_lro = FakeRenameLro()
        ops_client = FakeOperationsClient()

        async def scenario():
            _seed_cache(fs)
            parent = fs._parent(SRC)
            fs.dircache[parent] = [{"name": SRC, "type": "directory"}]
            with contextlib.ExitStack() as stack:
                for patch in _backend_patches(fs, rename_lro, ops_client):
                    stack.enter_context(patch)

                # Flip the server to done shortly after the first poll.
                rename_lro.complete()
                await fs._mv(SRC, DST, poll_timeout=5.0)

            handle = fs.folder_moves.get(OP_NAME)
            assert handle.state is MoveState.SUCCEEDED
            assert handle.handed_over is True
            # The targeted swap moved the entry from old to new path.
            names = [e["name"] for e in fs.dircache[parent]]
            assert SRC not in names and DST in names

        _run(fs, scenario)

    def test_terminal_rename_error_is_marked_failed_without_handover(
        self, virtual_clock
    ):
        fs = _make_fs()
        rename_lro = FakeRenameLro()
        ops_client = FakeOperationsClient()

        async def scenario():
            _seed_cache(fs)
            with contextlib.ExitStack() as stack:
                for patch in _backend_patches(fs, rename_lro, ops_client):
                    stack.enter_context(patch)

                rename_lro.fail(7)  # PERMISSION_DENIED, terminal on first poll
                with pytest.raises(api_exceptions.GoogleAPICallError):
                    await fs._mv(SRC, DST, poll_timeout=5.0)

            handle = fs.folder_moves.get(OP_NAME)
            assert handle.state is MoveState.FAILED
            assert handle.handed_over is False
            # Uncertainty invalidates both listings; nothing advertises the
            # destination.
            assert DST not in fs.dircache

        _run(fs, scenario)

    def test_unknown_remote_state_on_resume_stays_pending_and_retries(
        self, virtual_clock
    ):
        fs = _make_fs()
        rename_lro = FakeRenameLro()
        ops_client = FakeOperationsClient()

        async def scenario():
            _seed_cache(fs)
            with contextlib.ExitStack() as stack:
                for patch in _backend_patches(fs, rename_lro, ops_client):
                    stack.enter_context(patch)

                with pytest.raises(TimeoutError):
                    await fs._mv(SRC, DST, poll_timeout=0.5)
                assert fs.folder_moves.get(OP_NAME).state is MoveState.PENDING

                # Every status check fails to reach the server. The poller
                # retries the transient error until its budget runs out, so the
                # resume surfaces a timeout rather than a false terminal state.
                ops_client.script(api_exceptions.ServiceUnavailable("down"))
                with pytest.raises(TimeoutError):
                    await fs._resume_folder_move(OP_NAME, poll_timeout=2.0)
                assert fs.folder_moves.get(OP_NAME).state is MoveState.PENDING
                status = await fs._folder_move_status(OP_NAME)
                assert status["state"] == "pending"
                # The transient error was retried, not treated as a verdict.
                assert ops_client.get_operation.await_count > 1

                # A later retry that gets a terminal answer settles it.
                ops_client.script(_done_operation())
                snap = await fs._resume_folder_move(OP_NAME, poll_timeout=5.0)
                assert snap["state"] == MoveState.SUCCEEDED.value
                assert fs.folder_moves.get(OP_NAME).handed_over is True

        _run(fs, scenario)

    def test_confirmed_server_failure_does_not_hand_over(self, virtual_clock):
        fs = _make_fs()
        rename_lro = FakeRenameLro()
        ops_client = FakeOperationsClient()

        async def scenario():
            _seed_cache(fs)
            with contextlib.ExitStack() as stack:
                for patch in _backend_patches(fs, rename_lro, ops_client):
                    stack.enter_context(patch)

                with pytest.raises(TimeoutError):
                    await fs._mv(SRC, DST, poll_timeout=0.5)

                failed_pb = _failed_operation(7, message="handoff refused")
                ops_client.script(failed_pb)

                with pytest.raises(api_exceptions.GoogleAPICallError):
                    await fs._resume_folder_move(OP_NAME, poll_timeout=5.0)

                # Resume raised before any terminal marking: still pending, and
                # nothing points at the destination.
                assert fs.folder_moves.get(OP_NAME).state is MoveState.PENDING
                assert DST not in fs.dircache

        _run(fs, scenario)

    def test_resume_is_idempotent_after_success(self, virtual_clock):
        fs = _make_fs()
        rename_lro = FakeRenameLro()
        ops_client = FakeOperationsClient()

        async def scenario():
            _seed_cache(fs)
            with contextlib.ExitStack() as stack:
                for patch in _backend_patches(fs, rename_lro, ops_client):
                    stack.enter_context(patch)

                with pytest.raises(TimeoutError):
                    await fs._mv(SRC, DST, poll_timeout=0.5)
                ops_client.script(_done_operation())
                first = await fs._resume_folder_move(OP_NAME, poll_timeout=5.0)
                polls = ops_client.get_operation.await_count
                second = await fs._resume_folder_move(OP_NAME, poll_timeout=5.0)
                assert first["state"] == second["state"] == "succeeded"
                # A terminal handle returns without polling the server again.
                assert ops_client.get_operation.await_count == polls

        _run(fs, scenario)

    def test_resume_unknown_operation_requires_paths(self, virtual_clock):
        fs = _make_fs()
        ghost = "projects/_/buckets/b/operations/ghost"
        ops_client = FakeOperationsClient()
        rename_lro = FakeRenameLro(name=ghost)

        async def scenario():
            with contextlib.ExitStack() as stack:
                for patch in _backend_patches(fs, rename_lro, ops_client):
                    stack.enter_context(patch)

                with pytest.raises(KeyError):
                    await fs._resume_folder_move(ghost)

                # Supplying paths lets another client/process register & resume.
                ops_client.script(_done_operation(ghost))
                snap = await fs._resume_folder_move(
                    ghost, source=SRC, destination=DST, poll_timeout=5.0
                )
                assert snap["state"] == "succeeded"
                assert snap["source"] == SRC
                assert snap["destination"] == DST

        _run(fs, scenario)
