from __future__ import annotations

import os
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Final

import pytest

from tox.execute.input_arbiter import InputArbiter, owner_name
from tox.execute.local_sub_process import LocalSubProcessExecuteInstance
from tox.execute.request import ExecuteRequest, StdinSource
from tox.execute.stream import SyncWrite

_TIMEOUT: Final[float] = 10.0
_OPTIONS: Final[SimpleNamespace] = SimpleNamespace(
    no_capture=False,
    suicide_timeout=0.0,
    interrupt_timeout=0.1,
    terminate_timeout=0.1,
)


def test_owner_name_matches_run_id_identity() -> None:
    assert owner_name("alpha", "commands_post[1]") == "alpha:commands_post[1]"


def test_strict_arbiter_denies_unselected_terminal_input() -> None:
    arbiter = InputArbiter(strict=True, terminal_owners={"alpha:commands[0]"})

    with arbiter.authorize("beta:commands[0]", StdinSource.USER) as grant:
        assert grant.source is StdinSource.OFF
        assert grant.detach_terminal is True

    assert ("deny", "beta:commands[0]") in arbiter.events


def test_strict_arbiter_returns_fixed_bytes_to_real_child_request() -> None:
    arbiter = InputArbiter(strict=True, fixed_inputs={"beta:commands[0]": b"fixed\n"})

    with arbiter.authorize("beta:commands[0]", StdinSource.USER) as grant:
        assert grant.source is StdinSource.API
        assert grant.stdin_data == b"fixed\n"
        assert grant.detach_terminal is True


def test_strict_arbiter_returns_fixed_path(tmp_path: Path) -> None:
    fixed = tmp_path / "input.bin"
    fixed.write_bytes(b"from-file")
    arbiter = InputArbiter(strict=True, fixed_inputs={"beta:commands[0]": fixed})

    with arbiter.authorize("beta:commands[0]", StdinSource.USER) as grant:
        assert grant.stdin_path == fixed
        assert grant.stdin_data is None


def test_non_strict_arbiter_preserves_legacy_terminal_input() -> None:
    arbiter = InputArbiter()

    with arbiter.authorize("any:commands[0]", StdinSource.USER) as grant:
        assert grant.source is StdinSource.USER
        assert grant.detach_terminal is False


def test_terminal_lease_is_exclusive_and_released_after_cancellation() -> None:
    arbiter = InputArbiter(strict=True, terminal_owners={"alpha:commands[0]", "alpha:commands_post[0]"})
    second_entered = threading.Event()
    release_second = threading.Event()

    def takeover() -> None:
        with arbiter.authorize("alpha:commands_post[0]", StdinSource.USER):
            second_entered.set()
            assert release_second.wait(_TIMEOUT)

    with arbiter.authorize("alpha:commands[0]", StdinSource.USER):
        worker = threading.Thread(target=takeover)
        worker.start()
        assert not second_entered.wait(0.1)

    assert second_entered.wait(_TIMEOUT)
    release_second.set()
    worker.join(_TIMEOUT)
    assert not worker.is_alive()
    assert [event for event, owner in arbiter.events if owner.startswith("alpha:")].count("acquire") == 2


def _run_real_subprocess(request: ExecuteRequest) -> int:
    instance = LocalSubProcessExecuteInstance(
        request,
        _OPTIONS,
        SyncWrite("out", None),
        SyncWrite("err", None),
    )
    with instance as status:
        exit_code = status.wait(_TIMEOUT)
    assert exit_code is not None
    return exit_code


def test_fixed_stdin_bytes_are_read_by_real_subprocess(tmp_path: Path) -> None:
    code = "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"
    request = ExecuteRequest(
        cmd=[sys.executable, "-c", code],
        cwd=tmp_path,
        env=os.environ.copy(),
        stdin=StdinSource.API,
        run_id="fixed",
        stdin_data=b"real-child-bytes\n",
    )

    instance = LocalSubProcessExecuteInstance(
        request,
        _OPTIONS,
        SyncWrite("out", None),
        SyncWrite("err", None),
    )
    with instance as status:
        assert status.wait(_TIMEOUT) == 0
        assert bytes(status.out) == b"real-child-bytes\n"


@pytest.mark.skipif(os.name != "posix", reason="POSIX session isolation test")
def test_detached_request_starts_real_child_in_own_session(tmp_path: Path) -> None:
    code = "import os,sys; sys.exit(0 if os.getsid(0) == os.getpid() else 4)"
    request = ExecuteRequest(
        cmd=[sys.executable, "-c", code],
        cwd=tmp_path,
        env=os.environ.copy(),
        stdin=StdinSource.OFF,
        run_id="detached",
        detach_terminal=True,
    )

    assert _run_real_subprocess(request) == 0


def test_execute_request_rejects_two_fixed_input_sources(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="mutually exclusive"):
        ExecuteRequest(
            cmd=[sys.executable, "-c", "pass"],
            cwd=tmp_path,
            env=os.environ.copy(),
            stdin=StdinSource.API,
            run_id="",
            stdin_data=b"x",
            stdin_path=tmp_path / "x",
        )
