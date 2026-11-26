"""Errors."""

from __future__ import annotations


class InterpreterReplacedError(RuntimeError):
    """The interpreter approved during discovery is no longer available, so creation cannot continue.

    :param requested: the path the selected interpreter was found at
    :param approved: the resolved path of the approved executable, which no longer names it

    """

    def __init__(self, requested: str, approved: str) -> None:
        self.requested = requested
        self.approved = approved
        super().__init__(
            f"the interpreter selected at {requested} was replaced after discovery, and the approved executable "
            f"{approved} is no longer there; select the interpreter again to approve the one now installed"
        )


class ProcessCallFailedError(RuntimeError):
    """Failed a process call.

    :param code: the exit code of the process
    :param out: the standard output of the process
    :param err: the standard error of the process
    :param cmd: the command line that was run

    """

    def __init__(self, code: int, out: str, err: str, cmd: list[str]) -> None:
        super().__init__(code, out, err, cmd)
        self.code = code
        self.out = out
        self.err = err
        self.cmd = cmd


__all__ = [
    "InterpreterReplacedError",
    "ProcessCallFailedError",
]
