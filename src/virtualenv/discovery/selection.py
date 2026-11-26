"""Identity of the interpreter approved during discovery, and whether creation still gets that object."""

from __future__ import annotations

__lazy_modules__ = ["dataclasses", "enum", "os"]

import os
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from python_discovery import PythonInfo


class PinState(Enum):
    """How the path that selected an interpreter relates to the object approved during discovery.

    :var CURRENT: the path still names the approved interpreter
    :var MOVED: the path names another object, while the approved one is still at its resolved location
    :var LOST: neither the path nor the resolved location names the approved object

    """

    CURRENT = "current"
    MOVED = "moved"
    LOST = "lost"


@dataclass(frozen=True)
class InterpreterPin:
    """The identity of the interpreter discovery approved, so creation can tell whether it was replaced.

    A file identity of device, inode, size and modification time catches both a path pointed at another file and a
    file rewritten in place.

    :param requested: the absolute path discovery reported for the executable
    :param real: the resolved path of that same executable
    :param device: the device of the approved executable
    :param inode: the inode of the approved executable
    :param size: the size of the approved executable
    :param modified: the modification time of the approved executable, in nanoseconds

    """

    requested: str
    real: str
    device: int
    inode: int
    size: int
    modified: int

    @classmethod
    def of(cls, interpreter: PythonInfo) -> InterpreterPin | None:
        """Record the identity of the interpreter creation is based on.

        :param interpreter: the interpreter discovery selected

        :returns: the pin, ``None`` when the executable cannot be inspected

        """
        requested = interpreter.system_executable or interpreter.executable
        if not requested:
            return None
        try:
            info = os.stat(requested)
        except OSError:
            return None
        absolute = os.path.abspath(requested)
        return cls(
            requested=absolute,
            real=os.path.realpath(absolute),
            device=info.st_dev,
            inode=info.st_ino,
            size=info.st_size,
            modified=info.st_mtime_ns,
        )

    @property
    def identity(self) -> tuple[int, int, int, int]:
        """The file identity that names the approved executable."""
        return self.device, self.inode, self.size, self.modified

    def state(self) -> PinState:
        """Return whether the approved executable is still reachable, and through which path.

        :returns: the state of the pin

        """
        if self._matches(self.requested):
            return PinState.CURRENT
        if self._matches(self.real):
            return PinState.MOVED
        return PinState.LOST

    def _matches(self, path: str) -> bool:
        try:
            info = os.stat(path)
        except OSError:
            return False
        return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) == self.identity


__all__ = [
    "InterpreterPin",
    "PinState",
]
