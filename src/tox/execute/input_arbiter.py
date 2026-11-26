"""Exclusive arbitration for terminal and fixed subprocess input."""

from __future__ import annotations

import logging
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from .request import StdinSource

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

_LOGGER: Final[logging.Logger] = logging.getLogger(__name__)


@dataclass(frozen=True)
class InputResolution:
    """The stdin arrangement granted to one real subprocess."""

    source: StdinSource
    owner: str | None
    stdin_data: bytes | None = None
    stdin_path: Path | None = None
    detach_terminal: bool = False
    exclusive: bool = False


class InputArbiter:
    """Grant terminal inheritance to at most one command at a time.

    The arbiter never reads terminal bytes itself. A grant only decides which file descriptor the operating system
    passes to the resulting subprocess. Fixed inputs are likewise handed directly to that subprocess.
    """

    def __init__(
        self,
        terminal_owners: frozenset[str] | set[str] | tuple[str, ...] | list[str] = (),
        fixed_inputs: dict[str, bytes | Path] | None = None,
        *,
        strict: bool = False,
    ) -> None:
        self._terminal_owners = frozenset(terminal_owners)
        self._fixed_inputs = dict(fixed_inputs or {})
        self.strict = strict
        self._condition = threading.Condition(threading.RLock())
        self._active_owner: str | None = None
        self._active_thread: int | None = None
        self._active_depth = 0
        self.events: list[tuple[str, str]] = []

    @contextmanager
    def authorize(self, owner: str | None, requested: StdinSource) -> Iterator[InputResolution]:
        """Authorize one invocation and hold any terminal lease until it finishes."""
        resolution = self._resolve(owner, requested)
        if not resolution.exclusive or owner is None:
            yield resolution
            return

        thread_id = threading.get_ident()
        with self._condition:
            if self._active_thread == thread_id and self._active_owner != owner:
                msg = f"terminal lease {self._active_owner!r} cannot be replaced by {owner!r} on the same thread"
                raise RuntimeError(msg)
            while self._active_owner is not None and self._active_thread != thread_id:
                self._condition.wait()
            if self._active_thread == thread_id:
                self._active_depth += 1
            else:
                self._active_owner = owner
                self._active_thread = thread_id
                self._active_depth = 1
            self.events.append(("acquire", owner))
        try:
            yield resolution
        finally:
            with self._condition:
                self._active_depth -= 1
                if self._active_depth == 0:
                    self._active_owner = None
                    self._active_thread = None
                    self._condition.notify_all()
                self.events.append(("release", owner))

    def _resolve(self, owner: str | None, requested: StdinSource) -> InputResolution:
        if owner is not None and owner in self._fixed_inputs:
            fixed = self._fixed_inputs[owner]
            data = fixed if isinstance(fixed, bytes) else None
            path = None if isinstance(fixed, bytes) else fixed
            self._record("fixed", owner)
            return InputResolution(
                StdinSource.API,
                owner,
                stdin_data=data,
                stdin_path=path,
                detach_terminal=self.strict,
            )

        if requested is not StdinSource.USER:
            return InputResolution(requested, owner, detach_terminal=self.strict and requested is StdinSource.API)

        if not self.strict:
            return InputResolution(StdinSource.USER, owner)

        if owner is not None and owner in self._terminal_owners:
            self._record("allow", owner)
            return InputResolution(StdinSource.USER, owner, exclusive=True)

        label = owner or "<unidentified-command>"
        self._record("deny", label)
        _LOGGER.warning(
            "blocked terminal input for %s; it is not the explicitly selected command",
            label,
        )
        return InputResolution(StdinSource.OFF, owner, detach_terminal=True)

    def _record(self, event: str, owner: str) -> None:
        with self._condition:
            self.events.append((event, owner))


def owner_name(env_name: str, run_id: str) -> str:
    """Build the stable identity used by explicit input grants."""
    return f"{env_name}:{run_id}"


__all__ = ["InputArbiter", "InputResolution", "owner_name"]
