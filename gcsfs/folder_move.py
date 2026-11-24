"""Resumable bookkeeping for Hierarchical Namespace (HNS) folder moves.

Moving a folder between business groups on an HNS bucket is a server-side
long-running operation (LRO). Permission to read the folder only changes once
the server reports the rename finished, so a client that gets back an operation
id and then disconnects, or that gives up waiting after a timeout, must be able
to come back and ask "what is the state of *that* operation?" rather than
guessing from a local failure.

This module is transport-free. It only stores the facts a client needs to
re-attach to an in-flight rename and applies the single rule that matters for
the handover:

* until the LRO is observed ``done`` *without error*, the move is still
  :attr:`MoveState.PENDING`, so the source path stays authoritative and no
  permission or directory-cache handover happens;
* only a terminal success flips the move to :attr:`MoveState.SUCCEEDED`, which
  is the sole trigger for swapping visibility and updating the dircache;
* a terminal failure is :attr:`MoveState.FAILED` and leaves ownership where it
  was.

A status check that cannot reach the server (a timeout or transient error)
records nothing terminal. The caller retries; an unknown answer is never turned
into "handed over".
"""

import enum
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


class MoveState(str, enum.Enum):
    """Lifecycle of a tracked folder move.

    The string values are stable identifiers suitable for logs and the values
    returned by :meth:`FolderMoveHandle.snapshot`.
    """

    #: The rename was submitted and has not yet been observed as terminal.
    PENDING = "pending"
    #: The server reported the rename finished successfully. Ownership has moved.
    SUCCEEDED = "succeeded"
    #: The server reported the rename failed. Ownership stays with the source.
    FAILED = "failed"


@dataclass
class FolderMoveHandle:
    """Everything needed to re-attach to a submitted folder rename.

    The handle outlives the call that submitted the rename. It is keyed by the
    server-side operation name (the "long operation number") and remembers the
    old and new paths so a reconnecting client can interpret the result without
    re-deriving it.

    Attributes:
        operation_name: Server-side LRO name, e.g.
            ``projects/_/buckets/b/operations/op-123``.
        source: Stripped ``bucket/key`` path the folder is moved from.
        destination: Stripped ``bucket/key`` path the folder is moved to.
        request_id: Idempotency token sent on the original RenameFolder call.
        state: Current :class:`MoveState`.
        result: Unpacked operation response once succeeded, else ``None``.
        error: The terminal exception once failed, else ``None``.
    """

    operation_name: str
    source: str
    destination: str
    request_id: str
    state: MoveState = MoveState.PENDING
    result: Any = None
    error: Optional[BaseException] = None
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def snapshot(self) -> Dict[str, Any]:
        """A plain-dict, thread-safe view of the handle for logging/tests."""
        with self._lock:
            return {
                "operation_name": self.operation_name,
                "source": self.source,
                "destination": self.destination,
                "request_id": self.request_id,
                "state": self.state.value,
                "result": self.result,
                "error": repr(self.error) if self.error is not None else None,
            }

    def mark_succeeded(self, result: Any = None) -> None:
        """Records a confirmed server-side success and the handover point."""
        with self._lock:
            self.state = MoveState.SUCCEEDED
            self.result = result
            self.error = None

    def mark_failed(self, error: BaseException) -> None:
        """Records a confirmed server-side failure; ownership does not move."""
        with self._lock:
            self.state = MoveState.FAILED
            self.error = error

    @property
    def is_terminal(self) -> bool:
        """True once the move has a definite success/failure outcome."""
        return self.state in (MoveState.SUCCEEDED, MoveState.FAILED)

    @property
    def handed_over(self) -> bool:
        """True only when the permission/visibility handover may take effect."""
        return self.state is MoveState.SUCCEEDED


class FolderMoveRegistry:
    """Process-local registry of submitted folder moves, keyed by LRO name.

    The registry makes a disconnect or a polling timeout recoverable: the
    operation id returned to the client stays valid and can be looked up later
    to resume waiting. It deliberately never treats an unreachable server as a
    terminal answer -- failed status checks simply leave the handle pending.

    A plain :class:`threading.Lock` guards the dict and each handle; the methods
    are synchronous and cheap (no awaits), so they are safe to call from both
    fsspec's IO loop thread and synchronous wrapper code.
    """

    def __init__(self) -> None:
        self._handles: Dict[str, FolderMoveHandle] = {}
        self._lock = threading.Lock()

    def register(
        self,
        operation_name: str,
        source: str,
        destination: str,
        request_id: str,
    ) -> FolderMoveHandle:
        """Records a freshly submitted rename and returns its handle.

        Re-registering the same ``operation_name`` returns the existing handle
        rather than overwriting it, so a retried submit that resolves to the
        same LRO cannot reset an already-terminal outcome.
        """
        with self._lock:
            existing = self._handles.get(operation_name)
            if existing is not None:
                return existing
            handle = FolderMoveHandle(
                operation_name=operation_name,
                source=source,
                destination=destination,
                request_id=request_id,
            )
            self._handles[operation_name] = handle
            return handle

    def get(self, operation_name: str) -> FolderMoveHandle:
        """Returns the handle for ``operation_name`` or raises ``KeyError``."""
        with self._lock:
            return self._handles[operation_name]

    def __contains__(self, operation_name: object) -> bool:
        with self._lock:
            return operation_name in self._handles

    def pending(self) -> list[FolderMoveHandle]:
        """All handles still awaiting a terminal server answer."""
        with self._lock:
            return [h for h in self._handles.values() if not h.is_terminal]

    def discard(self, operation_name: str) -> None:
        """Drops a handle (e.g. after it has been reconciled by the caller)."""
        with self._lock:
            self._handles.pop(operation_name, None)

    def clear(self) -> None:
        """Removes every tracked handle."""
        with self._lock:
            self._handles.clear()
