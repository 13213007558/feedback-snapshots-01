"""Audit subscriptions that resume after an outage but stop at a withdrawal."""

from __future__ import annotations

from typing import Any, Generic, Mapping, cast

from pymongo import _csot
from pymongo.audit_shared import (
    AuditBatch,
    AuditResumePoint,
    AuditSubscriptionBase,
    AuditTrail,
)
from pymongo.change_stream_shared import _resumable
from pymongo.errors import ConnectionFailure, CursorNotFound, OperationFailure
from pymongo.typings import _DocumentType

_IS_SYNC = True


class AuditCursor:
    """A cursor returned by an audit subscription opener.

    Local change stream doubles can subclass this class and implement
    :meth:`next_batch`. Each cursor carries the command that created it so the
    audit trail can record the request that actually reached the opener.
    """

    def __init__(self, request: Mapping[str, Any]) -> None:
        self._request = dict(request)

    @property
    def request(self) -> Mapping[str, Any]:
        """The command issued to obtain this cursor."""
        return dict(self._request)

    def next_batch(self) -> AuditBatch:
        """Return the next batch of change events."""
        raise NotImplementedError

    def close(self) -> None:
        """Close the server cursor."""
        raise NotImplementedError


class AuditSubscription(AuditSubscriptionBase, Generic[_DocumentType]):
    """A change stream subscription behind an :class:`AuditTrail`.

    The subscription delivers events in order and resumes from its last
    acknowledged :class:`~pymongo.audit_shared.AuditResumePoint` after a
    temporary disconnection. Every resume and every buffered event is
    authorized against the trail before it is issued or delivered.

    The `opener` callable receives the current resume point and must return an
    :class:`AuditCursor`. Supplying an opener makes the state machine
    testable with local change stream doubles without a running MongoDB.
    """

    def __init__(
        self,
        scope: str | None,
        trail: AuditTrail,
        opener: Any,
        resume_point: AuditResumePoint | None = None,
    ) -> None:
        self._issued_request: Mapping[str, Any] | None = None
        self._timeout: float | None = None
        super().__init__(scope, trail, opener, resume_point)

    def _initialize(self) -> None:
        """Open the subscription, refusing a withdrawn starting point."""
        self._authorize(self._resume_point, is_resume=False)
        cursor = self._opener(self._resume_point)
        self._install(cursor, is_resume=False)

    def _install(self, cursor: AuditCursor, *, is_resume: bool) -> None:
        """Adopt an opened cursor and record the command that produced it."""
        self._cursor = cursor
        self._issued_request = cursor.request
        self._pending_error = None
        self._record_request(cursor.request, is_resume=is_resume)

    def _resume(self) -> None:
        """Authorize and issue a resume request."""
        self._authorize(self._resume_point, is_resume=True, error=self._pending_error)
        request = self._issued_request or {}
        try:
            cursor = self._opener(self._resume_point)
        except (ConnectionFailure, CursorNotFound) as exc:
            self._disconnected(request, exc)
            raise
        except OperationFailure as exc:
            if not _resumable(exc):
                self._closed = True
                raise
            self._disconnected(request, exc)
            raise
        self._install(cursor, is_resume=True)

    def _fetch(self) -> None:
        """Fetch and buffer one batch, or park the cursor after an outage."""
        cursor = self._cursor
        assert cursor is not None
        try:
            batch = cursor.next_batch()
        except (ConnectionFailure, CursorNotFound) as exc:
            self._disconnected(cursor.request, exc)
            return
        except OperationFailure as exc:
            if not _resumable(exc):
                self._closed = True
                raise
            self._disconnected(cursor.request, exc)
            return
        self._buffer_batch(batch, cursor.request)

    @_csot.apply
    def next(self) -> _DocumentType:
        """Return the next permitted change event.

        A temporary disconnection is recorded and one resume is attempted in
        this call. If that resume also fails, the caller receives the
        connection error and a later call retries from the same acknowledged
        resume point.

        :raises ~pymongo.errors.ScopeRevokedError: If a buffered event or
            resume point is within a withdrawn range.
        :raises StopIteration: Once the subscription is closed or
            exhausted.
        """
        terminal_revocation = self._terminal_revocation
        if terminal_revocation is not None:
            raise terminal_revocation
        if self._closed:
            raise StopIteration
        while True:
            if self._buffer:
                return cast(_DocumentType, self._take())
            if self._exhausted:
                self._finish()
                raise StopIteration
            if self._cursor is None:
                self._resume()
            else:
                self._fetch()
            if self._closed:
                raise StopIteration

    def __iter__(self) -> AuditSubscription[_DocumentType]:
        return self

    __next__ = next

    def __enter__(self) -> AuditSubscription[_DocumentType]:
        self._initialize_if_needed()
        return self

    def _initialize_if_needed(self) -> None:
        """Initialize an unopened subscription used as a context manager."""
        if self._cursor is None and not self._closed:
            self._initialize()

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()

    def close(self) -> None:
        """Stop delivery and close the underlying cursor."""
        cursor = self._cursor
        self._cursor = None
        if cursor is not None:
            cursor.close()
        self._finish()
