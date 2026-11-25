# Copyright 2026-present MongoDB, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Internal helpers for audit subscriptions, shared by the synchronous and asynchronous APIs."""

from __future__ import annotations

import copy
import threading
import time
from collections import deque
from collections.abc import Mapping, Sequence
from typing import Any, Literal

from bson.timestamp import Timestamp
from pymongo.errors import InvalidOperation, PyMongoError, ScopeRevokedError

_AuditEventKind = Literal[
    "scope_revoked",
    "stream_opened",
    "open_refused",
    "resume_attempted",
    "resume_refused",
    "resume_issued",
    "disconnected",
    "batch_received",
    "delivered",
    "delivery_blocked",
    "stream_closed",
]


def _require_timestamp(value: Any, what: str) -> Timestamp:
    if not isinstance(value, Timestamp):
        raise InvalidOperation(f"{what} must be a Timestamp, got {value!r}")
    return value


class AuditRevocation:
    """A scope, optionally bounded in cluster time, that was withdrawn.

    When `cluster_time` is provided, every change in :attr:`scope` at or before
    that time must not be delivered and must not be reachable through a resume
    point. When it is ``None``, the entire scope is withdrawn.

    :param scope: The namespace whose changes were withdrawn, or ``None`` when
        every scope was withdrawn.
    :param cluster_time: The inclusive upper bound of the withdrawn range, or
        ``None`` to withdraw the complete scope.
    :param reason: The operator-supplied reason for the withdrawal.
    """

    __slots__ = ("_cluster_time", "_reason", "_scope")

    def __init__(
        self,
        scope: str | None,
        cluster_time: Timestamp | None = None,
        reason: str | None = None,
    ) -> None:
        if cluster_time is not None:
            _require_timestamp(cluster_time, "cluster_time")
        if scope is not None and (not isinstance(scope, str) or not scope):
            raise TypeError("scope must be a non-empty namespace string or None")
        self._scope = scope
        self._cluster_time = cluster_time
        self._reason = reason

    @property
    def scope(self) -> str | None:
        """The namespace whose changes were withdrawn, or None for every scope."""
        return self._scope

    @property
    def cluster_time(self) -> Timestamp | None:
        """The inclusive upper bound of the withdrawn range, if bounded."""
        return self._cluster_time

    @property
    def reason(self) -> str | None:
        """The operator-supplied reason for the withdrawal."""
        return self._reason

    def covers(self, scope: str | None) -> bool:
        """Return True if this withdrawal applies to `scope`."""
        return self._scope is None or self._scope == scope

    def includes_position(self, cluster_time: Timestamp) -> bool:
        """Return True if a position at `cluster_time` is inside this withdrawal."""
        return self._cluster_time is None or cluster_time <= self._cluster_time

    def __repr__(self) -> str:
        return (
            f"AuditRevocation(scope={self._scope!r}, cluster_time={self._cluster_time!r}, "
            f"reason={self._reason!r})"
        )


class AuditResumePoint:
    """A resume token together with the cluster time of the position it names.

    A change stream resume token alone does not say when the position it
    names occurred, so a compliance check cannot tell whether resuming from it
    would replay withdrawn changes. An audit subscription therefore carries
    both the token and the cluster time of the last event it acknowledged.

    :param cluster_time: The cluster time of the event, or of the server
        response, that produced `token`.
    :param token: The ``_id`` of a change event or a
        ``postBatchResumeToken``.
    :param scope: The namespace at this resume position. When omitted, the
        subscription's scope is used for authorization.
    """

    __slots__ = ("_cluster_time", "_scope", "_token")

    def __init__(
        self,
        cluster_time: Timestamp,
        token: Mapping[str, Any],
        scope: str | None = None,
    ) -> None:
        _require_timestamp(cluster_time, "cluster_time")
        if not isinstance(token, Mapping):
            raise TypeError(f"token must be a mapping, not {type(token)}")
        if scope is not None and (not isinstance(scope, str) or not scope):
            raise TypeError("scope must be a non-empty namespace string or None")
        self._cluster_time = cluster_time
        self._token = copy.deepcopy(dict(token))
        self._scope = scope

    @property
    def cluster_time(self) -> Timestamp:
        """The cluster time of the position this resume point names."""
        return self._cluster_time

    @property
    def scope(self) -> str | None:
        """The namespace of the position, if one was recorded."""
        return self._scope

    @property
    def token(self) -> Mapping[str, Any]:
        """The resume token."""
        return copy.deepcopy(self._token)

    def __repr__(self) -> str:
        return (
            f"AuditResumePoint(cluster_time={self._cluster_time!r}, "
            f"scope={self._scope!r}, token={self._token!r})"
        )


class AuditBatch:
    """A batch of change events returned by an audit cursor.

    An opener returns this type from
    :meth:`~pymongo.asynchronous.audit.AsyncAuditCursor.next_batch` to describe one
    server response. The subscription, not the cursor, owns the buffered
    events and decides whether each one may be delivered.

    :param changes: The change events, in the order the server returned them.
        Each event must carry a top-level ``clusterTime``.
    :param post_batch_resume_token: The ``postBatchResumeToken`` the server
        returned for the batch, if any.
    :param cursor_id: The server cursor id, or ``0`` when the server closed
        the cursor.
    :param operation_time: The ``operationTime`` of the response, used to
        date a batch that contains no events.

    .. versionadded:: 4.21
    """

    __slots__ = ("changes", "cursor_id", "operation_time", "post_batch_resume_token")

    def __init__(
        self,
        changes: Sequence[Mapping[str, Any]],
        post_batch_resume_token: Mapping[str, Any] | None = None,
        cursor_id: int = 1,
        operation_time: Timestamp | None = None,
    ) -> None:
        if operation_time is not None:
            _require_timestamp(operation_time, "operation_time")
        self.changes = list(changes)
        self.post_batch_resume_token = (
            None
            if post_batch_resume_token is None
            else copy.deepcopy(dict(post_batch_resume_token))
        )
        self.cursor_id = cursor_id
        self.operation_time = operation_time

    @property
    def cluster_time(self) -> Timestamp | None:
        """The cluster time that acknowledges this batch."""
        event_times = [
            _require_timestamp(change.get("clusterTime"), "change clusterTime")
            for change in self.changes
        ]
        latest = max(event_times, default=None)
        if self.operation_time is not None and (latest is None or self.operation_time > latest):
            latest = self.operation_time
        return latest


class AuditTrail:
    """The compliance ledger shared by audit subscriptions.

    The ledger holds institutional withdrawals and an ordered audit trail of
    what each subscription processed: events delivered, resume requests that
    were refused before reaching the server, and the resume requests that were
    actually issued. A subscription consults the ledger before it opens a
    stream, before it resumes, and before it hands each buffered event to the
    caller.

    The ledger is thread safe. A withdrawal applies immediately to every
    subscription sharing the ledger, including events that were already
    buffered on the client before the withdrawal.

    .. versionadded:: 4.21
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._revocations: list[AuditRevocation] = []
        self._epoch = 0
        self._events: list[dict[str, Any]] = []
        self._sequence = 0

    def revoke(
        self,
        scope: str | None = None,
        cluster_time: Timestamp | str | None = None,
        reason: str | None = None,
    ) -> int:
        """Withdraw `scope`, optionally only through `cluster_time`.

        A string passed as `cluster_time` is treated as the reason for a full
        scope revocation. Return the new authorization epoch. When
        `cluster_time` is supplied, every resume point at or before that time is
        unusable afterwards. When it is ``None``, every resume point and
        buffered event for the scope is unusable.

        :param scope: The namespace to withdraw, or ``None`` to withdraw every
            scope.
        :param cluster_time: The inclusive end of the withdrawn range, or
            ``None`` to withdraw the whole scope.
        :param reason: The operator-supplied reason for the withdrawal.

        :raises TypeError: If `scope` is neither a non-empty string nor
            ``None``.
        :raises ~pymongo.errors.InvalidOperation: If `cluster_time` is not a
            :class:`~bson.timestamp.Timestamp`.
        """
        if isinstance(cluster_time, str):
            reason = cluster_time if reason is None else reason
            cluster_time = None
        revocation = AuditRevocation(scope, cluster_time, reason)
        with self._lock:
            self._revocations.append(revocation)
            self._epoch += 1
            epoch = self._epoch
            self._record_locked(
                "scope_revoked",
                scope,
                None,
                epoch,
                {
                    "revocation_time": cluster_time,
                    "full_scope": cluster_time is None,
                    "reason": reason,
                },
            )
        return epoch

    def revoke_scope(self, scope: str, reason: str | None = None) -> int:
        """Withdraw an entire namespace and all of its buffered positions."""
        return self.revoke(scope, None, reason)

    def revoke_all(self, reason: str | None = None) -> int:
        """Withdraw every namespace."""
        return self.revoke(None, None, reason)

    @property
    def epoch(self) -> int:
        """The current authorization epoch."""
        with self._lock:
            return self._epoch

    @property
    def revocations(self) -> tuple[AuditRevocation, ...]:
        """The withdrawals recorded so far."""
        with self._lock:
            return tuple(self._revocations)

    @property
    def events(self) -> tuple[dict[str, Any], ...]:
        """The ordered audit trail records, oldest first."""
        with self._lock:
            return tuple(copy.deepcopy(self._events))

    def applicable_all(self, scope: str | None) -> tuple[AuditRevocation, ...]:
        """Return all withdrawals that apply to `scope`, oldest first."""
        with self._lock:
            return tuple(rev for rev in self._revocations if rev.covers(scope))

    def applicable(self, scope: str | None) -> AuditRevocation | None:
        """Return the dominant withdrawal applicable to `scope`, if any."""
        revocations = self.applicable_all(scope)
        if not revocations:
            return None
        full_scope = [rev for rev in revocations if rev.cluster_time is None]
        if full_scope:
            return full_scope[-1]
        return max(revocations, key=lambda rev: rev.cluster_time)  # type: ignore[arg-type,return-value]

    @property
    def actual_resume_requests(self) -> tuple[dict[str, Any], ...]:
        """Return only resume requests that an opener successfully issued."""
        with self._lock:
            return tuple(
                copy.deepcopy(record)
                for record in self._events
                if record["kind"] == "resume_issued"
            )

    @property
    def processed_events(self) -> tuple[dict[str, Any], ...]:
        """Return delivery and delivery-block records in processing order."""
        with self._lock:
            return tuple(
                copy.deepcopy(record)
                for record in self._events
                if record["kind"] in {"delivered", "delivery_blocked"}
            )

    def transcript(self) -> tuple[str, ...]:
        """Return a compact, ordered human-readable audit transcript."""
        with self._lock:
            lines: list[str] = []
            for record in self._events:
                point = record["resume_point"]
                if point is None:
                    position = "position=-"
                else:
                    token = point["token"].get("_data", point["token"])
                    position = f"position=({point['cluster_time']}, {token})"
                details: list[str] = []
                for key in ("error", "count", "operation_type", "reason"):
                    value = record.get(key)
                    if value is not None:
                        details.append(f"{key}={value}")
                if record["kind"] in {"stream_opened", "resume_issued"}:
                    change_stream = (
                        record.get("request", {}).get("pipeline", [{}])[0].get("$changeStream", {})
                    )
                    details.append(f"changeStream={change_stream}")
                if record["kind"] == "delivery_blocked":
                    details.append(f"blocked={record.get('blocked_token')}")
                suffix = f" {' '.join(details)}" if details else ""
                lines.append(
                    f"{record['sequence']:02d} {record['kind']} "
                    f"scope={record['scope']} {position}{suffix}"
                )
            return tuple(lines)

    def _record(
        self,
        kind: _AuditEventKind,
        scope: str | None,
        resume_point: AuditResumePoint | None = None,
        **detail: Any,
    ) -> None:
        with self._lock:
            self._record_locked(kind, scope, resume_point, self._epoch, detail)

    def _record_locked(
        self,
        kind: _AuditEventKind,
        scope: str | None,
        resume_point: AuditResumePoint | None,
        epoch: int,
        detail: Mapping[str, Any],
    ) -> None:
        self._sequence += 1
        record: dict[str, Any] = {
            "sequence": self._sequence,
            "at": time.monotonic_ns(),
            "kind": kind,
            "scope": scope,
            "epoch": epoch,
            "resume_point": None
            if resume_point is None
            else {
                "cluster_time": resume_point.cluster_time,
                "token": resume_point.token,
            },
        }
        record.update(copy.deepcopy(dict(detail)))
        self._events.append(record)


class AuditSubscriptionBase:
    """The state machine shared by synchronous and asynchronous audit subscriptions.

    The state machine owns the resume point, the buffer of events the server
    acknowledged but the caller has not consumed, and every authorization
    check. Subclasses implement only the I/O: opening a cursor through the
    opener, fetching a batch, and closing the cursor.

    Two guarantees are enforced here rather than in the driver's change
    stream:

    - :meth:`_authorize` runs before any open or resume request is issued.
      When the resume point lies at or before an applicable withdrawal, the
      request is recorded as refused and :exc:`~pymongo.errors.ScopeRevokedError`
      is raised without contacting the server.
    - :meth:`_take` runs before every event is returned. A buffered event
      inside a withdrawn range is recorded as blocked and
      :exc:`~pymongo.errors.ScopeRevokedError` is raised, even though the event
      was already cached on the client.

    .. versionadded:: 4.21
    """

    def __init__(
        self,
        scope: str | None,
        trail: AuditTrail,
        opener: Any,
        resume_point: AuditResumePoint | None = None,
    ) -> None:
        if scope is not None and (not isinstance(scope, str) or not scope):
            raise TypeError("scope must be a non-empty namespace string or None")
        if not isinstance(trail, AuditTrail):
            raise TypeError(f"trail must be an AuditTrail, not {type(trail)}")
        if not callable(opener):
            raise TypeError("opener must be callable")
        if resume_point is not None and not isinstance(resume_point, AuditResumePoint):
            raise TypeError(f"resume_point must be an AuditResumePoint, not {type(resume_point)}")
        self._scope = scope
        self._trail = trail
        self._opener = opener
        self._resume_point = resume_point
        self._buffer: deque[Mapping[str, Any]] = deque()
        self._batch_end: AuditResumePoint | None = None
        self._cursor: Any = None
        self._pending_error: PyMongoError | None = None
        self._terminal_revocation: ScopeRevokedError | None = None
        self._closed = False
        self._exhausted = False
        self._recorded_close = False

    @property
    def scope(self) -> str | None:
        """The namespace this subscription reads, or None for every scope."""
        return self._scope

    @property
    def resume_point(self) -> AuditResumePoint | None:
        """The resume point for the most recent acknowledged position."""
        return self._resume_point

    @property
    def resume_token(self) -> Mapping[str, Any] | None:
        """The resume token for the most recent acknowledged position."""
        point = self._resume_point
        return None if point is None else point.token

    @property
    def epoch(self) -> int:
        """The current authorization epoch of the subscription's trail."""
        return self._trail.epoch

    @property
    def closed(self) -> bool:
        """True once the subscription stopped delivering."""
        return self._closed

    @property
    def alive(self) -> bool:
        """True while the subscription may still deliver events."""
        return not self._closed and not self._exhausted

    def _refusal(self, revocation: AuditRevocation, point: AuditResumePoint | None) -> str:
        scope = self._scope if point is None else point.scope or self._scope
        position = (
            "current position" if point is None else f"resume point at {point.cluster_time!r}"
        )
        if revocation.cluster_time is None:
            withdrawn = "was revoked in full"
        else:
            withdrawn = f"was withdrawn through {revocation.cluster_time!r}"
        return (
            f"The {position} for {scope or 'all scopes'} cannot be issued: "
            f"{revocation.scope or 'all scopes'} {withdrawn}"
            + (f": {revocation.reason}" if revocation.reason else "")
        )

    def _position_scope(self, point: AuditResumePoint) -> str | None:
        """Return the namespace to authorize for a resume point."""
        return point.scope or self._scope

    def _authorize(
        self,
        point: AuditResumePoint | None,
        *,
        is_resume: bool,
        error: PyMongoError | None = None,
    ) -> None:
        """Refuse an open or resume request whose position was withdrawn."""
        if is_resume:
            self._trail._record(
                "resume_attempted",
                self._scope,
                point,
                error=None if error is None else type(error).__name__,
            )
        position_scope = self._scope if point is None else self._position_scope(point)
        applicable = self._trail.applicable_all(position_scope)
        if point is None:
            revocation = next(
                (candidate for candidate in applicable if candidate.cluster_time is None),
                None,
            )
        else:
            revocation = next(
                (
                    candidate
                    for candidate in applicable
                    if candidate.includes_position(point.cluster_time)
                ),
                None,
            )
        if revocation is None:
            return
        self._trail._record(
            "resume_refused" if is_resume else "open_refused",
            self._scope,
            point,
            revocation_scope=revocation.scope,
            revocation_time=revocation.cluster_time,
            full_scope=revocation.cluster_time is None,
            reason=revocation.reason,
        )
        self._buffer.clear()
        self._batch_end = None
        self._closed = True
        refusal = ScopeRevokedError(self._refusal(revocation, point))
        self._terminal_revocation = refusal
        raise refusal

    def _record_request(self, request: Mapping[str, Any], is_resume: bool) -> None:
        """Record the command the opener actually issued."""
        self._trail._record(
            "resume_issued" if is_resume else "stream_opened",
            self._scope,
            self._resume_point,
            request=copy.deepcopy(dict(request)),
        )

    def _disconnected(self, request: Mapping[str, Any], exc: PyMongoError) -> None:
        """Record a lost connection and park the cursor for a later resume."""
        self._trail._record(
            "disconnected",
            self._scope,
            self._resume_point,
            request=copy.deepcopy(dict(request)),
            error=type(exc).__name__,
        )
        self._cursor = None
        self._pending_error = exc

    def _buffer_batch(self, batch: AuditBatch, request: Mapping[str, Any]) -> None:
        """Buffer a batch and remember the resume point that ends it.

        The batch's post-batch resume token is adopted only once every event
        in the batch has been delivered, matching change stream semantics: a
        caller that resumes mid-batch must replay the undelivered events.
        """
        self._buffer.extend(batch.changes)
        cluster_time = batch.cluster_time
        self._batch_end = (
            None
            if batch.post_batch_resume_token is None or cluster_time is None
            else AuditResumePoint(cluster_time, batch.post_batch_resume_token, self._scope)
        )
        if batch.cursor_id == 0:
            self._exhausted = True
        if not batch.changes and self._batch_end is not None:
            self._resume_point = self._batch_end
            self._batch_end = None
        self._trail._record(
            "batch_received",
            self._scope,
            self._resume_point,
            request=copy.deepcopy(dict(request)),
            count=len(batch.changes),
            cursor_id=batch.cursor_id,
            batch_tokens=[change.get("_id") for change in batch.changes],
        )

    def _event_scope(self, change: Mapping[str, Any]) -> str | None:
        """Return the namespace carried by a change event, when available."""
        namespace = change.get("ns")
        if isinstance(namespace, Mapping):
            database = namespace.get("db")
            collection = namespace.get("coll")
            if isinstance(database, str) and isinstance(collection, str):
                return f"{database}.{collection}"
        return self._scope

    def _take(self) -> Mapping[str, Any]:
        """Return the oldest buffered event if the trail permits delivery."""
        change = self._buffer.popleft()
        token = change.get("_id")
        if not isinstance(token, Mapping):
            self._closed = True
            raise InvalidOperation(
                "Cannot provide resume functionality when the resume token is missing."
            )
        cluster_time = _require_timestamp(change.get("clusterTime"), "change clusterTime")
        event_scope = self._event_scope(change)
        revocation = next(
            (
                candidate
                for candidate in self._trail.applicable_all(event_scope)
                if candidate.includes_position(cluster_time)
            ),
            None,
        )
        if revocation is not None:
            self._trail._record(
                "delivery_blocked",
                event_scope,
                self._resume_point,
                reason=revocation.reason,
                operation_type=change.get("operationType"),
                revocation_scope=revocation.scope,
                revocation_time=revocation.cluster_time,
                full_scope=revocation.cluster_time is None,
                blocked_cluster_time=cluster_time,
                blocked_token=token,
            )
            self._buffer.clear()
            self._batch_end = None
            self._closed = True
            where = event_scope or "all scopes"
            if revocation.cluster_time is None:
                withdrawn = "the scope was revoked in full"
            else:
                withdrawn = f"it was withdrawn through {revocation.cluster_time!r}"
            blocked_error = ScopeRevokedError(
                f"Event at {cluster_time!r} in {where} is blocked because {withdrawn}"
                + (f": {revocation.reason}" if revocation.reason else "")
            )
            self._terminal_revocation = blocked_error
            raise blocked_error
        if not self._buffer and self._batch_end is not None:
            self._resume_point = self._batch_end
            self._batch_end = None
        else:
            self._resume_point = AuditResumePoint(cluster_time, token, event_scope)
        self._trail._record(
            "delivered",
            event_scope,
            self._resume_point,
            operation_type=change.get("operationType"),
            ns=change.get("ns"),
        )
        return change

    def _finish(self) -> None:
        """Record that the subscription closed exactly once."""
        self._closed = True
        if self._recorded_close:
            return
        self._recorded_close = True
        self._trail._record("stream_closed", self._scope, self._resume_point)
