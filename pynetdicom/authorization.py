"""Destination authorisation for the C-MOVE service.

A C-MOVE SCP performs two privileged actions that are independent of each
other:

* it decides whether the *requesting identity* may query the archive, and
* it opens a **new** association with the *move destination* and sends the
  matching SOP Instances over it using one or more C-STORE sub-operations.

Authorising the query says nothing about whether the nominated destination may
receive the data, and a destination approval may be withdrawn while a C-MOVE
operation is in progress. This module provides an optional policy object that
keeps the two approvals separate, binds the destination approval to the new
association, and re-validates it for every C-STORE sub-operation.

If no policy is assigned to an :class:`~pynetdicom.ae.ApplicationEntity` via
``ApplicationEntity.move_authorization`` then the C-MOVE SCP keeps its previous
behaviour and no authorisation checks are made.

Examples
--------

>>> from pynetdicom import AE
>>> from pynetdicom.authorization import InMemoryMoveAuthorization
>>> policy = InMemoryMoveAuthorization(approved_queries=["EXPORT_SCU"])
>>> policy.grant_destination("EXPORT_SCU", "ARCHIVE_DEST")
>>> ae = AE()
>>> ae.move_authorization = policy
>>> # Later, while the C-MOVE operation is running:
>>> policy.revoke_destination("EXPORT_SCU", "ARCHIVE_DEST")

References
----------

* DICOM Standard, Part 4, :dcm:`Annex C<part04/chapter_C.html>`
"""

from __future__ import annotations

import threading
from collections.abc import Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

from pydicom.dataset import Dataset

if TYPE_CHECKING:  # pragma: no cover
    from pynetdicom.dimse_primitives import C_MOVE


QUERY_STAGE = "query"
DESTINATION_STAGE = "destination"
SUB_OPERATION_STAGE = "sub-operation"


@dataclass(frozen=True)
class MoveApproval:
    """The result of a destination authorisation decision.

    Approvals are evidence objects: the C-MOVE SCP keeps the destination
    approval for the lifetime of the new storage association and passes it to
    the policy again for each C-STORE sub-operation. ``generation`` records the
    state of the destination grant at the time of approval so that a later
    withdrawal invalidates previously issued approvals.
    """

    identity: str
    """The requesting identity the approval applies to."""

    approved: bool
    """``True`` if the action was approved, ``False`` otherwise."""

    stage: str
    """One of ``"query"``, ``"destination"`` or ``"sub-operation"``."""

    destination: str | None = None
    """The *Move Destination* AE title the approval applies to."""

    reason: str = ""
    """A short, non-sensitive reason for the decision."""

    request_message_id: int | None = None
    """The *Message ID* of the C-MOVE request being authorised."""

    generation: int | None = None
    """The destination grant generation at the time of approval."""

    sop_instance_uid: str | None = None
    """The SOP Instance UID for sub-operation approvals."""

    def __post_init__(self) -> None:
        if self.stage not in (QUERY_STAGE, DESTINATION_STAGE, SUB_OPERATION_STAGE):
            raise ValueError(f"Invalid approval stage '{self.stage}'")

    @property
    def denied(self) -> bool:
        """``True`` if the action was denied."""
        return not self.approved


class MoveAuthorization(Protocol):
    """Protocol for C-MOVE destination authorisation policies.

    Implementations must treat the query approval, the destination approval
    and the per sub-operation approval as separate decisions. The
    :meth:`approve_sub_operation` method must consult the current state of the
    destination grant rather than only the previously issued approval.
    """

    def approve_query(self, identity: str, request: C_MOVE) -> MoveApproval:
        """Return the decision for the querying identity."""
        ...

    def approve_destination(
        self, query: MoveApproval, destination: str, request: C_MOVE
    ) -> MoveApproval:
        """Return the decision for opening an association with `destination`."""
        ...

    def approve_sub_operation(
        self,
        destination: MoveApproval,
        dataset: Dataset | None = None,
        sop_instance_uid: str | None = None,
    ) -> MoveApproval:
        """Return the decision for sending a single C-STORE sub-operation."""
        ...


@dataclass
class _Grant:
    """The current state of a destination approval for an identity."""

    approved: bool
    generation: int
    reference: str | None = None
    # If not None, only these SOP Instance UIDs may be sent
    allowed_instances: frozenset[str] | None = None


class InMemoryMoveAuthorization:
    """An in-memory :class:`MoveAuthorization` implementation.

    The policy keeps a set of identities approved to *query* the archive and a
    separate per ``(identity, destination)`` grant for *receiving* data. A
    grant can be withdrawn at any time; already issued destination approvals
    then fail :meth:`approve_sub_operation` because their ``generation`` no
    longer matches the current grant.

    The policy never stores or returns credentials. Query identities are
    caller-supplied strings (for example the calling AE title or a username)
    and the audit log contains only the approval decisions.

    Parameters
    ----------
    approved_queries : iterable of str, optional
        The identities approved to query the archive.
    """

    def __init__(self, approved_queries: Iterable[str] | None = None) -> None:
        self._lock = threading.RLock()
        self._approved_queries: set[str] = set(approved_queries or ())
        self._grants: dict[tuple[str, str], _Grant] = {}
        self._audit: list[MoveApproval] = []

    def allow_query(self, identity: str) -> None:
        """Approve `identity` to query the archive."""
        with self._lock:
            self._approved_queries.add(identity)

    def deny_query(self, identity: str, *, reason: str = "query identity revoked") -> None:
        """Withdraw `identity`'s approval to query the archive."""
        with self._lock:
            self._approved_queries.discard(identity)
            self._audit.append(
                MoveApproval(
                    identity=identity,
                    approved=False,
                    stage=QUERY_STAGE,
                    reason=reason,
                )
            )

    def grant_destination(
        self,
        identity: str,
        destination: str,
        *,
        reference: str | None = None,
        allowed_instances: Iterable[str] | None = None,
    ) -> MoveApproval:
        """Approve `identity` to send data to `destination`.

        Parameters
        ----------
        identity : str
            The requesting identity the grant applies to.
        destination : str
            The *Move Destination* AE title the grant applies to.
        reference : str, optional
            A caller-defined non-sensitive reference (for example a ticket
            number) recorded with the grant.
        allowed_instances : iterable of str, optional
            If given, only the listed SOP Instance UIDs may be sent to
            `destination`. If ``None`` then all instances are allowed.

        Returns
        -------
        MoveApproval
            The destination approval, which can be passed to
            :meth:`approve_sub_operation`.
        """
        with self._lock:
            grant = self._grants.get((identity, destination))
            generation = 1 if grant is None else grant.generation + 1
            allowed = (
                None if allowed_instances is None else frozenset(allowed_instances)
            )
            self._grants[(identity, destination)] = _Grant(
                approved=True,
                generation=generation,
                reference=reference,
                allowed_instances=allowed,
            )
            approval = MoveApproval(
                identity=identity,
                approved=True,
                stage=DESTINATION_STAGE,
                destination=destination,
                reason="destination approved",
                generation=generation,
            )
            self._audit.append(approval)
            return approval

    def revoke_destination(
        self,
        identity: str,
        destination: str,
        *,
        reason: str = "destination approval revoked",
    ) -> None:
        """Withdraw `identity`'s approval to send data to `destination`.

        Any destination approval issued before this call is invalidated and
        subsequent sub-operation checks will fail.
        """
        with self._lock:
            grant = self._grants.get((identity, destination))
            generation = 1 if grant is None else grant.generation + 1
            self._grants[(identity, destination)] = _Grant(
                approved=False, generation=generation
            )
            self._audit.append(
                MoveApproval(
                    identity=identity,
                    approved=False,
                    stage=DESTINATION_STAGE,
                    destination=destination,
                    reason=reason,
                    generation=generation,
                )
            )

    def destination_state(self, identity: str, destination: str) -> str:
        """Return ``"approved"``, ``"revoked"`` or ``"unknown"``."""
        with self._lock:
            grant = self._grants.get((identity, destination))
            if grant is None:
                return "unknown"

            return "approved" if grant.approved else "revoked"

    @property
    def audit_log(self) -> tuple[MoveApproval, ...]:
        """Return an immutable snapshot of the recorded decisions."""
        with self._lock:
            return tuple(self._audit)

    def _record(self, approval: MoveApproval) -> MoveApproval:
        self._audit.append(approval)
        return approval

    def approve_query(self, identity: str, request: C_MOVE) -> MoveApproval:
        """Return the decision for the querying identity."""
        with self._lock:
            approved = identity in self._approved_queries
            reason = "query identity approved" if approved else "query identity not approved"
            return self._record(
                MoveApproval(
                    identity=identity,
                    approved=approved,
                    stage=QUERY_STAGE,
                    reason=reason,
                    request_message_id=getattr(request, "MessageID", None),
                )
            )

    def approve_destination(
        self, query: MoveApproval, destination: str, request: C_MOVE
    ) -> MoveApproval:
        """Return the decision for connecting to `destination`."""
        with self._lock:
            if not query.approved:
                return self._record(
                    MoveApproval(
                        identity=query.identity,
                        approved=False,
                        stage=DESTINATION_STAGE,
                        destination=destination,
                        reason="query identity not approved",
                        request_message_id=getattr(request, "MessageID", None),
                    )
                )

            grant = self._grants.get((query.identity, destination))
            if grant is None:
                reason = f"no destination approval for '{destination}'"
            elif not grant.approved:
                reason = f"destination approval for '{destination}' revoked"
            else:
                reason = "destination approved"

            approved = grant is not None and grant.approved
            return self._record(
                MoveApproval(
                    identity=query.identity,
                    approved=approved,
                    stage=DESTINATION_STAGE,
                    destination=destination,
                    reason=reason,
                    request_message_id=getattr(request, "MessageID", None),
                    generation=None if grant is None else grant.generation,
                )
            )

    def approve_sub_operation(
        self,
        destination: MoveApproval,
        dataset: Dataset | None = None,
        sop_instance_uid: str | None = None,
    ) -> MoveApproval:
        """Return the decision for a single C-STORE sub-operation."""
        uid = sop_instance_uid
        if uid is None and isinstance(dataset, Dataset):
            uid = getattr(dataset, "SOPInstanceUID", None)

        with self._lock:
            if not destination.approved or destination.destination is None:
                return self._record(
                    MoveApproval(
                        identity=destination.identity,
                        approved=False,
                        stage=SUB_OPERATION_STAGE,
                        destination=destination.destination,
                        reason="destination was not approved",
                        request_message_id=destination.request_message_id,
                        sop_instance_uid=uid,
                    )
                )

            grant = self._grants.get((destination.identity, destination.destination))
            if grant is None:
                approved = False
                reason = "destination approval no longer exists"
            elif not grant.approved:
                approved = False
                reason = "destination approval revoked during the operation"
            elif destination.generation != grant.generation:
                approved = False
                reason = "destination approval changed during the operation"
            elif (
                grant.allowed_instances is not None
                and uid not in grant.allowed_instances
            ):
                # The destination is approved, but not for this instance
                approved = False
                reason = "SOP Instance not approved for the destination"
            else:
                approved = True
                reason = "sub-operation approved"

            return self._record(
                MoveApproval(
                    identity=destination.identity,
                    approved=approved,
                    stage=SUB_OPERATION_STAGE,
                    destination=destination.destination,
                    reason=reason,
                    request_message_id=destination.request_message_id,
                    generation=None if grant is None else grant.generation,
                    sop_instance_uid=uid,
                )
            )


def query_identity(assoc: Any) -> str:
    """Return a non-sensitive identity for the C-MOVE requestor.

    Prefers the *User Identity Negotiation* primary field if the requestor sent
    one, otherwise falls back to the calling AE title. The *Secondary Field*
    (which may contain a passcode) is never used.
    """
    requestor = getattr(assoc, "requestor", None)
    ae_title = getattr(requestor, "ae_title", None) or ""

    try:
        identity = requestor.user_identity
    except Exception:
        identity = None

    if identity is not None:
        primary = getattr(identity, "primary_field", None)
        if isinstance(primary, bytes) and primary:
            try:
                text = primary.decode("ascii")
            except UnicodeDecodeError:
                text = primary.hex()

            return f"{ae_title}:{text}"

    return str(ae_title) or "UNKNOWN"
