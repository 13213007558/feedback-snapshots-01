import copy
import uuid

from datetime import datetime, timedelta, timezone
from enum import Enum

from openfga_sdk.approval.scope import TupleScope, enforce_scope
from openfga_sdk.client.models.tuple import ClientTuple


class ApprovalStatus(str, Enum):
    PENDING = "PENDING"
    ISSUED = "ISSUED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class ApprovalExpiredError(Exception):
    """
    Raised when a check (or a retry of one) is attempted after the approval
    that authorized its temporary relationships has expired.
    """

    def __init__(self, approval_id: str):
        self.approval_id = approval_id
        super().__init__(f"approval {approval_id} has expired")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Approval:
    """
    A caller-issued approval that authorizes a set of temporary (contextual)
    relationships for a single check, optionally restricted to an
    object/relation scope.

    The approval snapshots its tuples when it is created. The snapshot, rather
    than the caller's list, is the only data that can ever be sent, so later
    mutation of the caller's list never changes an in-flight or retried check.
    """

    def __init__(
        self,
        contextual_tuples: list[ClientTuple],
        scope: TupleScope | None = None,
        ttl: timedelta | None = None,
        approval_id: str | None = None,
        now: datetime | None = None,
    ):
        self._id = approval_id or str(uuid.uuid4())
        self._scope = scope
        self._issued_at = now or _utc_now()
        self._ttl = ttl
        self._revoked = False

        if self._issued_at.tzinfo is None:
            self._issued_at = self._issued_at.replace(tzinfo=timezone.utc)

        # Validate every tuple against the scope before snapshotting, then keep
        # a deep copy so the caller cannot mutate the approved data.
        self._snapshot: list[ClientTuple] = [
            self._snapshot_tuple(tuple_key)
            for tuple_key in enforce_scope(contextual_tuples, scope)
        ]

    @staticmethod
    def _snapshot_tuple(tuple_key: ClientTuple) -> ClientTuple:
        return copy.deepcopy(tuple_key)

    @property
    def id(self) -> str:
        return self._id

    @property
    def scope(self) -> TupleScope | None:
        return self._scope

    @property
    def issued_at(self) -> datetime:
        return self._issued_at

    @property
    def expires_at(self) -> datetime | None:
        if self._ttl is None:
            return None

        return self._issued_at + self._ttl

    @property
    def status(self) -> ApprovalStatus:
        if self._revoked:
            return ApprovalStatus.REVOKED

        if self.expires_at is not None and _utc_now() >= self.expires_at:
            return ApprovalStatus.EXPIRED

        return ApprovalStatus.ISSUED

    def is_valid(self, now: datetime | None = None) -> bool:
        if self._revoked:
            return False

        if self.expires_at is None:
            return True

        current = now or _utc_now()
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)

        return current < self.expires_at

    def revoke(self) -> None:
        self._revoked = True

    def materialize(self, now: datetime | None = None) -> list[ClientTuple]:
        """
        Return an independent copy of the approved temporary tuples for use in
        a check attempt. Raises ``ApprovalExpiredError`` if the approval is no
        longer valid. Every call re-checks expiry, so a retry blocked behind a
        transient failure cannot reuse an approval that lapsed while waiting.
        """
        if not self.is_valid(now):
            raise ApprovalExpiredError(self._id)

        return [copy.deepcopy(tuple_key) for tuple_key in self._snapshot]
