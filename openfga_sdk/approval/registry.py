import threading

from dataclasses import dataclass, field
from datetime import datetime, timezone

from openfga_sdk.approval.approval import Approval
from openfga_sdk.approval.scope import TupleScope
from openfga_sdk.client.models.tuple import ClientTuple


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class TupleDispatch:
    """
    One temporary tuple actually attached to an outgoing check, captured at the
    moment of dispatch so the audit trail is independent of later caller
    mutations.
    """

    user: str
    relation: str
    object: str

    @classmethod
    def from_tuple(cls, tuple_key: ClientTuple) -> "TupleDispatch":
        return cls(
            user=tuple_key.user,
            relation=tuple_key.relation,
            object=tuple_key.object,
        )

    def as_dict(self) -> dict[str, str]:
        return {"user": self.user, "relation": self.relation, "object": self.object}


@dataclass
class ApprovalDispatchRecord:
    """
    Audit entry tying a single check attempt back to the approval that supplied
    its temporary relationships and recording exactly which tuples were sent.
    """

    attempt_id: str
    approval_id: str
    check_index: int
    scope: TupleScope | None
    tuples: list[TupleDispatch]
    dispatched_at: datetime = field(default_factory=_utc_now)
    attempt: int = 0


class ApprovalRegistry:
    """
    In-memory store of issued approvals and an audit trail of every temporary
    relationship dispatched to OpenFGA.

    Temporary relationships are never written here as persistent data: the
    registry only holds the approvals themselves and dispatch records. A normal
    check without an approval produces no dispatch record.
    """

    def __init__(self):
        self._approvals: dict[str, Approval] = {}
        self._dispatch_log: list[ApprovalDispatchRecord] = []
        self._lock = threading.Lock()

    def issue(self, approval: Approval) -> Approval:
        with self._lock:
            self._approvals[approval.id] = approval

        return approval

    def get(self, approval_id: str) -> Approval | None:
        with self._lock:
            return self._approvals.get(approval_id)

    def require(self, approval_id: str) -> Approval:
        approval = self.get(approval_id)
        if approval is None:
            raise KeyError(f"unknown approval {approval_id}")

        return approval

    def record_dispatch(
        self,
        approval: Approval,
        tuples: list[ClientTuple],
        check_index: int,
        attempt_id: str,
        attempt: int,
    ) -> ApprovalDispatchRecord:
        record = ApprovalDispatchRecord(
            attempt_id=attempt_id,
            approval_id=approval.id,
            check_index=check_index,
            scope=approval.scope,
            tuples=[TupleDispatch.from_tuple(tuple_key) for tuple_key in tuples],
            attempt=attempt,
        )

        with self._lock:
            self._dispatch_log.append(record)

        return record

    def dispatch_log(self) -> list[ApprovalDispatchRecord]:
        with self._lock:
            return list(self._dispatch_log)

    def dispatches_for(self, approval_id: str) -> list[ApprovalDispatchRecord]:
        with self._lock:
            return [
                record
                for record in self._dispatch_log
                if record.approval_id == approval_id
            ]

    def reset(self) -> None:
        with self._lock:
            self._approvals.clear()
            self._dispatch_log.clear()
