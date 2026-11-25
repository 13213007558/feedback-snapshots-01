"""
audit_proof - lifecycle-event proof boundary simulation for APScheduler.

Public API is importable with the standard library only; the APScheduler
specific bridges live in :mod:`audit_proof.aps_bridge` and
:mod:`audit_proof.live`.
"""

from __future__ import annotations

from .delivery import (
    ControllableBroker,
    Inbox,
    LossyForwarder,
    OutboxRelay,
    VerifyingConsumer,
)
from .model import (
    PublicCompletionEvent,
    canonical_result_digest,
    stable_event_id,
)
from .reconcile import Reconciler, Verdict
from .scenarios import run_simulation
from .unit_of_work import (
    AuditUnitOfWork,
    CommittedState,
    SaveRolledBack,
    make_unbound_early_event,
)

__all__ = [
    "AuditUnitOfWork",
    "CommittedState",
    "ControllableBroker",
    "Inbox",
    "LossyForwarder",
    "OutboxRelay",
    "PublicCompletionEvent",
    "Reconciler",
    "SaveRolledBack",
    "Verdict",
    "VerifyingConsumer",
    "canonical_result_digest",
    "make_unbound_early_event",
    "run_simulation",
    "stable_event_id",
]
