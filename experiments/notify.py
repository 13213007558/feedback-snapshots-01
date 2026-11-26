"""Shared tracing + notification primitives for the local experiments.

Event taxonomy proposed for security-operations notifications:

- association.changed   local relation committed (bind/unbind), a durable fact
- association.pending   relation change attempted but remote/local confirmation
                        is still outstanding; must be reconciled by read-back
- callback.completed    the browser redirect happened; pure UX signal, never
                        evidence of a state change

Every event carries a deterministic idempotency key so consumers can dedupe
re-deliveries: (op, provider, id_key, uid, user_id, attempt).
"""

from __future__ import annotations

import functools


class Notifier:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def emit(self, kind: str, op: str, status: str, **fact) -> dict:
        event = {
            "kind": kind,
            "op": op,
            "status": status,
            "idem_key": (
                op,
                fact.get("provider"),
                fact.get("id_key", ""),
                str(fact.get("uid")),
                fact.get("user_id"),
                fact.get("attempt", 0),
            ),
            **fact,
        }
        self.events.append(event)
        return event


class Trace:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def record(self, entry: str) -> None:
        self.calls.append(entry)

    def dump(self) -> str:
        return "\n".join(f"  {i + 1:>2}. {c}" for i, c in enumerate(self.calls))


def traced(trace: Trace, label: str):
    """Wrap a callable so every invocation is appended to the trace."""

    def deco(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            trace.record(label)
            return func(*args, **kwargs)

        return wrapper

    return deco
