"""Deterministic, in-process simulator of a Celery cluster + Flower.

No broker and no network: a fake control bus and a manual event pump replace
them so every message ordering, loss and delay is reproducible.  The event
stream is fed into Celery's real ``EventsState`` (subclassed by Flower in
``flower/events.py``), so the state-merge behaviour the experiments observe is
the production behaviour, not a re-implementation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from celery.events import Event

from flower.events import EventsState
from .model import Attempt, Channel, Ledger


@dataclass
class WorkerModel:
    """Minimal worker: a revoked-id set plus per-attempt execution fate."""

    hostname: str
    revoked_ids: set = field(default_factory=set)
    # task_id -> ordered list of attempt fates: 'succeed' or 'revoke'
    plan: Dict[str, List[str]] = field(default_factory=dict)
    clock: int = 0


class FakeControlBus:
    """Stand-in for the Celery mailbox used by ``control.revoke``.

    ``deliver_replies`` controls whether the worker reply is returned to the
    caller (Flower calls revoke without reply=True today, so by default the
    reply is dropped even though the worker still processes the command).
    """

    def __init__(self, worker: WorkerModel, deliver_replies: bool = False):
        self.worker = worker
        self.deliver_replies = deliver_replies
        self.commands: List[dict] = []

    def revoke(self, task_id: str, terminate: bool = False,
               signal: str = 'SIGTERM', reply: bool = False):
        self.commands.append({'task_id': task_id, 'terminate': terminate,
                              'signal': signal, 'reply': reply})
        # The worker always registers the id in its in-memory revoked set when
        # it handles the command, regardless of whether a reply is requested.
        self.worker.revoked_ids.add(task_id)
        if reply and self.deliver_replies:
            return [{self.worker.hostname: {'ok': f'revoked {task_id}'}}]
        return None


class ClusterSimulator:
    """Drives one task id through configurable message interleavings."""

    def __init__(self, task_id: str, *, max_tasks: int = 10000):
        self.task_id = task_id
        self.state = EventsState(max_tasks_in_memory=max_tasks)
        self.worker = WorkerModel(hostname='celery@worker1')
        self.bus = FakeControlBus(self.worker)
        self.ledger = Ledger()
        self._clock = 0
        self._time = 0.0

    def tick(self) -> float:
        self._time += 1.0
        return self._time

    # -- channel 1: the Flower HTTP revoke API -----------------------------
    def http_revoke(self, *, status: int = 200) -> float:
        """Represents POST /api/task/revoke/<id>.

        Flower runs ``control.revoke`` without reply=True and unconditionally
        writes the 200, so a 200 here means "accepted locally" only.
        """
        at = self.tick()
        self.bus.revoke(self.task_id, reply=False)
        self.ledger.append(
            self.task_id, Channel.API, 'revoke-http', at,
            payload={'status': status, 'reply_requested': False})
        return at

    # -- channel 2: explicit control-bus reply (reply=True) ---------------
    def control_revoke_with_reply(self, *, delivered: bool = True) -> float:
        at = self.tick()
        prev = self.bus.deliver_replies
        self.bus.deliver_replies = delivered
        response = self.bus.revoke(self.task_id, reply=True)
        self.bus.deliver_replies = prev
        self.ledger.append(
            self.task_id, Channel.CONTROL, 'revoke-reply', at,
            payload={'worker': self.worker.hostname,
                     'ok': bool(response), 'delivered': delivered})
        return at

    # -- channel 3: worker task events -------------------------------------
    def emit(self, event_type: str, attempt: Attempt,
             *, extra: Optional[dict] = None, duplicate: bool = False) -> float:
        """Push one worker event through the real EventsState merge path."""
        self._clock += 1
        at = self.tick()
        event = Event(event_type, uuid=self.task_id,
                      hostname=self.worker.hostname, clock=self._clock,
                      timestamp=at, local_received=at)
        if extra:
            event.update(extra)
        self.state.event(event)
        self.ledger.append(
            self.task_id, Channel.EVENT, event_type, at,
            attempt_no=attempt.attempt_no, payload=dict(event),
            clock=self._clock, duplicate=duplicate)
        return at

    def succeeded_attempt(self, attempt: Attempt) -> None:
        self.emit('task-received', attempt)
        self.emit('task-started', attempt)
        self.emit('task-succeeded', attempt, extra={'result': 'ok',
                                                    'runtime': 0.5})

    def revoked_attempt(self, attempt: Attempt, *, terminated: bool = False,
                        expired: bool = False) -> None:
        self.emit('task-received', attempt)
        if terminated:
            self.emit('task-started', attempt)
        self.emit('task-revoked', attempt,
                  extra={'terminated': terminated, 'signum': None,
                         'expired': expired})

    def late_succeeded(self, attempt: Attempt) -> None:
        """A re-delivered success for an id we already saw terminate."""
        self.emit('task-succeeded', attempt,
                  extra={'result': 'ok', 'runtime': 0.5}, duplicate=True)

    # -- read-only view of what Flower would show --------------------------
    def flower_task_view(self) -> dict:
        task = self.state.tasks.get(self.task_id)
        if task is None:
            return {'state': 'UNKNOWN'}
        return {
            'state': task.state,
            'received': task.received,
            'started': task.started,
            'succeeded': task.succeeded,
            'failed': task.failed,
            'revoked': task.revoked,
            'retried': task.retried,
            'clock': task.clock,
        }


def run_scenario(name: str, build: Callable[[ClusterSimulator], None]
                 ) -> 'ScenarioResult':
    """Execute one scenario end to end and capture every observation."""
    sim = ClusterSimulator(task_id=f'task-{name}')
    build(sim)
    from .model import Reconciler
    reconciliation = Reconciler().reconcile(sim.ledger, sim.task_id)
    return ScenarioResult(name, sim, reconciliation)


@dataclass
class ScenarioResult:
    name: str
    sim: ClusterSimulator
    reconciliation: object
