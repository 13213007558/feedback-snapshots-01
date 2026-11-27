"""The four incident scenarios the on-call team asked to reproduce.

Each scenario is a pure function over a :class:`ClusterSimulator`, so they can
be replayed in any order, in tests, or from the CLI runner with identical
results.  Scenario A and D exercise both message orderings explicitly.
"""

from __future__ import annotations

from .model import Attempt
from .simulator import ClusterSimulator, run_scenario


# Scenario A (ordering 1): revoke HTTP 200 arrives, but no control reply is
# delivered; the worker later emits task-revoked.  This is the headline
# "cancelled, then I still saw ..." path where the API alone is silent.
def a_reply_missing_then_revoked(sim: ClusterSimulator) -> None:
    attempt = Attempt(sim.task_id, attempt_no=0)
    sim.emit('task-received', attempt)
    sim.http_revoke()                       # 200 accepted locally, reply=False
    # control bus reply is intentionally never recorded (dropped)
    sim.revoked_attempt(attempt, terminated=False)


# Scenario B: revoke is acknowledged first, but a (retry) attempt later
# succeeds under the same task id.  The HTTP 200 cannot prove the later
# execution was interrupted.
def b_reply_first_then_another_attempt_succeeds(sim: ClusterSimulator) -> None:
    first = Attempt(sim.task_id, attempt_no=0)
    sim.revoked_attempt(first, terminated=True)
    sim.http_revoke()                       # 200 after the revoke already ran
    # A retry reuses the same task id but is a distinct attempt.
    second = Attempt(sim.task_id, attempt_no=1)
    sim.emit('task-retried', first)
    sim.succeeded_attempt(second)


# Scenario C (ordering 1): success event arrives before the revoked event.
def c_success_before_revoked(sim: ClusterSimulator) -> None:
    attempt = Attempt(sim.task_id, attempt_no=0)
    sim.emit('task-received', attempt)
    sim.emit('task-started', attempt)
    sim.http_revoke()
    sim.emit('task-succeeded', attempt, extra={'result': 'ok'})
    sim.emit('task-revoked', attempt,
             extra={'terminated': True, 'signum': 15, 'expired': False})


# Scenario D (ordering 2, the swap of C): revoked event arrives before the
# late success event (e.g. a duplicated / re-delivered result for the same id).
def d_revoked_before_success(sim: ClusterSimulator) -> None:
    attempt = Attempt(sim.task_id, attempt_no=0)
    sim.emit('task-received', attempt)
    sim.emit('task-started', attempt)
    sim.http_revoke()
    sim.emit('task-revoked', attempt,
             extra={'terminated': True, 'signum': 15, 'expired': False})
    sim.late_succeeded(attempt)


SCENARIOS = {
    'A_reply_missing_revoked': a_reply_missing_then_revoked,
    'B_reply_first_other_success': b_reply_first_then_another_attempt_succeeds,
    'C_success_then_revoked': c_success_before_revoked,
    'D_revoked_then_success': d_revoked_before_success,
}


def run_all() -> list:
    return [run_scenario(name, builder)
            for name, builder in SCENARIOS.items()]
