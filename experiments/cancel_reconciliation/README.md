# Cancel / revoke reconciliation experiments

Broker-free, in-process experiments showing why a Flower revoke "success"
cannot by itself prove that a task attempt was interrupted. The design and the
on-call runbook (Chinese) are in `RECONCILIATION.zh.md`.

## Three evidence channels (kept separate on purpose)

- `api`     - `POST /api/task/revoke/<id>` HTTP reply; only proves local
              acceptance because Flower calls `control.revoke` without
              `reply=True` and always returns 200.
- `control` - worker control-bus reply (only present with `reply=True`);
              proves a worker handled the command, not the task terminal.
- `event`   - `task-*` events merged by the real `flower.events.EventsState`;
              describe the task's own state but are async, reorderable and
              share one id across retries / late duplicate results.

## Run

From the repository root (no broker, no socket binding):

```bash
python -m experiments.cancel_reconciliation.run_experiments
python -m pytest experiments/cancel_reconciliation/test_reconciliation.py -q
```

## Layout

- `model.py`       - append-only ledger, evidence records, pure reconciler and
                     verdicts (`INTERRUPTED`, `SUCCEEDED`, `CONFLICTED`,
                     `AMBIGUOUS_TERMINAL`, `CANCEL_REQUESTED_ONLY`, `NO_EVIDENCE`).
- `simulator.py`   - deterministic fake control bus driving the real Celery
                     `EventsState`, so message loss/order/duplication is exact.
- `scenarios.py`   - the four requested scenarios A-D.
- `run_experiments.py` - CLI report: observation points, supported conclusions,
                     undecidable windows, additional records required.
- `test_reconciliation.py` - broker-free pytest cases locking the behaviour.
