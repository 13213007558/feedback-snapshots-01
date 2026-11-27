"""Re-runnable CLI: prints observations, supported conclusions and blind spots.

Usage (from the repository root)::

    python -m experiments.cancel_reconciliation.run_experiments

The run is fully deterministic and broker-free; it only needs celery, tornado
and the flower package on the path (the project virtualenv already has them).
"""

from __future__ import annotations

from .model import Channel, Verdict
from .scenarios import SCENARIOS, run_scenario

VERDICT_EXPLANATION = {
    Verdict.INTERRUPTED:
        'At least one attempt ended in task-revoked; an interruption is '
        'evidenced by the event channel only.',
    Verdict.SUCCEEDED:
        'Only success-class terminals observed; the task ran to completion.',
    Verdict.CONFLICTED:
        'Both revoked and succeeded observed on DIFFERENT attempts (retry or '
        'late result under the same id). A single yes/no needs attempt ids.',
    Verdict.AMBIGUOUS_TERMINAL:
        'Two different terminals arrived for ONE attempt. Celery displays the '
        'last-arrived state, but causal order is unknowable from the events; '
        'the displayed state must not be treated as ground truth.',
    Verdict.CANCEL_REQUESTED_ONLY:
        'Cancel was accepted and/or a worker handled the command, but no '
        'terminal event proves what the task itself did.',
    Verdict.NO_EVIDENCE:
        'No observation recorded for the task id.',
}


def _print_scenario(result) -> None:
    rec = result.reconciliation
    print('=' * 78)
    print(f'SCENARIO {result.name}')
    print('-' * 78)
    print('Observation points (arrival order):')
    for row in result.sim.ledger.records(result.sim.task_id):
        tag = row.channel.value.upper().ljust(7)
        extra = ''
        if row.channel == Channel.EVENT:
            extra = f' attempt={row.attempt_no} clock={row.clock}'
            if row.duplicate:
                extra += ' [DUPLICATE]'
        print(f'  t={row.observed_at:4.0f} {tag} {row.kind}{extra}')

    print('\nWhat Flower would now display for the task id:')
    view = result.sim.flower_task_view()
    print(f'  state={view["state"]}  revoked_ts={view["revoked"]}  '
          f'succeeded_ts={view["succeeded"]}')

    print('\nConclusions each channel independently supports:')
    for channel, notes in rec.channel_evidence.items():
        if notes:
            for note in notes:
                print(f'  [{channel:7}] {note}')
        else:
            print(f'  [{channel:7}] (no evidence)')

    print(f'\nReconciliation verdict: {rec.verdict.value}')
    print(f'  -> {VERDICT_EXPLANATION[rec.verdict]}')

    if rec.undecidable_windows:
        print('\nUndecidable windows:')
        for window in rec.undecidable_windows:
            print(f'  t={window["from"]:.0f}..t={window["to"]:.0f}: '
                  f'{window["reason"]}')
    else:
        print('\nUndecidable windows: none (a terminal was always present)')

    print('\nAdditional records required to close the gap:')
    for item in rec.missing_records:
        print(f'  - {item}')
    print()


def main() -> int:
    print('Flower cancel/revoke reconciliation - reproducible local experiment')
    print('Three evidence channels are kept separate: '
          'api (HTTP accept) | control (worker command reply) | '
          'event (task state)\n')
    for name, builder in SCENARIOS.items():
        _print_scenario(run_scenario(name, builder))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
