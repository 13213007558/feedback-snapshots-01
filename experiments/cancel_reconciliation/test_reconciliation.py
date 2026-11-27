"""Broker-free tests locking the cancellation reconciliation behaviour.

Run from the repository root::

    python -m pytest experiments/cancel_reconciliation/test_reconciliation.py -q
    python -m unittest experiments.cancel_reconciliation.test_reconciliation -v

These tests never open a socket or talk to a broker, so they run inside an
environment that forbids local port binding (unlike the Tornado HTTP cases).
"""

import unittest

from experiments.cancel_reconciliation.model import (
    Attempt,
    Channel,
    Ledger,
    Reconciler,
    Verdict,
)
from experiments.cancel_reconciliation.scenarios import SCENARIOS, run_scenario
from experiments.cancel_reconciliation.simulator import ClusterSimulator


class ReconciliationTests(unittest.TestCase):

    def test_http_200_only_proves_local_acceptance_not_interruption(self):
        # An API 200 with no terminal event must never be read as "cancelled".
        ledger = Ledger()
        ledger.append('t1', Channel.API, 'revoke-http', 1.0,
                      payload={'status': 200})
        result = Reconciler().reconcile(ledger, 't1')
        self.assertEqual(result.verdict, Verdict.CANCEL_REQUESTED_ONLY)
        self.assertEqual(result.terminals, {})
        self.assertTrue(any('control-bus reply' in m
                            for m in result.missing_records))

    def test_control_reply_does_not_prove_task_terminal_state(self):
        # Even a delivered worker reply only proves the command was handled.
        ledger = Ledger()
        ledger.append('t2', Channel.API, 'revoke-http', 1.0,
                      payload={'status': 200})
        ledger.append('t2', Channel.CONTROL, 'revoke-reply', 2.0,
                      payload={'worker': 'w1', 'ok': True})
        result = Reconciler().reconcile(ledger, 't2')
        self.assertEqual(result.verdict, Verdict.CANCEL_REQUESTED_ONLY)
        self.assertTrue(result.channel_evidence[Channel.CONTROL.value])

    def test_scenario_a_missing_reply_then_revoked_is_interrupted(self):
        result = run_scenario('A_reply_missing_revoked',
                              SCENARIOS['A_reply_missing_revoked'])
        self.assertEqual(result.reconciliation.verdict,
                         Verdict.INTERRUPTED)
        # No control-channel evidence: the worker reply was never delivered.
        self.assertEqual(
            result.reconciliation.channel_evidence[Channel.CONTROL.value], [])
        self.assertEqual(result.sim.flower_task_view()['state'], 'REVOKED')

    def test_scenario_b_retry_success_under_same_id_is_conflicted(self):
        result = run_scenario('B_reply_first_other_success',
                              SCENARIOS['B_reply_first_other_success'])
        self.assertEqual(result.reconciliation.verdict, Verdict.CONFLICTED)
        # Two distinct attempts, two different terminals, same task id.
        self.assertEqual(set(result.reconciliation.terminals), {0, 1})
        self.assertEqual(result.sim.flower_task_view()['state'], 'SUCCESS')

    def test_scenario_c_and_d_order_swap_both_ambiguous(self):
        for name in ('C_success_then_revoked', 'D_revoked_then_success'):
            result = run_scenario(name, SCENARIOS[name])
            self.assertEqual(result.reconciliation.verdict,
                             Verdict.AMBIGUOUS_TERMINAL)
            # Celery keeps the last-arrived terminal regardless of causal order.
            self.assertEqual(result.sim.flower_task_view()['state'],
                             'SUCCESS')

    def test_late_duplicate_success_does_not_erase_revoked_timestamp(self):
        # Even when state flips to SUCCESS, the revoked timestamp remains in
        # state, which is the extra evidence an audit needs.
        sim = ClusterSimulator(task_id='t-late')
        attempt = Attempt('t-late', 0)
        sim.revoked_attempt(attempt, terminated=True)
        sim.late_succeeded(attempt)
        view = sim.flower_task_view()
        self.assertEqual(view['state'], 'SUCCESS')
        self.assertIsNotNone(view['revoked'])
        self.assertIsNotNone(view['succeeded'])

    def test_success_always_wins_over_revoked_by_celery_precedence(self):
        # task-succeeded (precedence 0) outranks task-revoked (precedence 3),
        # so a later revoked event cannot flip state back once a success is
        # merged, while a late success can flip REVOKED to SUCCESS. The
        # displayed state is therefore not an authoritative cancel proof.
        def build_revoked_first(sim):
            attempt = Attempt(sim.task_id, 0)
            sim.emit('task-received', attempt)
            sim.emit('task-started', attempt)
            sim.emit('task-revoked', attempt, extra={'terminated': True})
            sim.emit('task-succeeded', attempt, extra={'result': 'ok'})

        def build_success_first(sim):
            attempt = Attempt(sim.task_id, 0)
            sim.emit('task-received', attempt)
            sim.emit('task-started', attempt)
            sim.emit('task-succeeded', attempt, extra={'result': 'ok'})
            sim.emit('task-revoked', attempt, extra={'terminated': True})

        revoked_first = run_scenario('order-revoked-first',
                                     build_revoked_first)
        success_first = run_scenario('order-success-first',
                                     build_success_first)
        self.assertEqual(revoked_first.sim.flower_task_view()['state'],
                         'SUCCESS')
        self.assertEqual(success_first.sim.flower_task_view()['state'],
                         'SUCCESS')
        for result in (revoked_first, success_first):
            self.assertIsNotNone(result.sim.flower_task_view()['revoked'])
            self.assertEqual(result.reconciliation.verdict,
                             Verdict.AMBIGUOUS_TERMINAL)

    def test_undecidable_window_spans_accept_to_terminal(self):
        result = run_scenario('A_reply_missing_revoked',
                              SCENARIOS['A_reply_missing_revoked'])
        windows = result.reconciliation.undecidable_windows
        self.assertTrue(windows)
        self.assertLess(windows[0]['from'], windows[0]['to'])

    def test_no_evidence_when_id_unknown(self):
        result = Reconciler().reconcile(Ledger(), 'never-seen')
        self.assertEqual(result.verdict, Verdict.NO_EVIDENCE)

    def test_ledger_is_append_only_and_ordered(self):
        ledger = Ledger()
        for index in range(5):
            ledger.append('t', Channel.EVENT, 'task-received', float(index))
        rows = ledger.records('t')
        self.assertEqual([row.seq for row in rows], [0, 1, 2, 3, 4])
        self.assertEqual(rows, sorted(rows, key=lambda row: row.observed_at))


if __name__ == '__main__':
    unittest.main()
