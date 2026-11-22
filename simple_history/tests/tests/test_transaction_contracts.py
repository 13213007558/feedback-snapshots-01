"""
Transaction contract tests for auditing via django-simple-history.

These tests pin down what a write leaves behind in the business table and
the history table - and what signal receivers observe - for each outcome:

* the database reports success (commit),
* the whole batch fails (rollback),
* a single signal receiver raises mid-write.

Every test reads back from the real tables (``Poll`` /
``PollWithUniqueQuestion`` and their history tables) and cross-checks the
signals actually observed, so the suite can detect the dangerous divergence
where the business change was never committed but a receiver already
treated the history record as fact (or vice versa).
"""

from contextlib import contextmanager
from unittest.mock import patch

from django.db import IntegrityError, transaction
from django.test import TransactionTestCase
from django.utils import timezone

from simple_history.manager import HistoryManager
from simple_history.signals import (
    post_create_historical_record,
    pre_create_historical_record,
)
from simple_history.tests.models import Poll, PollWithUniqueQuestion
from simple_history.utils import bulk_update_with_history


class BatchAbort(Exception):
    """Simulates the surrounding batch failing after a write."""


class ReceiverBlowup(Exception):
    """Simulates a single signal receiver raising mid-write."""


@contextmanager
def recorded_signals(signal):
    """Collect every emission of ``signal`` for later cross-checking."""
    observed = []

    def receiver(sender, **kwargs):
        observed.append(kwargs)

    signal.connect(receiver, weak=False)
    try:
        yield observed
    finally:
        signal.disconnect(receiver)


def raising_receiver(sender, **kwargs):
    raise ReceiverBlowup("receiver treated the write as fact and failed")


def make_poll(question="What is up?"):
    return Poll(question=question, pub_date=timezone.now())


class RegularSaveTransactionContractTest(TransactionTestCase):
    """Contract for ``instance.save()`` on a model with HistoricalRecords."""

    def test_commit_leaves_business_row_history_row_and_matching_signal(self):
        with recorded_signals(post_create_historical_record) as observed:
            with transaction.atomic():
                poll = make_poll()
                poll.save()

        # Read back from the real tables: both rows committed.
        self.assertEqual(Poll.objects.count(), 1)
        history = Poll.history.get()
        self.assertEqual(history.history_type, "+")
        self.assertEqual(history.question, poll.question)

        # The observed signal describes exactly what was committed.
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0]["instance"].pk, poll.pk)
        self.assertEqual(observed[0]["history_instance"].id, history.id)

    def test_rollback_leaves_no_rows_but_receiver_observed_phantom_history(self):
        with recorded_signals(post_create_historical_record) as observed:
            with self.assertRaises(BatchAbort):
                with transaction.atomic():
                    make_poll().save()
                    raise BatchAbort

        # Read back: neither the business row nor the history row exists.
        self.assertFalse(Poll.objects.exists())
        self.assertFalse(Poll.history.exists())

        # ...yet the receiver already observed the history record and could
        # have treated it as fact. The signal payload is a phantom: it must
        # never be trusted without a committed read-back.
        self.assertEqual(len(observed), 1)
        phantom = observed[0]["history_instance"]
        self.assertFalse(Poll.history.filter(id=phantom.id).exists())

    def test_pre_signal_error_in_autocommit_leaves_business_row_without_history(
        self,
    ):
        pre_create_historical_record.connect(raising_receiver, weak=False)
        self.addCleanup(pre_create_historical_record.disconnect, raising_receiver)

        poll = make_poll()
        with self.assertRaises(ReceiverBlowup):
            poll.save()

        # The caller saw a failure, but in autocommit the business row was
        # already committed while the history row was never written:
        # an audit gap that only a table read-back reveals.
        self.assertTrue(Poll.objects.filter(pk=poll.pk).exists())
        self.assertFalse(Poll.history.exists())

    def test_post_signal_error_in_autocommit_leaves_both_rows_despite_error(self):
        post_create_historical_record.connect(raising_receiver, weak=False)
        self.addCleanup(post_create_historical_record.disconnect, raising_receiver)

        poll = make_poll()
        with self.assertRaises(ReceiverBlowup):
            poll.save()

        # The caller saw a failure, yet both rows committed: retrying the
        # "failed" write would duplicate the audit trail.
        self.assertTrue(Poll.objects.filter(pk=poll.pk).exists())
        self.assertEqual(Poll.history.count(), 1)

    def test_signal_error_inside_atomic_rolls_back_business_and_history(self):
        pre_create_historical_record.connect(raising_receiver, weak=False)
        self.addCleanup(pre_create_historical_record.disconnect, raising_receiver)

        with self.assertRaises(ReceiverBlowup):
            with transaction.atomic():
                make_poll().save()

        # Wrapping the save in a transaction restores all-or-nothing:
        # the receiver's exception rolls back both tables.
        self.assertFalse(Poll.objects.exists())
        self.assertFalse(Poll.history.exists())

    def test_on_commit_receiver_only_observes_committed_history(self):
        committed = []

        with transaction.atomic():
            poll = make_poll()
            poll.save()
            transaction.on_commit(lambda: committed.append(poll.pk))
        self.assertEqual(committed, [poll.pk])
        self.assertTrue(Poll.history.filter(id__isnull=False).exists())

        # On rollback the deferred receiver never runs, so it can never
        # mistake an uncommitted history record for fact.
        committed.clear()
        with self.assertRaises(BatchAbort):
            with transaction.atomic():
                make_poll("Rolled back?").save()
                transaction.on_commit(lambda: committed.append("phantom"))
                raise BatchAbort
        self.assertEqual(committed, [])
        self.assertFalse(Poll.objects.filter(question="Rolled back?").exists())


class BulkUpdateTransactionContractTest(TransactionTestCase):
    """Contract for ``bulk_update_with_history()``."""

    def test_commit_updates_business_rows_and_writes_matching_history(self):
        make_poll("q0").save()
        make_poll("q1").save()
        polls = list(Poll.objects.order_by("id"))
        for index, poll in enumerate(polls):
            poll.question = f"updated {index}"

        with recorded_signals(post_create_historical_record) as observed:
            rows_updated = bulk_update_with_history(polls, Poll, fields=["question"])

        self.assertEqual(rows_updated, 2)
        # Read back the business table.
        self.assertEqual(
            list(Poll.objects.order_by("id").values_list("question", flat=True)),
            ["updated 0", "updated 1"],
        )
        # Read back the history table: one "~" record per updated row,
        # carrying the committed values.
        updates = list(Poll.history.filter(history_type="~").order_by("id"))
        self.assertEqual(len(updates), 2)
        self.assertEqual(
            [entry.question for entry in updates], ["updated 0", "updated 1"]
        )
        # The bulk path emits no post_create_historical_record signals
        # (covered in detail below).
        self.assertEqual(observed, [])

    def test_batch_integrity_error_rolls_back_business_and_history(self):
        poll1 = PollWithUniqueQuestion.objects.create(
            question="q1", pub_date=timezone.now()
        )
        poll2 = PollWithUniqueQuestion.objects.create(
            question="q2", pub_date=timezone.now()
        )
        poll1.question = poll2.question = "duplicate"

        with self.assertRaises(IntegrityError):
            bulk_update_with_history(
                [poll1, poll2], PollWithUniqueQuestion, ["question"]
            )

        # Read back: the business table kept the original values...
        self.assertEqual(
            PollWithUniqueQuestion.objects.get(pk=poll1.pk).question, "q1"
        )
        self.assertEqual(
            PollWithUniqueQuestion.objects.get(pk=poll2.pk).question, "q2"
        )
        # ...and no "~" history leaked from the aborted batch.
        self.assertFalse(
            PollWithUniqueQuestion.history.filter(history_type="~").exists()
        )

    def test_history_step_failure_rolls_back_business_changes(self):
        make_poll("q0").save()
        make_poll("q1").save()
        polls = list(Poll.objects.order_by("id"))
        for poll in polls:
            poll.question = "changed"

        # The history write fails after the business UPDATE already
        # succeeded inside the shared transaction.
        with patch.object(
            HistoryManager,
            "bulk_history_create",
            side_effect=ReceiverBlowup("history write failed"),
        ):
            with self.assertRaises(ReceiverBlowup):
                bulk_update_with_history(polls, Poll, fields=["question"])

        # Read back: the business UPDATE was rolled back with the batch...
        self.assertEqual(
            list(Poll.objects.order_by("id").values_list("question", flat=True)),
            ["q0", "q1"],
        )
        # ...and no partial history survived.
        self.assertFalse(Poll.history.filter(history_type="~").exists())

    def test_bulk_update_emits_no_history_signals(self):
        make_poll("q0").save()
        polls = list(Poll.objects.order_by("id"))
        for poll in polls:
            poll.question = "changed"

        with (
            recorded_signals(pre_create_historical_record) as observed_pre,
            recorded_signals(post_create_historical_record) as observed_post,
        ):
            bulk_update_with_history(polls, Poll, fields=["question"])

        # Reverse divergence: the history table gained committed rows...
        self.assertEqual(Poll.history.filter(history_type="~").count(), 1)
        # ...but no receiver was notified. Consumers that treat the signals
        # as their source of truth silently miss bulk writes; they must
        # read the history table instead.
        self.assertEqual(observed_pre, [])
        self.assertEqual(observed_post, [])
