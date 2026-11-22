import datetime
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from django.contrib.auth import get_user_model
from django.db import OperationalError, connections
from django.test import (
    RequestFactory,
    TestCase,
    TransactionTestCase,
)

from simple_history.attribution import (
    get_context_history_user,
    history_user_context,
)
from simple_history.middleware import _context_manager
from simple_history.tests.models import Poll
from simple_history.utils import bulk_create_with_history, bulk_update_with_history

User = get_user_model()
today = datetime.datetime(2020, 1, 1, 10, 0)


def _request_for(user):
    request = RequestFactory().post("/")
    request.user = user
    return request


class HistoryUserContextTestCase(TestCase):
    def setUp(self):
        self.service = User.objects.create_user("service", "service@example.com")
        self.approver = User.objects.create_user("approver", "approver@example.com")
        self.alice = User.objects.create_user("alice", "alice@example.com")
        self.bob = User.objects.create_user("bob", "bob@example.com")

    def create_poll(self, question="question"):
        poll = Poll.objects.create(question=question, pub_date=today)
        return poll.history.get()

    def test_context_attributes_service_identity(self):
        with history_user_context(user=self.service):
            record = self.create_poll()

        self.assertEqual(record.history_user_id, self.service.id)

    def test_approver_is_recorded_as_author(self):
        with history_user_context(user=self.service, approver=self.approver):
            record = self.create_poll()

        self.assertEqual(record.history_user_id, self.approver.id)

    def test_context_yields_effective_author(self):
        with history_user_context(user=self.service, approver=self.approver) as author:
            self.assertEqual(author, self.approver)

        with history_user_context(user=self.service) as author:
            self.assertEqual(author, self.service)

    def test_context_author_takes_precedence_over_request_user(self):
        with _context_manager(_request_for(self.alice)):
            with history_user_context(user=self.service, approver=self.approver):
                record = self.create_poll()

        self.assertEqual(record.history_user_id, self.approver.id)

    def test_explicit_instance_user_still_wins(self):
        poll = Poll(question="question", pub_date=today)
        poll._history_user = self.alice

        with history_user_context(user=self.service, approver=self.approver):
            poll.save()

        self.assertEqual(poll.history.get().history_user_id, self.alice.id)

    def test_context_is_cleared_after_exit(self):
        with history_user_context(user=self.service):
            self.assertEqual(get_context_history_user(), self.service)

        self.assertIsNone(get_context_history_user())
        self.assertIsNone(self.create_poll().history_user_id)

    def test_context_is_cleared_when_block_raises(self):
        with self.assertRaisesRegex(RuntimeError, "boom"):
            with history_user_context(user=self.service):
                raise RuntimeError("boom")

        self.assertIsNone(get_context_history_user())
        self.assertIsNone(self.create_poll().history_user_id)

    def test_nested_contexts_restore_previous_author(self):
        with history_user_context(user=self.service):
            with history_user_context(user=self.service, approver=self.approver):
                self.assertEqual(get_context_history_user(), self.approver)

            self.assertEqual(get_context_history_user(), self.service)
            record = self.create_poll()

        self.assertEqual(record.history_user_id, self.service.id)

    def test_context_is_not_shared_with_a_later_request(self):
        with history_user_context(user=self.service, approver=self.approver):
            self.create_poll("imported")

        with _context_manager(_request_for(self.bob)):
            record = self.create_poll("after import")

        self.assertEqual(record.history_user_id, self.bob.id)

    def test_bulk_create_uses_context_author(self):
        with history_user_context(user=self.service, approver=self.approver):
            polls = bulk_create_with_history(
                [Poll(question="1", pub_date=today)], Poll
            )

        self.assertEqual(polls[0].history.get().history_user_id, self.approver.id)

    def test_bulk_update_uses_context_author(self):
        poll = Poll.objects.create(question="before", pub_date=today)

        with history_user_context(user=self.service):
            poll.question = "after"
            bulk_update_with_history([poll], Poll, ["question"])

        self.assertEqual(poll.history.latest().history_user_id, self.service.id)

    def test_bulk_default_user_wins_over_context(self):
        with history_user_context(user=self.service):
            bulk_create_with_history(
                [Poll(question="1", pub_date=today)],
                Poll,
                default_user=self.alice,
            )

        self.assertEqual(Poll.history.get().history_user_id, self.alice.id)

    def test_bulk_explicit_instance_user_wins_over_context(self):
        poll = Poll(question="1", pub_date=today)
        poll._history_user = self.alice

        with history_user_context(user=self.service):
            bulk_create_with_history([poll], Poll)

        self.assertEqual(Poll.history.get().history_user_id, self.alice.id)


class ImportTaskAttributionTestCase(TestCase):
    """An import task runs as a service identity, sometimes with an approver."""

    def setUp(self):
        self.service = User.objects.create_user("service", "service@example.com")
        self.approver = User.objects.create_user("approver", "approver@example.com")

    def run_import(self, *, approver=None):
        """Mimic a loader that does not know about requests."""
        with history_user_context(user=self.service, approver=approver):
            for index in range(3):
                Poll.objects.create(question=f"row {index}", pub_date=today)

            for poll in Poll.objects.order_by("id"):
                poll.question = poll.question.upper()
                poll.save()

    def test_import_without_approval_is_attributed_to_service(self):
        self.run_import()

        self.assertEqual(
            {record.history_user_id for record in Poll.history.all()},
            {self.service.id},
        )

    def test_import_with_approval_is_attributed_to_approver(self):
        self.run_import(approver=self.approver)

        self.assertEqual(
            {record.history_user_id for record in Poll.history.all()},
            {self.approver.id},
        )

    def test_import_without_approval_does_not_fall_back_to_get_user(self):
        # Poll has no get_user; without the context the author would be unset.
        with history_user_context(user=self.service):
            Poll.objects.create(question="row", pub_date=today)

        self.assertEqual(Poll.history.get().history_user_id, self.service.id)


class ConcurrentAttributionTestCase(TransactionTestCase):
    """Run two request users and one import task at the same time.

    The request users must keep their own attribution even while the import
    task declares an author, and the import author must be gone once the task
    context exits.
    """

    def setUp(self):
        self.alice = User.objects.create_user("alice", "alice@example.com")
        self.bob = User.objects.create_user("bob", "bob@example.com")
        self.service = User.objects.create_user("service", "service@example.com")
        self.approver = User.objects.create_user("approver", "approver@example.com")
        self.barrier = threading.Barrier(3)
        self.results = {}

    def _save_in_request(self, user, key):
        try:
            with _context_manager(_request_for(user)):
                self.barrier.wait(timeout=10)
                record = self._create_poll(key)
                self.results[key] = record.history_user_id
        finally:
            connections.close_all()

    def _save_in_import_task(self):
        try:
            with history_user_context(user=self.service, approver=self.approver):
                self.barrier.wait(timeout=10)
                record = self._create_poll("import")
                self.results["import"] = record.history_user_id
                self.results["inside"] = get_context_history_user()
            self.results["after"] = get_context_history_user()
        finally:
            connections.close_all()

    def _create_poll(self, question):
        for attempt in range(100):
            try:
                poll = Poll.objects.create(question=question, pub_date=today)
                return poll.history.get()
            except OperationalError as exc:
                if "locked" not in str(exc).lower() or attempt == 99:
                    raise
                time.sleep(0.02)

    def test_concurrent_requests_and_import_keep_separate_authors(self):
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(self._save_in_request, self.alice, "alice"),
                executor.submit(self._save_in_request, self.bob, "bob"),
                executor.submit(self._save_in_import_task),
            ]
            for future in futures:
                future.result(timeout=30)

        self.assertEqual(self.results["alice"], self.alice.id)
        self.assertEqual(self.results["bob"], self.bob.id)
        self.assertEqual(self.results["import"], self.approver.id)
        self.assertEqual(self.results["inside"], self.approver)
        self.assertIsNone(self.results["after"])

        # A request handled after the import task does not inherit its author.
        with _context_manager(_request_for(self.alice)):
            record = self._create_poll("after import")

        self.assertEqual(record.history_user_id, self.alice.id)
        self.assertEqual(
            sorted(
                Poll.history.values_list("question", "history_user_id"),
            ),
            sorted(
                [
                    ("alice", self.alice.id),
                    ("bob", self.bob.id),
                    ("import", self.approver.id),
                    ("after import", self.alice.id),
                ]
            ),
        )
