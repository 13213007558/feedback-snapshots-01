from contextlib import contextmanager
from datetime import datetime, timedelta
from io import StringIO
from unittest.mock import patch

from django.core import management
from django.core.management.base import CommandError
from django.test import TestCase, override_settings

from simple_history import models as sh_models
from simple_history.management.commands import (
    clean_duplicate_history,
    clean_old_history,
    populate_history,
)

from ..models import (
    Book,
    CustomManagerNameModel,
    Place,
    Poll,
    PollWithCustomManager,
    PollWithExcludeFields,
    RecordWithComplianceFreeze,
    RecordWithComplianceFreezeInDifferentDb,
    Restaurant,
)
from .utils import (
    OTHER_DB_NAME,
    database_router_override_settings_compliance_freeze_in_diff_db,
)


@contextmanager
def replace_registry(new_value=None):
    hidden_registry = sh_models.registered_models
    sh_models.registered_models = new_value or {}
    try:
        yield
    except Exception:
        raise
    finally:
        sh_models.registered_models = hidden_registry


class TestPopulateHistory(TestCase):
    command_name = "populate_history"
    command_error = (management.CommandError, SystemExit)

    def test_no_args(self):
        out = StringIO()
        management.call_command(self.command_name, stdout=out, stderr=StringIO())
        self.assertIn(populate_history.Command.COMMAND_HINT, out.getvalue())

    def test_bad_args(self):
        test_data = (
            (populate_history.Command.MODEL_NOT_HISTORICAL, ("tests.place",)),
            (populate_history.Command.MODEL_NOT_FOUND, ("invalid.model",)),
            (populate_history.Command.MODEL_NOT_FOUND, ("bad_key",)),
        )
        for msg, args in test_data:
            out = StringIO()
            self.assertRaises(
                self.command_error,
                management.call_command,
                self.command_name,
                *args,
                stdout=StringIO(),
                stderr=out,
            )
            self.assertIn(msg, out.getvalue())

    def test_auto_populate(self):
        Poll.objects.create(question="Will this populate?", pub_date=datetime.now())
        Poll.history.all().delete()
        management.call_command(
            self.command_name, auto=True, stdout=StringIO(), stderr=StringIO()
        )
        self.assertEqual(Poll.history.all().count(), 1)

    def test_populate_with_custom_batch_size(self):
        Poll.objects.create(question="Will this populate?", pub_date=datetime.now())
        Poll.history.all().delete()
        management.call_command(
            self.command_name,
            auto=True,
            batchsize=500,
            stdout=StringIO(),
            stderr=StringIO(),
        )
        self.assertEqual(Poll.history.all().count(), 1)

    def test_specific_populate(self):
        Poll.objects.create(question="Will this populate?", pub_date=datetime.now())
        Poll.history.all().delete()
        Book.objects.create(isbn="9780007117116")
        Book.history.all().delete()
        management.call_command(
            self.command_name, "tests.book", stdout=StringIO(), stderr=StringIO()
        )
        self.assertEqual(Book.history.all().count(), 1)
        self.assertEqual(Poll.history.all().count(), 0)

    def test_failing_wont_save(self):
        Poll.objects.create(question="Will this populate?", pub_date=datetime.now())
        Poll.history.all().delete()
        self.assertRaises(
            self.command_error,
            management.call_command,
            self.command_name,
            "tests.poll",
            "tests.invalid_model",
            stdout=StringIO(),
            stderr=StringIO(),
        )
        self.assertEqual(Poll.history.all().count(), 0)

    def test_multi_table(self):
        data = {"rating": 5, "name": "Tea 'N More"}
        Restaurant.objects.create(**data)
        Restaurant.updates.all().delete()
        management.call_command(
            self.command_name, "tests.restaurant", stdout=StringIO(), stderr=StringIO()
        )
        update_record = Restaurant.updates.all()[0]
        for attr, value in data.items():
            self.assertEqual(getattr(update_record, attr), value)

    def test_existing_objects(self):
        data = {"rating": 5, "name": "Tea 'N More"}
        out = StringIO()
        Restaurant.objects.create(**data)
        pre_call_count = Restaurant.updates.count()
        management.call_command(
            self.command_name, "tests.restaurant", stdout=StringIO(), stderr=out
        )
        self.assertEqual(Restaurant.updates.count(), pre_call_count)
        self.assertIn(populate_history.Command.EXISTING_HISTORY_FOUND, out.getvalue())

    def test_no_historical(self):
        out = StringIO()
        with replace_registry({"test_place": Place}):
            management.call_command(self.command_name, auto=True, stdout=out)
        self.assertIn(populate_history.Command.NO_REGISTERED_MODELS, out.getvalue())

    def test_batch_processing_with_batch_size_less_than_total(self):
        data = [
            Poll(id=1, question="Question 1", pub_date=datetime.now()),
            Poll(id=2, question="Question 2", pub_date=datetime.now()),
            Poll(id=3, question="Question 3", pub_date=datetime.now()),
            Poll(id=4, question="Question 4", pub_date=datetime.now()),
        ]
        Poll.objects.bulk_create(data)

        management.call_command(
            self.command_name,
            auto=True,
            batchsize=3,
            stdout=StringIO(),
            stderr=StringIO(),
        )

        self.assertEqual(Poll.history.count(), 4)

    def test_stdout_not_printed_when_verbosity_is_0(self):
        out = StringIO()
        Poll.objects.create(question="Question 1", pub_date=datetime.now())

        management.call_command(
            self.command_name,
            auto=True,
            batchsize=3,
            stdout=out,
            stderr=StringIO(),
            verbosity=0,
        )

        self.assertEqual(out.getvalue(), "")

    def test_stdout_printed_when_verbosity_is_not_specified(self):
        out = StringIO()
        Poll.objects.create(question="Question 1", pub_date=datetime.now())

        management.call_command(
            self.command_name, auto=True, batchsize=3, stdout=out, stderr=StringIO()
        )

        self.assertNotEqual(out.getvalue(), "")

    def test_excluded_fields(self):
        poll = PollWithExcludeFields.objects.create(
            question="Will this work?", pub_date=datetime.now()
        )
        PollWithExcludeFields.history.all().delete()
        management.call_command(
            self.command_name,
            "tests.pollwithexcludefields",
            auto=True,
            stdout=StringIO(),
            stderr=StringIO(),
        )
        initial_history_record = PollWithExcludeFields.history.all()[0]
        self.assertEqual(initial_history_record.question, poll.question)


class TestCleanDuplicateHistory(TestCase):
    command_name = "clean_duplicate_history"
    command_error = (management.CommandError, SystemExit)

    def test_no_args(self):
        out = StringIO()
        management.call_command(self.command_name, stdout=out, stderr=StringIO())
        self.assertIn(clean_duplicate_history.Command.COMMAND_HINT, out.getvalue())

    def test_bad_args(self):
        test_data = (
            (clean_duplicate_history.Command.MODEL_NOT_HISTORICAL, ("tests.place",)),
            (clean_duplicate_history.Command.MODEL_NOT_FOUND, ("invalid.model",)),
            (clean_duplicate_history.Command.MODEL_NOT_FOUND, ("bad_key",)),
        )
        for msg, args in test_data:
            out = StringIO()
            self.assertRaises(
                self.command_error,
                management.call_command,
                self.command_name,
                *args,
                stdout=StringIO(),
                stderr=out,
            )
            self.assertIn(msg, out.getvalue())

    def test_no_historical(self):
        out = StringIO()
        with replace_registry({"test_place": Place}):
            management.call_command(self.command_name, auto=True, stdout=out)
        self.assertIn(
            clean_duplicate_history.Command.NO_REGISTERED_MODELS, out.getvalue()
        )

    def test_auto_dry_run(self):
        p = Poll.objects.create(
            question="Will this be deleted?", pub_date=datetime.now()
        )
        p.save()

        # not related to dry_run test, just for increasing coverage :)
        # create instance with single-entry history older than "minutes"
        # so it is skipped
        p = Poll.objects.create(
            question="Will this be deleted?", pub_date=datetime.now()
        )
        h = p.history.first()
        h.history_date -= timedelta(hours=1)
        h.save()

        self.assertEqual(Poll.history.all().count(), 3)
        out = StringIO()
        management.call_command(
            self.command_name,
            auto=True,
            minutes=50,
            dry=True,
            stdout=out,
            stderr=StringIO(),
        )
        self.assertEqual(
            out.getvalue(),
            "Removed 1 historical records for "
            "<class 'simple_history.tests.models.Poll'>\n",
        )
        self.assertEqual(Poll.history.all().count(), 3)

    def test_auto_cleanup(self):
        p = Poll.objects.create(
            question="Will this be deleted?", pub_date=datetime.now()
        )
        self.assertEqual(Poll.history.all().count(), 1)
        p.save()
        self.assertEqual(Poll.history.all().count(), 2)
        p.question = "Maybe this one won't...?"
        p.save()
        self.assertEqual(Poll.history.all().count(), 3)
        out = StringIO()
        management.call_command(
            self.command_name, auto=True, stdout=out, stderr=StringIO()
        )
        self.assertEqual(
            out.getvalue(),
            "Removed 1 historical records for "
            "<class 'simple_history.tests.models.Poll'>\n",
        )
        self.assertEqual(Poll.history.all().count(), 2)

    def _prepare_cleanup_manager(self):
        one = PollWithCustomManager._default_manager.create(
            question="This is hidden in default manager",
            pub_date=datetime.now(),
            hidden=True,
        )
        one.save()

        two = PollWithCustomManager._default_manager.create(
            question="This is visible in default manager", pub_date=datetime.now()
        )
        two.save()

        self.assertEqual(PollWithCustomManager.history.count(), 4)

    def test_auto_cleanup_defaultmanager(self):
        self._prepare_cleanup_manager()

        out = StringIO()
        management.call_command(
            self.command_name, auto=True, stdout=out, stderr=StringIO()
        )
        self.assertEqual(
            out.getvalue(),
            "Removed 1 historical records for "
            "<class 'simple_history.tests.models.PollWithCustomManager'>\n",
        )
        self.assertEqual(PollWithCustomManager.history.count(), 3)

    def test_auto_cleanup_basemanage(self):
        self._prepare_cleanup_manager()

        out = StringIO()
        management.call_command(
            self.command_name,
            auto=True,
            base_manager=True,
            stdout=out,
            stderr=StringIO(),
        )
        self.assertEqual(
            out.getvalue(),
            "Removed 1 historical records for "
            "<class 'simple_history.tests.models.PollWithCustomManager'>\n"
            "Removed 1 historical records for "
            "<class 'simple_history.tests.models.PollWithCustomManager'>\n",
        )
        self.assertEqual(PollWithCustomManager.history.count(), 2)

    def test_auto_cleanup_verbose(self):
        p = Poll.objects.create(
            question="Will this be deleted?", pub_date=datetime.now()
        )
        self.assertEqual(Poll.history.all().count(), 1)
        p.save()
        p.question = "Maybe this one won't...?"
        p.save()
        self.assertEqual(Poll.history.all().count(), 3)
        out = StringIO()
        management.call_command(
            self.command_name,
            "tests.poll",
            auto=True,
            verbosity=2,
            stdout=out,
            stderr=StringIO(),
        )
        self.assertEqual(
            out.getvalue(),
            "<class 'simple_history.tests.models.Poll'> has 3 historical entries\n"
            "Removed 1 historical records for "
            "<class 'simple_history.tests.models.Poll'>\n",
        )
        self.assertEqual(Poll.history.all().count(), 2)

    def test_auto_cleanup_dated(self):
        the_time_is_now = datetime.now()
        p = Poll.objects.create(
            question="Will this be deleted?", pub_date=the_time_is_now
        )
        self.assertEqual(Poll.history.all().count(), 1)
        p.save()
        p.save()
        self.assertEqual(Poll.history.all().count(), 3)
        p.question = "Or this one...?"
        p.save()
        p.save()
        self.assertEqual(Poll.history.all().count(), 5)

        for h in Poll.history.all()[2:]:
            h.history_date -= timedelta(hours=1)
            h.save()

        management.call_command(
            self.command_name,
            auto=True,
            minutes=50,
            stdout=StringIO(),
            stderr=StringIO(),
        )
        self.assertEqual(Poll.history.all().count(), 4)

    def test_auto_cleanup_dated_extra_one(self):
        the_time_is_now = datetime.now()
        p = Poll.objects.create(
            question="Will this be deleted?", pub_date=the_time_is_now
        )
        self.assertEqual(Poll.history.all().count(), 1)
        p.save()
        p.save()
        self.assertEqual(Poll.history.all().count(), 3)
        p.question = "Or this one...?"
        p.save()
        p.save()
        p.save()
        p.save()
        self.assertEqual(Poll.history.all().count(), 7)

        for h in Poll.history.all()[2:]:
            h.history_date -= timedelta(hours=1)
            h.save()

        management.call_command(
            self.command_name,
            auto=True,
            minutes=50,
            stdout=StringIO(),
            stderr=StringIO(),
        )
        # even though only the last 2 entries match the date range
        # the "extra_one" (the record before the oldest match)
        # is identical to the oldest match, so oldest match is deleted
        self.assertEqual(Poll.history.all().count(), 5)

    def test_auto_cleanup_custom_history_field(self):
        m = CustomManagerNameModel.objects.create(name="John")
        self.assertEqual(CustomManagerNameModel.log.all().count(), 1)
        m.save()
        self.assertEqual(CustomManagerNameModel.log.all().count(), 2)
        m.name = "Ivan"
        m.save()
        self.assertEqual(CustomManagerNameModel.log.all().count(), 3)
        out = StringIO()
        management.call_command(
            self.command_name, auto=True, stdout=out, stderr=StringIO()
        )
        self.assertEqual(
            out.getvalue(),
            "Removed 1 historical records for "
            "<class 'simple_history.tests.models.CustomManagerNameModel'>\n",
        )
        self.assertEqual(CustomManagerNameModel.log.all().count(), 2)

    def test_auto_cleanup_with_excluded_fields(self):
        p = Poll.objects.create(
            question="Will this be deleted?", pub_date=datetime.now()
        )
        self.assertEqual(Poll.history.all().count(), 1)
        p.pub_date = p.pub_date + timedelta(days=1)
        p.save()
        self.assertEqual(Poll.history.all().count(), 2)
        out = StringIO()
        management.call_command(
            self.command_name,
            auto=True,
            excluded_fields=("pub_date",),
            stdout=out,
            stderr=StringIO(),
        )
        self.assertEqual(
            out.getvalue(),
            "Removed 1 historical records for "
            "<class 'simple_history.tests.models.Poll'>\n",
        )
        self.assertEqual(Poll.history.all().count(), 1)

    def test_auto_cleanup_for_model_with_excluded_fields(self):
        p = PollWithExcludeFields.objects.create(
            question="Will this be deleted?", pub_date=datetime.now()
        )
        self.assertEqual(PollWithExcludeFields.history.all().count(), 1)
        p.pub_date = p.pub_date + timedelta(days=1)
        p.save()
        self.assertEqual(PollWithExcludeFields.history.all().count(), 2)
        out = StringIO()
        management.call_command(
            self.command_name, auto=True, stdout=out, stderr=StringIO()
        )
        self.assertEqual(
            out.getvalue(),
            "Removed 1 historical records for "
            "<class 'simple_history.tests.models.PollWithExcludeFields'>\n",
        )
        self.assertEqual(PollWithExcludeFields.history.all().count(), 1)


class TestCleanOldHistory(TestCase):
    command_name = "clean_old_history"
    command_error = (management.CommandError, SystemExit)

    def test_no_args(self):
        out = StringIO()
        management.call_command(self.command_name, stdout=out, stderr=StringIO())
        self.assertIn(clean_old_history.Command.COMMAND_HINT, out.getvalue())

    def test_bad_args(self):
        test_data = (
            (clean_old_history.Command.MODEL_NOT_HISTORICAL, ("tests.place",)),
            (clean_old_history.Command.MODEL_NOT_FOUND, ("invalid.model",)),
            (clean_old_history.Command.MODEL_NOT_FOUND, ("bad_key",)),
        )
        for msg, args in test_data:
            out = StringIO()
            self.assertRaises(
                self.command_error,
                management.call_command,
                self.command_name,
                *args,
                stdout=StringIO(),
                stderr=out,
            )
            self.assertIn(msg, out.getvalue())

    def test_no_historical(self):
        out = StringIO()
        with replace_registry({"test_place": Place}):
            management.call_command(self.command_name, auto=True, stdout=out)
        self.assertIn(clean_old_history.Command.NO_REGISTERED_MODELS, out.getvalue())

    def test_auto_dry_run(self):
        p = Poll.objects.create(
            question="Will this be deleted?", pub_date=datetime.now()
        )
        p.save()

        # not related to dry_run test, just for increasing coverage :)
        # create instance with single-entry history older than "minutes"
        # so it is skipped
        p = Poll.objects.create(
            question="Will this be deleted?", pub_date=datetime.now()
        )
        h = p.history.first()
        h.history_date -= timedelta(days=31)
        h.save()

        self.assertEqual(Poll.history.all().count(), 3)
        out = StringIO()
        management.call_command(
            self.command_name,
            auto=True,
            days=20,
            dry=True,
            stdout=out,
            stderr=StringIO(),
        )
        self.assertEqual(
            out.getvalue(),
            "Removed 1 historical records for "
            "<class 'simple_history.tests.models.Poll'>\n",
        )
        self.assertEqual(Poll.history.all().count(), 3)

    def test_auto_cleanup(self):
        p = Poll.objects.create(
            question="Will this be deleted?", pub_date=datetime.now()
        )
        self.assertEqual(Poll.history.all().count(), 1)
        p.save()
        self.assertEqual(Poll.history.all().count(), 2)
        p.question = "Maybe this one won't...?"
        p.save()
        self.assertEqual(Poll.history.all().count(), 3)
        out = StringIO()
        h = p.history.first()
        h.history_date -= timedelta(days=40)
        h.save()
        management.call_command(
            self.command_name, auto=True, stdout=out, stderr=StringIO()
        )
        self.assertEqual(
            out.getvalue(),
            "Removed 1 historical records for "
            "<class 'simple_history.tests.models.Poll'>\n",
        )
        self.assertEqual(Poll.history.all().count(), 2)

    def test_auto_cleanup_verbose(self):
        p = Poll.objects.create(
            question="Will this be deleted?", pub_date=datetime.now()
        )
        self.assertEqual(Poll.history.all().count(), 1)
        p.save()
        p.question = "Maybe this one won't...?"
        p.save()
        h = p.history.first()
        h.history_date -= timedelta(days=40)
        h.save()
        self.assertEqual(Poll.history.all().count(), 3)
        out = StringIO()
        management.call_command(
            self.command_name,
            "tests.poll",
            auto=True,
            verbosity=2,
            stdout=out,
            stderr=StringIO(),
        )

        self.assertEqual(
            out.getvalue(),
            "<class 'simple_history.tests.models.Poll'> has 1 old historical entries\n"
            "Removed 1 historical records for "
            "<class 'simple_history.tests.models.Poll'>\n",
        )
        self.assertEqual(Poll.history.all().count(), 2)

    def test_auto_cleanup_dated(self):
        the_time_is_now = datetime.now()
        p = Poll.objects.create(
            question="Will this be deleted?", pub_date=the_time_is_now
        )
        self.assertEqual(Poll.history.all().count(), 1)
        p.save()
        p.save()
        self.assertEqual(Poll.history.all().count(), 3)
        p.question = "Or this one...?"
        p.save()
        p.save()
        self.assertEqual(Poll.history.all().count(), 5)

        for h in Poll.history.all()[2:]:
            h.history_date -= timedelta(days=30)
            h.save()

        management.call_command(
            self.command_name,
            auto=True,
            days=20,
            stdout=StringIO(),
            stderr=StringIO(),
        )
        self.assertEqual(Poll.history.all().count(), 2)

    def test_auto_cleanup_dated_extra_one(self):
        the_time_is_now = datetime.now()
        p = Poll.objects.create(
            question="Will this be deleted?", pub_date=the_time_is_now
        )
        self.assertEqual(Poll.history.all().count(), 1)
        p.save()
        p.save()
        self.assertEqual(Poll.history.all().count(), 3)
        p.question = "Or this one...?"
        p.save()
        p.save()
        p.save()
        p.save()
        self.assertEqual(Poll.history.all().count(), 7)

        for h in Poll.history.all()[2:]:
            h.history_date -= timedelta(days=30)
            h.save()

        management.call_command(
            self.command_name,
            auto=True,
            days=20,
            stdout=StringIO(),
            stderr=StringIO(),
        )
        # We will remove the 3 ones that we are marking as old
        self.assertEqual(Poll.history.all().count(), 2)

    def test_auto_cleanup_custom_history_field(self):
        m = CustomManagerNameModel.objects.create(name="John")
        self.assertEqual(CustomManagerNameModel.log.all().count(), 1)
        m.save()
        self.assertEqual(CustomManagerNameModel.log.all().count(), 2)
        m.name = "Ivan"
        m.save()
        h = m.log.first()
        h.history_date -= timedelta(days=40)
        h.save()
        self.assertEqual(CustomManagerNameModel.log.all().count(), 3)
        out = StringIO()
        management.call_command(
            self.command_name, auto=True, stdout=out, stderr=StringIO()
        )

        self.assertEqual(
            out.getvalue(),
            "Removed 1 historical records for "
            "<class 'simple_history.tests.models.CustomManagerNameModel'>\n",
        )
        self.assertEqual(CustomManagerNameModel.log.all().count(), 2)


POLICY_PATH = "simple_history.tests.cleanup_policies.ComplianceFreezePolicy"


class TestCleanOldHistoryWithPolicy(TestCase):
    command_name = "clean_old_history"
    model = RecordWithComplianceFreeze

    def _make_record(self, *, frozen=False, freeze_reason="", days_old=40):
        record = self.model.objects.create(
            name="record",
            compliance_frozen=frozen,
            freeze_reason=freeze_reason,
        )
        historical = record.history.first()
        historical.history_date -= timedelta(days=days_old)
        historical.save()
        return record, historical

    def test_dry_run_marks_protection_reason_and_changes_nothing(self):
        frozen, frozen_history = self._make_record(
            frozen=True, freeze_reason="Legal hold GH-7558"
        )
        regular, regular_history = self._make_record()
        out = StringIO()
        management.call_command(
            self.command_name,
            "tests.recordwithcompliancefreeze",
            "--days",
            "30",
            "--dry",
            "--policy",
            POLICY_PATH,
            stdout=out,
            stderr=StringIO(),
        )
        output = out.getvalue()
        self.assertIn(
            f"Protecting historical record {frozen_history.history_id}", output
        )
        self.assertIn("Legal hold GH-7558", output)
        self.assertIn("Kept 1 protected historical records", output)
        self.assertIn("Removed 1 historical records", output)
        # Dry run must not touch any data.
        self.assertEqual(self.model.history.count(), 2)
        self.assertTrue(
            self.model.history.filter(history_id=frozen_history.history_id).exists()
        )
        self.assertTrue(
            self.model.history.filter(history_id=regular_history.history_id).exists()
        )

    def test_real_run_deletes_expired_but_keeps_frozen_records(self):
        frozen, frozen_history = self._make_record(
            frozen=True, freeze_reason="Legal hold GH-7558"
        )
        regular, regular_history = self._make_record()
        management.call_command(
            self.command_name,
            "tests.recordwithcompliancefreeze",
            "--days",
            "30",
            "--policy",
            POLICY_PATH,
            stdout=StringIO(),
            stderr=StringIO(),
        )
        remaining = list(self.model.history.all())
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0].history_id, frozen_history.history_id)
        self.assertFalse(
            self.model.history.filter(history_id=regular_history.history_id).exists()
        )

    def test_without_policy_keeps_original_behavior(self):
        record, _ = self._make_record(frozen=True, freeze_reason="Legal hold")
        self.assertEqual(self.model.history.count(), 1)
        management.call_command(
            self.command_name,
            "tests.recordwithcompliancefreeze",
            "--days",
            "30",
            stdout=StringIO(),
            stderr=StringIO(),
        )
        # No policy given: even the frozen record is eligible for deletion.
        self.assertEqual(self.model.history.count(), 0)

    def test_failed_cleanup_rolls_back_and_rerun_reapplies_policy(self):
        frozen, frozen_history = self._make_record(
            frozen=True, freeze_reason="Legal hold GH-7558"
        )
        regular, regular_history = self._make_record()
        history_model = self.model.history.model
        queryset_class = type(history_model.objects.all())
        original_delete = queryset_class.delete

        def failing_delete(queryset, *args, **kwargs):
            original_delete(queryset, *args, **kwargs)
            raise RuntimeError("simulated cleanup failure")

        with patch.object(queryset_class, "delete", failing_delete):
            with self.assertRaises(RuntimeError):
                management.call_command(
                    self.command_name,
                    "tests.recordwithcompliancefreeze",
                    "--days",
                    "30",
                    "--policy",
                    POLICY_PATH,
                    stdout=StringIO(),
                    stderr=StringIO(),
                )

        # The transaction rolled back: nothing was deleted.
        self.assertEqual(self.model.history.count(), 2)
        self.assertTrue(
            self.model.history.filter(history_id=frozen_history.history_id).exists()
        )
        self.assertTrue(
            self.model.history.filter(history_id=regular_history.history_id).exists()
        )

        # Rerun with the policy still in force: only the expired, non-frozen
        # record is removed; the frozen one survives again.
        management.call_command(
            self.command_name,
            "tests.recordwithcompliancefreeze",
            "--days",
            "30",
            "--policy",
            POLICY_PATH,
            stdout=StringIO(),
            stderr=StringIO(),
        )
        remaining = list(self.model.history.all())
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0].history_id, frozen_history.history_id)

    def test_rerun_evaluates_the_policy_currently_in_force(self):
        # First run: both objects are frozen, so nothing is deleted.
        first, first_history = self._make_record(
            frozen=True, freeze_reason="Initial freeze"
        )
        second, second_history = self._make_record(
            frozen=True, freeze_reason="Initial freeze"
        )
        management.call_command(
            self.command_name,
            "tests.recordwithcompliancefreeze",
            "--days",
            "30",
            "--policy",
            POLICY_PATH,
            stdout=StringIO(),
            stderr=StringIO(),
        )
        self.assertEqual(self.model.history.count(), 2)

        # The freeze on the second object is lifted before the next run.
        self.model.objects.filter(pk=second.pk).update(
            compliance_frozen=False, freeze_reason=""
        )
        second.refresh_from_db()
        second.save()
        # Keep the new history entry fresh so only the old entry is expired.
        new_entry = (
            self.model.history.filter(id=second.pk)
            .order_by("-history_date", "-history_id")
            .first()
        )
        self.assertNotEqual(new_entry.history_id, second_history.history_id)
        new_entry.history_date = datetime.now()
        new_entry.save()

        management.call_command(
            self.command_name,
            "tests.recordwithcompliancefreeze",
            "--days",
            "30",
            "--policy",
            POLICY_PATH,
            stdout=StringIO(),
            stderr=StringIO(),
        )
        # The still-frozen object is fully intact; the unfrozen object's old
        # entry was cleaned while its fresh entry remains.
        self.assertTrue(
            self.model.history.filter(history_id=first_history.history_id).exists()
        )
        self.assertFalse(
            self.model.history.filter(history_id=second_history.history_id).exists()
        )
        remaining_for_second = self.model.history.filter(id=second.pk)
        self.assertEqual(remaining_for_second.count(), 1)
        self.assertEqual(remaining_for_second.first().history_id, new_entry.history_id)

    def test_deleted_object_keeps_frozen_snapshot_protection(self):
        record, frozen_history = self._make_record(
            frozen=True, freeze_reason="Legal hold GH-7558"
        )
        record_pk = record.pk
        # Age the existing entry before deleting the object so every history
        # record ends up past the retention window.
        for historical in self.model.history.filter(id=record_pk):
            historical.history_date -= timedelta(days=40)
            historical.save()
        record.delete()
        deletion_record = self.model.history.filter(
            id=record_pk, history_type="-"
        ).first()
        deletion_record.history_date -= timedelta(days=40)
        deletion_record.save()
        management.call_command(
            self.command_name,
            "tests.recordwithcompliancefreeze",
            "--days",
            "30",
            "--policy",
            POLICY_PATH,
            stdout=StringIO(),
            stderr=StringIO(),
        )
        # Even though the live object no longer exists, the frozen snapshots
        # must be preserved in full.
        self.assertEqual(self.model.history.filter(id=record_pk).count(), 2)
        self.assertTrue(
            self.model.history.filter(history_id=frozen_history.history_id).exists()
        )

    def test_invalid_policy_path_raises_command_error(self):
        self._make_record()
        with self.assertRaises(CommandError):
            management.call_command(
                self.command_name,
                "tests.recordwithcompliancefreeze",
                "--policy",
                "simple_history.tests.cleanup_policies.DoesNotExist",
                stdout=StringIO(),
                stderr=StringIO(),
            )
        # The failed command must not have deleted anything.
        self.assertEqual(self.model.history.count(), 1)


@override_settings(**database_router_override_settings_compliance_freeze_in_diff_db)
class TestCleanOldHistoryWithPolicySeparateDatabase(TestCase):
    command_name = "clean_old_history"
    databases = {"default", OTHER_DB_NAME}
    model = RecordWithComplianceFreezeInDifferentDb

    def _make_record(self, *, frozen=False, freeze_reason="", days_old=40):
        record = self.model.objects.using("default").create(
            name="record",
            compliance_frozen=frozen,
            freeze_reason=freeze_reason,
        )
        historical = record.history.using(OTHER_DB_NAME).first()
        historical.history_date -= timedelta(days=days_old)
        historical.save(using=OTHER_DB_NAME)
        return record, historical

    def test_dry_run_previews_both_samples_in_separate_history_db(self):
        frozen, frozen_history = self._make_record(
            frozen=True, freeze_reason="Legal hold GH-7558"
        )
        regular, regular_history = self._make_record()
        self.assertEqual(self.model.history.using(OTHER_DB_NAME).count(), 2)
        self.assertEqual(self.model.history.using("default").count(), 0)
        out = StringIO()
        management.call_command(
            self.command_name,
            "tests.recordwithcompliancefreezeindifferentdb",
            "--days",
            "30",
            "--dry",
            "--policy",
            POLICY_PATH,
            "--database",
            OTHER_DB_NAME,
            stdout=out,
            stderr=StringIO(),
        )
        output = out.getvalue()
        self.assertIn("Legal hold GH-7558", output)
        self.assertIn("Kept 1 protected historical records", output)
        self.assertIn("Removed 1 historical records", output)
        self.assertEqual(self.model.history.using(OTHER_DB_NAME).count(), 2)

    def test_real_run_preserves_frozen_records_in_separate_history_db(self):
        frozen, frozen_history = self._make_record(
            frozen=True, freeze_reason="Legal hold GH-7558"
        )
        regular, regular_history = self._make_record()
        management.call_command(
            self.command_name,
            "tests.recordwithcompliancefreezeindifferentdb",
            "--days",
            "30",
            "--policy",
            POLICY_PATH,
            "--database",
            OTHER_DB_NAME,
            stdout=StringIO(),
            stderr=StringIO(),
        )
        remaining = list(self.model.history.using(OTHER_DB_NAME).all())
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0].history_id, frozen_history.history_id)
        self.assertFalse(
            self.model.history.using(OTHER_DB_NAME)
            .filter(history_id=regular_history.history_id)
            .exists()
        )

    def test_failed_cleanup_rerun_keeps_frozen_records_in_separate_db(self):
        frozen, frozen_history = self._make_record(
            frozen=True, freeze_reason="Legal hold GH-7558"
        )
        regular, regular_history = self._make_record()
        history_model = self.model.history.model
        manager = history_model.objects.using(OTHER_DB_NAME)
        queryset_class = type(manager.all())
        original_delete = queryset_class.delete

        def failing_delete(queryset, *args, **kwargs):
            original_delete(queryset, *args, **kwargs)
            raise RuntimeError("simulated cleanup failure")

        with patch.object(queryset_class, "delete", failing_delete):
            with self.assertRaises(RuntimeError):
                management.call_command(
                    self.command_name,
                    "tests.recordwithcompliancefreezeindifferentdb",
                    "--days",
                    "30",
                    "--policy",
                    POLICY_PATH,
                    "--database",
                    OTHER_DB_NAME,
                    stdout=StringIO(),
                    stderr=StringIO(),
                )

        self.assertEqual(self.model.history.using(OTHER_DB_NAME).count(), 2)

        management.call_command(
            self.command_name,
            "tests.recordwithcompliancefreezeindifferentdb",
            "--days",
            "30",
            "--policy",
            POLICY_PATH,
            "--database",
            OTHER_DB_NAME,
            stdout=StringIO(),
            stderr=StringIO(),
        )
        remaining = list(self.model.history.using(OTHER_DB_NAME).all())
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0].history_id, frozen_history.history_id)
        self.assertTrue(
            self.model.history.using(OTHER_DB_NAME)
            .filter(history_id=frozen_history.history_id)
            .exists()
        )
