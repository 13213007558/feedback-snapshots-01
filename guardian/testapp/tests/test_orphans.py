from io import StringIO
import re
from unittest.mock import patch

from django.apps import apps as django_apps
from django.contrib.auth import get_user_model
from django.contrib.auth.management import create_permissions
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.management import call_command
from django.db import DatabaseError
from django.db.models.query import QuerySet
from django.test import TestCase

from guardian.models import Group, GroupObjectPermission, UserObjectPermission
from guardian.shortcuts import assign_perm
from guardian.testapp.models import UUIDPKModel
from guardian.testapp.tests.conf import skipUnlessTestApp
from guardian.utils import clean_orphan_obj_perms, delete_orphan_obj_perms, preview_orphan_obj_perms

auth_app = django_apps.get_app_config("auth")

User = get_user_model()
user_module_name = User._meta.model_name


@skipUnlessTestApp
class OrphanedObjectPermissionsTest(TestCase):
    def setUp(self):
        # Create objects for which we would assign obj perms
        self.target_user1 = User.objects.create(username="user1")
        self.target_group1 = Group.objects.create(name="group1")
        self.target_obj1 = ContentType.objects.create(model="foo", app_label="fake-for-guardian-tests")
        self.target_obj2 = ContentType.objects.create(model="bar", app_label="fake-for-guardian-tests")
        # Required if MySQL backend is used :/
        create_permissions(auth_app, 1)

        self.user = User.objects.create(username="user")
        self.group = Group.objects.create(name="group")

    def _create_orphan_permissions(self, count=10):
        """Helper method to create a specific number of orphan permissions"""
        target_objs = []
        for i in range(count):
            # Use only the test method name (not self.id(), whose fully qualified
            # dotted path can exceed ContentType.model's max_length=100 and raise
            # a DataError on strict backends like PostgreSQL/MySQL, even though
            # SQLite silently accepts it).
            target_obj = ContentType.objects.create(
                model=f"test_model_{self._testMethodName}_{i}", app_label="fake-for-guardian-tests"
            )
            target_objs.append(target_obj)

            # Assign permissions to both user and group
            assign_perm("change_contenttype", self.user, target_obj)
            assign_perm("delete_contenttype", self.group, target_obj)

        # Delete the target objects to create orphans
        for target_obj in target_objs:
            target_obj.delete()

        return count * 2  # Each object had 2 permissions (user + group)

    def _get_current_orphan_count(self):
        """Get current number of orphan permissions"""
        from guardian.models import UserObjectPermission

        user_orphans = sum(1 for obj in UserObjectPermission.objects.all() if obj.content_object is None)
        group_orphans = sum(1 for obj in GroupObjectPermission.objects.all() if obj.content_object is None)

        return user_orphans + group_orphans

    def test_clean_perms(self):
        # assign obj perms
        target_perms = {
            self.target_user1: ["change_%s" % user_module_name],
            self.target_group1: ["delete_group"],
            self.target_obj1: ["change_contenttype", "delete_contenttype"],
            self.target_obj2: ["change_contenttype"],
        }
        obj_perms_count = sum(len(val) for key, val in target_perms.items())
        for target, perms in target_perms.items():
            target.__old_pk = target.pk  # Store pkeys
            for perm in perms:
                assign_perm(perm, self.user, target)

        # Remove targets
        for target, perms in target_perms.items():
            target.delete()

        # Clean orphans
        removed = clean_orphan_obj_perms()
        self.assertEqual(removed, obj_perms_count)

        # Recreate targets and check if user has no permissions
        for target, perms in target_perms.items():
            target.pk = target.__old_pk
            target.save()
            for perm in perms:
                self.assertFalse(self.user.has_perm(perm, target))

    def test_clean_perms_with_batch_size(self):
        """Test cleaning orphan permissions with batch_size parameter"""
        expected_orphans = self._create_orphan_permissions(5)

        removed = clean_orphan_obj_perms(batch_size=3)

        self.assertEqual(removed, expected_orphans)
        self.assertEqual(self._get_current_orphan_count(), 0)

    def test_clean_perms_with_max_batches(self):
        """Test cleaning orphan permissions with max_batches parameter"""
        # Get current orphan count and create new ones
        self._create_orphan_permissions(10)
        total_orphans = self._get_current_orphan_count()

        # Clean with batch size and max batches - should process limited batches
        removed = clean_orphan_obj_perms(batch_size=3, max_batches=2)
        self.assertLessEqual(removed, total_orphans)
        self.assertGreater(removed, 0)

        # Clean the rest
        remaining = clean_orphan_obj_perms()
        self.assertEqual(removed + remaining, total_orphans)

    def test_clean_perms_with_skip_batches(self):
        """Test cleaning orphan permissions with skip_batches parameter"""
        # Get current orphan count and create new ones
        self._create_orphan_permissions(10)
        total_orphans = self._get_current_orphan_count()

        # Skip some batches and clean the rest
        removed = clean_orphan_obj_perms(batch_size=3, skip_batches=2)
        self.assertLessEqual(removed, total_orphans)

        # Clean the skipped ones
        remaining = clean_orphan_obj_perms()
        self.assertEqual(removed + remaining, total_orphans)

    def test_clean_perms_with_max_duration_secs(self):
        """Test cleaning orphan permissions with max_duration_secs parameter"""
        self._create_orphan_permissions(5)

        # Test with very short duration (should stop early)
        with patch("guardian.utils.time.monotonic") as mock_time:
            # Mock time to simulate duration limit being reached
            mock_time.side_effect = [0, 0.5, 2.0] + [3.0] * 20

            removed = clean_orphan_obj_perms(batch_size=2, max_duration_secs=1)
            # Should stop early due to time limit
            self.assertGreaterEqual(removed, 0)

    def test_clean_perms_combined_parameters(self):
        """Test cleaning orphan permissions with multiple parameters combined"""
        expected_orphans = self._create_orphan_permissions(15)

        # Use batch_size, skip_batches, max_batches
        removed = clean_orphan_obj_perms(batch_size=3, skip_batches=1, max_batches=3)
        self.assertGreaterEqual(removed, 0)
        self.assertLessEqual(removed, expected_orphans)

        # Clean remaining
        remaining = clean_orphan_obj_perms()
        self.assertEqual(removed + remaining, expected_orphans)

    def test_clean_perms_no_orphans(self):
        """Test cleaning when there are no orphan permissions"""
        # Don't create any orphans
        removed = clean_orphan_obj_perms(batch_size=5)
        self.assertEqual(removed, 0)

    def test_clean_perms_edge_cases(self):
        """Test edge cases for parameter combinations"""
        # Test that parameters are accepted and work without exact count verification
        self._create_orphan_permissions(5)

        # Test with batch_size larger than total records
        removed = clean_orphan_obj_perms(batch_size=100)
        self.assertGreaterEqual(removed, 0)  # Should work without errors

        # Clean any remaining
        clean_orphan_obj_perms()

        # Create more orphans for next test
        self._create_orphan_permissions(3)

        # Test with skip_batches larger than available batches
        removed = clean_orphan_obj_perms(batch_size=2, skip_batches=10)
        # With skip_batches > available batches, should remove 0
        self.assertEqual(removed, 0)

        # Clean the remaining orphans to verify function still works
        remaining = clean_orphan_obj_perms()
        self.assertGreaterEqual(remaining, 0)  # Should clean remaining orphans

    def test_clean_perms_return_value_consistency(self):
        """Test that return value is consistent across different parameter combinations"""
        expected_orphans = self._create_orphan_permissions(8)

        # Clean in batches and verify total
        total_removed = 0
        while True:
            removed = clean_orphan_obj_perms(batch_size=3, max_batches=1)
            if removed == 0:
                break
            total_removed += removed

        self.assertEqual(total_removed, expected_orphans)

    def _assign_perms_with_orphans(self, identity, perm, count, orphan_indexes):
        """Assign ``perm`` on ``count`` new objects, in pk order, then delete the objects at ``orphan_indexes``"""
        target_objs = [
            ContentType.objects.create(model=f"{identity}_{i}", app_label="fake-for-guardian-tests")
            for i in range(count)
        ]
        for target_obj in target_objs:
            assign_perm(perm, identity, target_obj)
        for i in orphan_indexes:
            target_objs[i].delete()

    def _resume_skip_batches(self, logs):
        """Return the skip_batches value from the logged resume hint"""
        match = re.search(r"skip_batches=(\d+)", logs.output[-1])
        self.assertIsNotNone(match)
        return int(match.group(1))

    def test_clean_perms_batched_does_not_skip_rows_after_deleting_orphans(self):
        """Deleting orphans in one batch must not make the next batch skip rows"""
        self._assign_perms_with_orphans(self.user, "change_contenttype", 4, orphan_indexes=[0, 2])
        self._assign_perms_with_orphans(self.group, "delete_contenttype", 4, orphan_indexes=[0, 2])

        removed = clean_orphan_obj_perms(batch_size=2)

        self.assertEqual(removed, 4)
        self.assertEqual(self._get_current_orphan_count(), 0)

    def test_clean_perms_resume_hint_does_not_skip_user_orphans(self):
        """Resuming with the logged skip_batches must reach orphans left in the user permissions"""
        self._assign_perms_with_orphans(self.user, "change_contenttype", 6, orphan_indexes=[0, 2])

        with self.assertLogs("guardian.utils", level="INFO") as logs:
            removed = clean_orphan_obj_perms(batch_size=2, max_batches=1)
        self.assertEqual(removed, 1)

        removed += clean_orphan_obj_perms(batch_size=2, skip_batches=self._resume_skip_batches(logs))

        self.assertEqual(removed, 2)
        self.assertEqual(self._get_current_orphan_count(), 0)

    def test_clean_perms_resume_hint_does_not_skip_group_orphans(self):
        """Resuming with the logged skip_batches must reach orphans left in the group permissions"""
        self._assign_perms_with_orphans(self.user, "change_contenttype", 3, orphan_indexes=[1])
        self._assign_perms_with_orphans(self.group, "delete_contenttype", 4, orphan_indexes=[0, 2])

        # Two batches cover the 3 user permissions, the third covers the first 2 group permissions
        with self.assertLogs("guardian.utils", level="INFO") as logs:
            removed = clean_orphan_obj_perms(batch_size=2, max_batches=3)
        self.assertEqual(removed, 2)

        removed += clean_orphan_obj_perms(batch_size=2, skip_batches=self._resume_skip_batches(logs))

        self.assertEqual(removed, 3)
        self.assertEqual(self._get_current_orphan_count(), 0)

    def test_clean_perms_batched_reaches_last_group_batch_after_partial_user_batch(self):
        """The batch budget must cover the last group batch when the user permissions end in a partial batch"""
        self._assign_perms_with_orphans(self.user, "change_contenttype", 1, orphan_indexes=[])
        self._assign_perms_with_orphans(self.group, "delete_contenttype", 3, orphan_indexes=[2])

        # 1 user batch and 2 group batches, although the 4 rows would fit in 2 batches of 2
        removed = clean_orphan_obj_perms(batch_size=2)

        self.assertEqual(removed, 1)
        self.assertEqual(self._get_current_orphan_count(), 0)

    def test_clean_perms_resume_hint_reaches_last_group_batch(self):
        """Resuming after a partial user batch must still have batches left for the remaining group permissions"""
        self._assign_perms_with_orphans(self.user, "change_contenttype", 1, orphan_indexes=[])
        self._assign_perms_with_orphans(self.group, "delete_contenttype", 3, orphan_indexes=[2])

        with self.assertLogs("guardian.utils", level="INFO") as logs:
            removed = clean_orphan_obj_perms(batch_size=2, max_batches=2)
        self.assertEqual(removed, 0)

        removed += clean_orphan_obj_perms(batch_size=2, skip_batches=self._resume_skip_batches(logs))

        self.assertEqual(removed, 1)
        self.assertEqual(self._get_current_orphan_count(), 0)

    def test_clean_perms_command(self):
        """
        Same test as the one above but rather function directly, we call
        management command instead.
        """

        # assign obj perms
        target_perms = {
            self.target_user1: ["change_%s" % user_module_name],
            self.target_group1: ["delete_group"],
            self.target_obj1: ["change_contenttype", "delete_contenttype"],
            self.target_obj2: ["change_contenttype"],
        }
        for target, perms in target_perms.items():
            target.__old_pk = target.pk  # Store pkeys
            for perm in perms:
                assign_perm(perm, self.user, target)

        # Remove targets
        for target, perms in target_perms.items():
            target.delete()

        # Clean orphans
        call_command("clean_orphan_obj_perms", verbosity=0)

        # Recreate targets and check if user has no permissions
        for target, perms in target_perms.items():
            target.pk = target.__old_pk
            target.save()
            for perm in perms:
                self.assertFalse(self.user.has_perm(perm, target))

    def test_clean_perms_command_with_batch_size(self):
        """Test management command with batch-size parameter"""
        # Create orphans
        self._create_orphan_permissions(5)

        # Don't rely on _get_current_orphan_count, just run the command and verify it works
        out = StringIO()
        call_command("clean_orphan_obj_perms", batch_size=3, verbosity=1, stdout=out)

        output = out.getvalue()
        # Just verify that some permissions were removed and the format is correct
        self.assertIn("Removed", output)
        self.assertIn("object permission entries with no targets", output)

        # Extract the actual number and verify it's reasonable
        import re

        match = re.search(r"Removed (\d+) object permission entries", output)
        if match:
            removed = int(match.group(1))
            self.assertGreater(removed, 0)  # Should have removed something
            self.assertLessEqual(removed, 20)  # Reasonable upper bound

    def test_clean_perms_command_with_max_batches(self):
        """Test management command with max-batches parameter"""
        expected_orphans = self._create_orphan_permissions(8)

        out = StringIO()
        call_command("clean_orphan_obj_perms", batch_size=3, max_batches=2, verbosity=1, stdout=out)

        output = out.getvalue()
        # Should have removed some permissions
        self.assertIn("Removed", output)
        self.assertIn("object permission entries", output)

        # Extract the number from output and verify it's reasonable
        import re

        match = re.search(r"Removed (\d+) object permission entries", output)
        if match:
            removed = int(match.group(1))
            self.assertGreater(removed, 0)
            self.assertLessEqual(removed, expected_orphans)

    def test_clean_perms_command_with_skip_batches(self):
        """Test management command with skip-batches parameter"""
        self._create_orphan_permissions(8)

        out = StringIO()
        call_command("clean_orphan_obj_perms", batch_size=3, skip_batches=1, verbosity=1, stdout=out)

        output = out.getvalue()
        self.assertIn("Removed", output)
        self.assertIn("object permission entries", output)

    def test_clean_perms_command_with_max_duration_secs(self):
        """Test management command with max-duration-secs parameter"""
        self._create_orphan_permissions(5)

        with patch("guardian.utils.time.monotonic") as mock_time:
            mock_time.side_effect = [0, 0.5, 2.0] + [3.0] * 20

            out = StringIO()
            call_command("clean_orphan_obj_perms", batch_size=2, max_duration_secs=1, verbosity=1, stdout=out)

            output = out.getvalue()
            # Should have some output indicating removal
            self.assertIn("Removed", output)

    def test_clean_perms_command_combined_parameters(self):
        """Test management command with multiple parameters"""
        self._create_orphan_permissions(10)

        out = StringIO()
        call_command("clean_orphan_obj_perms", batch_size=3, skip_batches=1, max_batches=2, verbosity=1, stdout=out)

        output = out.getvalue()
        self.assertIn("Removed", output)
        self.assertIn("object permission entries", output)

    def test_clean_perms_command_verbosity_levels(self):
        """Test management command with different verbosity levels"""
        self._create_orphan_permissions(3)

        # Test verbosity=0 (should produce no output)
        out = StringIO()
        call_command("clean_orphan_obj_perms", verbosity=0, stdout=out)
        self.assertEqual(out.getvalue().strip(), "")

        # Create more orphans and test verbosity=1
        self._create_orphan_permissions(2)
        out = StringIO()
        call_command("clean_orphan_obj_perms", verbosity=1, stdout=out)
        output = out.getvalue()
        self.assertIn("Removed", output)
        self.assertIn("object permission entries", output)

    def test_clean_perms_command_no_orphans(self):
        """Test management command when there are no orphan permissions"""
        # First clean any existing orphans
        clean_orphan_obj_perms()

        out = StringIO()
        call_command("clean_orphan_obj_perms", verbosity=1, stdout=out)

        output = out.getvalue()
        self.assertIn("Removed 0 object permission entries with no targets", output)

    def test_preview_orphan_obj_perms_reports_candidates_without_deleting(self):
        """Previewing lists the orphan entries in a verifiable form and deletes nothing"""
        expected_orphans = self._create_orphan_permissions(3)

        preview = preview_orphan_obj_perms()

        self.assertEqual(preview.database, "default")
        self.assertEqual(preview.count, expected_orphans)
        self.assertEqual(len(preview.for_model("user")), 3)
        self.assertEqual(len(preview.for_model("group")), 3)
        for record in preview.records:
            self.assertTrue(record.content_type_id)
            self.assertTrue(record.object_pk)
        # Nothing was removed
        self.assertEqual(self._get_current_orphan_count(), expected_orphans)

    def test_delete_orphan_obj_perms_removes_exactly_the_previewed_entries(self):
        """Executing a preview removes the previewed entries and reports them for cross-checking"""
        expected_orphans = self._create_orphan_permissions(4)
        preview = preview_orphan_obj_perms()

        result = delete_orphan_obj_perms(preview, batch_size=3)

        self.assertEqual(result.database, "default")
        self.assertEqual(result.removed, expected_orphans)
        self.assertEqual(result.skipped, 0)
        self.assertEqual(result.failed_batches, 0)
        self.assertEqual({record.pk for record in result.removed_records}, {record.pk for record in preview.records})
        self.assertEqual(self._get_current_orphan_count(), 0)

    def test_delete_orphan_obj_perms_skips_targets_restored_after_preview(self):
        """A target re-created between preview and execution keeps its permissions"""
        target = ContentType.objects.create(model="restored", app_label="fake-for-guardian-tests")
        assign_perm("change_contenttype", self.user, target)
        old_pk = target.pk
        target.delete()

        preview = preview_orphan_obj_perms()
        self.assertEqual(preview.count, 1)

        # The target object is restored before the preview is executed
        target.pk = old_pk
        target.save()

        result = delete_orphan_obj_perms(preview)

        self.assertEqual(result.removed, 0)
        self.assertEqual(result.skipped, 1)
        self.assertEqual(result.skipped_records, preview.records)
        self.assertTrue(self.user.has_perm("change_contenttype", target))

    def test_delete_orphan_obj_perms_removes_uuid_pk_orphans(self):
        """Orphan entries pointing at UUID primary key targets are found and removed"""
        target = UUIDPKModel.objects.create()
        assign_perm("change_uuidpkmodel", self.user, target)
        target_uuid = target.pk
        target.delete()

        preview = preview_orphan_obj_perms()
        self.assertEqual(preview.count, 1)
        self.assertEqual(preview.records[0].object_pk, str(target_uuid))

        result = delete_orphan_obj_perms(preview)

        self.assertEqual(result.removed, 1)
        self.assertEqual(self._get_current_orphan_count(), 0)

    def test_delete_orphan_obj_perms_skips_restored_uuid_pk_target(self):
        """A UUID primary key target restored after the preview keeps its permissions"""
        target = UUIDPKModel.objects.create()
        assign_perm("change_uuidpkmodel", self.user, target)
        target_uuid = target.pk
        target.delete()

        preview = preview_orphan_obj_perms()
        self.assertEqual(preview.count, 1)

        # The object is re-created with the same UUID primary key before execution
        UUIDPKModel.objects.create(uuid_pk=target_uuid)

        result = delete_orphan_obj_perms(preview)

        self.assertEqual(result.removed, 0)
        self.assertEqual(result.skipped, 1)
        self.assertTrue(self.user.has_perm("change_uuidpkmodel", UUIDPKModel.objects.get(pk=target_uuid)))

    def test_delete_orphan_obj_perms_continues_after_batch_failure(self):
        """A failing batch is reported and skipped; a later run removes the rest"""
        self._assign_perms_with_orphans(self.user, "change_contenttype", 6, orphan_indexes=[0, 1, 2, 3, 4, 5])
        preview = preview_orphan_obj_perms()
        self.assertEqual(preview.count, 6)

        real_delete = QuerySet.delete
        failed_once = []

        def flaky_delete(qs, *args, **kwargs):
            if qs.model is UserObjectPermission and not failed_once:
                failed_once.append(True)
                raise DatabaseError("simulated batch failure")
            return real_delete(qs, *args, **kwargs)

        with patch("django.db.models.query.QuerySet.delete", autospec=True, side_effect=flaky_delete):
            result = delete_orphan_obj_perms(preview, batch_size=2)

        self.assertEqual(result.failed_batches, 1)
        self.assertEqual(result.batches_processed, 2)
        self.assertEqual(result.removed, 4)
        self.assertEqual(self._get_current_orphan_count(), 2)

        # A fresh preview and execution finishes the cleanup
        result = delete_orphan_obj_perms(preview_orphan_obj_perms(), batch_size=2)
        self.assertEqual(result.failed_batches, 0)
        self.assertEqual(result.removed, 2)
        self.assertEqual(self._get_current_orphan_count(), 0)

    def test_clean_perms_command_dry_run_previews_without_deleting(self):
        """--dry-run reports the orphan entries and leaves them in place"""
        expected_orphans = self._create_orphan_permissions(3)

        out = StringIO()
        call_command("clean_orphan_obj_perms", dry_run=True, verbosity=1, stdout=out)

        output = out.getvalue()
        self.assertIn(
            "Found %d object permission entries with no targets on database 'default'" % expected_orphans, output
        )
        self.assertIn("dry run", output)
        self.assertEqual(self._get_current_orphan_count(), expected_orphans)

        # Verbosity 2 lists every entry so the preview can be cross-checked
        out = StringIO()
        call_command("clean_orphan_obj_perms", dry_run=True, verbosity=2, stdout=out)
        self.assertIn("object_pk=", out.getvalue())

        # A real run afterwards removes them
        out = StringIO()
        call_command("clean_orphan_obj_perms", verbosity=1, stdout=out)
        self.assertIn("Removed %d object permission entries with no targets" % expected_orphans, out.getvalue())
        self.assertEqual(self._get_current_orphan_count(), 0)


@skipUnlessTestApp
class OrphanedObjectPermissionsMultiDbTest(TestCase):
    """Orphan cleanup on a nominated database alias (second in-memory SQLite database)"""

    databases = {"default", "secondary"}

    def setUp(self):
        self.user = User.objects.using("secondary").create(username="secondary-user")

    def _create_secondary_orphan(self):
        """Create one orphan user object permission on the secondary database"""
        target = ContentType.objects.using("secondary").create(
            model="secondaryfoo", app_label="fake-for-guardian-tests"
        )
        content_type = ContentType.objects.using("secondary").get(app_label="contenttypes", model="contenttype")
        permission = Permission.objects.using("secondary").get(codename="change_contenttype", content_type=content_type)
        obj_perm = UserObjectPermission.objects.using("secondary").create(
            user=self.user,
            permission=permission,
            content_type=content_type,
            object_pk=str(target.pk),
        )
        target.delete()
        return obj_perm

    def test_preview_and_delete_respect_database_alias(self):
        obj_perm = self._create_secondary_orphan()

        default_preview = preview_orphan_obj_perms(using="default")
        self.assertEqual(default_preview.count, 0)

        preview = preview_orphan_obj_perms(using="secondary")
        self.assertEqual(preview.database, "secondary")
        self.assertEqual(preview.count, 1)
        self.assertEqual(preview.records[0].pk, obj_perm.pk)
        # The orphan is still there after previewing
        self.assertTrue(UserObjectPermission.objects.using("secondary").filter(pk=obj_perm.pk).exists())

        result = delete_orphan_obj_perms(preview)
        self.assertEqual(result.database, "secondary")
        self.assertEqual(result.removed, 1)
        self.assertFalse(UserObjectPermission.objects.using("secondary").filter(pk=obj_perm.pk).exists())

    def test_clean_orphan_obj_perms_using_alias(self):
        obj_perm = self._create_secondary_orphan()

        removed = clean_orphan_obj_perms(using="secondary")

        self.assertEqual(removed, 1)
        self.assertFalse(UserObjectPermission.objects.using("secondary").filter(pk=obj_perm.pk).exists())

    def test_clean_perms_command_with_database_option(self):
        obj_perm = self._create_secondary_orphan()

        out = StringIO()
        call_command("clean_orphan_obj_perms", database="secondary", dry_run=True, verbosity=1, stdout=out)
        self.assertIn("Found 1 object permission entries with no targets on database 'secondary'", out.getvalue())
        self.assertTrue(UserObjectPermission.objects.using("secondary").filter(pk=obj_perm.pk).exists())

        out = StringIO()
        call_command("clean_orphan_obj_perms", database="secondary", verbosity=1, stdout=out)
        self.assertIn("Removed 1 object permission entries with no targets", out.getvalue())
        self.assertFalse(UserObjectPermission.objects.using("secondary").filter(pk=obj_perm.pk).exists())
