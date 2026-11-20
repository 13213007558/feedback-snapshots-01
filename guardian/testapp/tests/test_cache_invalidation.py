from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import transaction
from django.test import TransactionTestCase

from guardian.conf import settings as guardian_settings
from guardian.core import ObjectPermissionChecker
from guardian.models import UserObjectPermission
from guardian.shortcuts import assign_perm, remove_perm
from guardian.testapp.models import Project, ProjectUserObjectPermission
from guardian.utils import invalidate_obj_perms_cache_on_commit

User = get_user_model()


class CacheInvalidationContractTestCase(TransactionTestCase):
    """Real-database scenarios for the commit-deferred cache invalidation contract.

    A back-office batch revokes access to a set of objects while other
    requests have already prefetched permission results for them. The
    contract: cached authorization results for exactly the revoked objects
    are evicted only once the revocation transaction commits; rollbacks
    leave the cache untouched and non-target objects keep their cache hits.
    """

    def setUp(self):
        self.user = User.objects.create(username="batch-target")
        # Direct foreign key object permission targets
        self.project1 = Project.objects.create(name="project-1")
        self.project2 = Project.objects.create(name="project-2")
        # Generic object permission targets
        self.group1 = Group.objects.create(name="generic-1")
        self.group2 = Group.objects.create(name="generic-2")

        for project in (self.project1, self.project2):
            assign_perm("change_project", self.user, project)
        for group in (self.group1, self.group2):
            assign_perm("change_group", self.user, group)

        # Simulate a request that already prefetched this batch of objects.
        self.checker = ObjectPermissionChecker(self.user)
        self.checker.prefetch_perms([self.project1, self.project2])
        self.checker.prefetch_perms([self.group1, self.group2])

        self.key_project1 = self.checker.get_local_cache_key(self.project1)
        self.key_project2 = self.checker.get_local_cache_key(self.project2)
        self.key_group1 = self.checker.get_local_cache_key(self.group1)
        self.key_group2 = self.checker.get_local_cache_key(self.group2)

    def test_rolled_back_revocation_keeps_cache_and_perms(self):
        class RevokeFailed(Exception):
            pass

        try:
            with transaction.atomic():
                remove_perm("change_project", self.user, self.project1)
                remove_perm("change_group", self.user, self.group1)
                invalidate_obj_perms_cache_on_commit(self.checker, [self.project1, self.group1])
                raise RevokeFailed
        except RevokeFailed:
            pass

        # The rollback discarded the scheduled invalidation: every prefetched
        # entry is still served from the cache without hitting the database.
        with self.assertNumQueries(0):
            self.assertTrue(self.checker.has_perm("change_project", self.project1))
            self.assertTrue(self.checker.has_perm("change_group", self.group1))
            self.assertTrue(self.checker.has_perm("change_project", self.project2))
            self.assertTrue(self.checker.has_perm("change_group", self.group2))

        # Database state was rolled back as well, so a fresh checker agrees.
        self.assertTrue(
            ProjectUserObjectPermission.objects.filter(user=self.user, content_object=self.project1).exists()
        )
        self.assertTrue(UserObjectPermission.objects.filter(user=self.user, object_pk=str(self.group1.pk)).exists())
        fresh = ObjectPermissionChecker(self.user)
        self.assertTrue(fresh.has_perm("change_project", self.project1))
        self.assertTrue(fresh.has_perm("change_group", self.group1))

    def test_committed_revocation_evicts_only_target_entries(self):
        with transaction.atomic():
            remove_perm("change_project", self.user, self.project1)
            remove_perm("change_group", self.user, self.group1)
            invalidate_obj_perms_cache_on_commit(self.checker, [self.project1, self.group1])
            # Not committed yet: cached entries must still be in place.
            self.assertIn(self.key_project1, self.checker._obj_perms_cache)
            self.assertIn(self.key_group1, self.checker._obj_perms_cache)

        # Committed: exactly the revoked objects' entries are gone, for both
        # the direct foreign key and the generic permission models.
        self.assertNotIn(self.key_project1, self.checker._obj_perms_cache)
        self.assertNotIn(self.key_group1, self.checker._obj_perms_cache)
        # Non-target objects from the same prefetch batch keep their entries.
        self.assertIn(self.key_project2, self.checker._obj_perms_cache)
        self.assertIn(self.key_group2, self.checker._obj_perms_cache)

        # Non-target checks are still pure cache hits.
        with self.assertNumQueries(0):
            self.assertTrue(self.checker.has_perm("change_project", self.project2))
            self.assertTrue(self.checker.has_perm("change_group", self.group2))

        # Revoked entries are re-fetched from the database and now denied.
        self.assertFalse(self.checker.has_perm("change_project", self.project1))
        self.assertFalse(self.checker.has_perm("change_group", self.group1))
        self.assertFalse(
            ProjectUserObjectPermission.objects.filter(user=self.user, content_object=self.project1).exists()
        )
        self.assertFalse(UserObjectPermission.objects.filter(user=self.user, object_pk=str(self.group1.pk)).exists())

    def test_invalidate_cache_evicts_only_given_objects_immediately(self):
        evicted = self.checker.invalidate_cache([self.project1, self.group1])

        self.assertEqual(evicted, 2)
        self.assertNotIn(self.key_project1, self.checker._obj_perms_cache)
        self.assertNotIn(self.key_group1, self.checker._obj_perms_cache)
        self.assertIn(self.key_project2, self.checker._obj_perms_cache)
        self.assertIn(self.key_group2, self.checker._obj_perms_cache)

        with self.assertNumQueries(0):
            self.assertTrue(self.checker.has_perm("change_project", self.project2))
            self.assertTrue(self.checker.has_perm("change_group", self.group2))

        # Evicted entries are re-fetched from the unchanged database.
        self.assertTrue(self.checker.has_perm("change_project", self.project1))
        self.assertTrue(self.checker.has_perm("change_group", self.group1))

    def test_auto_prefetch_cache_on_identity_evicted_on_commit(self):
        guardian_settings.AUTO_PREFETCH = True
        try:
            checker = ObjectPermissionChecker(self.user)
            self.assertTrue(checker.has_perm("change_project", self.project1))
            self.assertTrue(checker.has_perm("change_group", self.group1))
            self.assertTrue(hasattr(self.user, "_guardian_perms_cache"))
            prefetch_cache = self.user._guardian_perms_cache
            self.assertIs(checker._obj_perms_cache, prefetch_cache)

            with transaction.atomic():
                remove_perm("change_project", self.user, self.project1)
                invalidate_obj_perms_cache_on_commit(self.user, [self.project1])
                self.assertIn(self.key_project1, prefetch_cache)

            # Only the revoked direct-FK entry is evicted from the shared
            # prefetch cache; generic and non-target entries survive.
            self.assertNotIn(self.key_project1, prefetch_cache)
            self.assertIn(self.key_project2, prefetch_cache)
            self.assertIn(self.key_group1, prefetch_cache)
            self.assertIn(self.key_group2, prefetch_cache)

            # The checker sharing the prefetch cache observes the eviction.
            self.assertFalse(checker.has_perm("change_project", self.project1))
            with self.assertNumQueries(0):
                self.assertTrue(checker.has_perm("change_group", self.group1))
        finally:
            guardian_settings.AUTO_PREFETCH = False
