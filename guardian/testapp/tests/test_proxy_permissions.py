"""Object permissions for proxy models that share one database row.

``Ticket`` and ``SupervisorReview`` are proxies of ``Project`` and both opt into
``guardian_proxy_permission_mode = "isolate"``. The tests below assign
permissions through one view and assert that the other view, the concrete
model, and the bulk query APIs do not see them.
"""

from unittest import mock

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase

from guardian.conf import settings as guardian_settings
from guardian.core import ObjectPermissionChecker
from guardian.exceptions import MixedContentTypeError
from guardian.ctypes import get_content_type, get_proxy_permission_mode
from guardian.models import UserObjectPermission
from guardian.shortcuts import (
    assign_perm,
    get_group_perms,
    get_groups_with_perms,
    get_objects_for_group,
    get_objects_for_user,
    get_perms,
    get_perms_for_model,
    get_user_perms,
    get_users_with_perms,
    remove_perm,
)
from guardian.testapp.models import Project, ProjectUserObjectPermission, SupervisorReview, Ticket

User = get_user_model()


def base_content_type(obj):
    """Custom GUARDIAN_GET_CONTENT_TYPE target that pins everything to Project."""
    return ContentType.objects.get_for_model(Project)


class ProxyPermissionMatrixTests(TestCase):
    """One ``Project`` row, two isolated proxy views, three grant styles."""

    def setUp(self):
        self.project = Project.objects.create(name="ticket-1")
        self.ticket = Ticket.objects.get(pk=self.project.pk)
        self.review = SupervisorReview.objects.get(pk=self.project.pk)
        self.user = User.objects.create_user(username="joe")
        self.group = Group.objects.create(name="reviewers")
        self.user.groups.add(self.group)

    def _assert_view_matrix(self, *, ticket, review, base):
        self.assertIs(self.user.has_perm("change_ticket", self.ticket), ticket)
        self.assertIs(self.user.has_perm("change_supervisorreview", self.review), review)
        self.assertIs(self.user.has_perm("change_project", self.project), base)

    def test_direct_user_grant_is_scoped_to_its_proxy(self):
        assign_perm("change_ticket", self.user, self.ticket)

        self._assert_view_matrix(ticket=True, review=False, base=False)
        self.assertEqual(
            list(get_user_perms(self.user, self.ticket).values_list("codename", flat=True)),
            ["change_ticket"],
        )
        self.assertEqual(list(get_user_perms(self.user, self.review)), [])
        self.assertEqual(list(get_user_perms(self.user, self.project)), [])

    def test_group_grant_is_scoped_to_its_proxy(self):
        assign_perm("change_supervisorreview", self.group, self.review)

        self._assert_view_matrix(ticket=False, review=True, base=False)
        self.assertEqual(
            list(get_group_perms(self.user, self.review).values_list("codename", flat=True)),
            ["change_supervisorreview"],
        )
        self.assertEqual(list(get_group_perms(self.user, self.ticket)), [])
        self.assertEqual(list(get_group_perms(self.user, self.project)), [])

    def test_grants_to_both_views_are_independent(self):
        assign_perm("change_ticket", self.user, self.ticket)
        assign_perm("delete_supervisorreview", self.group, self.review)

        self.assertEqual(sorted(get_perms(self.user, self.ticket)), ["change_ticket"])
        self.assertEqual(sorted(get_perms(self.user, self.review)), ["delete_supervisorreview"])
        self.assertEqual(get_perms(self.user, self.project), [])

    def test_bulk_reads_do_not_leak_into_the_other_view(self):
        assign_perm("change_ticket", self.user, self.ticket)

        self.assertEqual(list(get_objects_for_user(self.user, "change_ticket", Ticket)), [self.ticket])
        self.assertEqual(list(get_objects_for_user(self.user, "change_supervisorreview", SupervisorReview)), [])
        self.assertEqual(list(get_objects_for_user(self.user, "change_project", Project)), [])
        self.assertEqual(list(get_objects_for_group(self.group, "change_ticket", Ticket)), [])
        self.assertEqual(list(get_objects_for_group(self.group, "change_supervisorreview", SupervisorReview)), [])
        self.assertEqual(list(get_objects_for_group(self.group, "change_project", Project)), [])

    def test_bulk_reads_do_not_leak_from_a_group_grant(self):
        assign_perm("change_supervisorreview", self.group, self.review)

        self.assertEqual(
            list(get_objects_for_user(self.user, "change_supervisorreview", SupervisorReview)), [self.review]
        )
        self.assertEqual(list(get_objects_for_user(self.user, "change_ticket", Ticket)), [])
        self.assertEqual(list(get_objects_for_user(self.user, "change_project", Project)), [])
        self.assertEqual(
            list(get_objects_for_group(self.group, "change_supervisorreview", SupervisorReview)), [self.review]
        )
        self.assertEqual(list(get_objects_for_group(self.group, "change_ticket", Ticket)), [])
        self.assertEqual(list(get_objects_for_group(self.group, "change_project", Project)), [])

    def test_people_and_group_listings_use_the_view_content_type(self):
        assign_perm("change_ticket", self.user, self.ticket)

        self.assertEqual(list(get_users_with_perms(self.ticket)), [self.user])
        self.assertEqual(list(get_users_with_perms(self.review)), [])
        self.assertEqual(list(get_users_with_perms(self.project)), [])
        self.assertEqual(list(get_groups_with_perms(self.ticket)), [])
        self.assertEqual(list(get_groups_with_perms(self.review)), [])

        assign_perm("change_supervisorreview", self.group, self.review)
        self.assertEqual(list(get_groups_with_perms(self.ticket)), [])
        self.assertEqual(list(get_groups_with_perms(self.review)), [self.group])

    def test_removing_from_one_view_keeps_the_other(self):
        assign_perm("change_ticket", self.user, self.ticket)
        assign_perm("change_supervisorreview", self.user, self.review)

        remove_perm("change_ticket", self.user, self.ticket)

        self.assertFalse(self.user.has_perm("change_ticket", self.ticket))
        self.assertTrue(self.user.has_perm("change_supervisorreview", self.review))
        self.assertEqual(
            list(get_user_perms(self.user, self.review).values_list("codename", flat=True)),
            ["change_supervisorreview"],
        )

    def test_each_row_is_stored_under_its_own_content_type(self):
        assign_perm("change_ticket", self.user, self.ticket)
        assign_perm("change_supervisorreview", self.user, self.review)

        content_types = set(UserObjectPermission.objects.values_list("content_type__model", flat=True))
        self.assertEqual(content_types, {"ticket", "supervisorreview"})
        self.assertEqual(get_content_type(self.ticket).model, "ticket")
        self.assertEqual(get_content_type(self.review).model, "supervisorreview")

    def test_base_model_grant_is_not_visible_to_isolated_proxies(self):
        assign_perm("change_project", self.user, self.project)

        self.assertTrue(self.user.has_perm("change_project", self.project))
        self.assertFalse(self.user.has_perm("change_ticket", self.ticket))
        self.assertFalse(self.user.has_perm("change_supervisorreview", self.review))
        self.assertEqual(list(get_objects_for_user(self.user, "change_project", Project)), [self.project])
        self.assertEqual(list(get_objects_for_user(self.user, "change_ticket", Ticket)), [])

    def test_bulk_assign_to_a_proxy_queryset_stays_in_that_view(self):
        other = Project.objects.create(name="ticket-2")
        assign_perm("change_ticket", self.user, Ticket.objects.filter(pk__in=[self.project.pk, other.pk]))

        self.assertEqual(
            sorted(get_objects_for_user(self.user, "change_ticket", Ticket).values_list("pk", flat=True)),
            sorted([self.project.pk, other.pk]),
        )
        self.assertEqual(list(get_objects_for_user(self.user, "change_supervisorreview", SupervisorReview)), [])
        self.assertEqual(list(get_objects_for_user(self.user, "change_project", Project)), [])

    def test_global_base_permission_does_not_grant_the_proxy(self):
        self.user.user_permissions.add(
            Permission.objects.get(content_type=ContentType.objects.get_for_model(Project), codename="change_project")
        )
        self.user = User.objects.get(pk=self.user.pk)

        self.assertTrue(self.user.has_perm("testapp.change_project"))
        # Global permissions never grant object-level access in Django's
        # ModelBackend, and they must not leak across proxy content types either.
        self.assertFalse(self.user.has_perm("change_project", self.project))
        self.assertFalse(self.user.has_perm("change_ticket", self.ticket))
        self.assertFalse(self.user.has_perm("change_supervisorreview", self.review))
        self.assertEqual(list(get_objects_for_user(self.user, "change_ticket", Ticket, accept_global_perms=True)), [])

    def test_base_codename_is_rejected_rather_than_silently_shared(self):
        # Starting from the permission (instead of klass) resolves the base
        # content type, and the proxy queryset can no longer match it.
        with self.assertRaises(MixedContentTypeError):
            get_objects_for_user(self.user, "testapp.change_project", klass=Ticket)
        # Starting from the proxy resolves the proxy's codenames, so the base
        # permission name does not exist for it.
        with self.assertRaises(Permission.DoesNotExist):
            assign_perm("change_project", self.user, self.ticket)

    def test_per_checker_cache_is_keyed_per_view(self):
        checker = ObjectPermissionChecker(self.user)
        assign_perm("change_ticket", self.user, self.ticket)

        self.assertTrue(checker.has_perm("change_ticket", self.ticket))
        self.assertFalse(checker.has_perm("change_supervisorreview", self.review))
        self.assertFalse(checker.has_perm("change_project", self.project))

    def test_proxy_permissions_are_created_for_the_proxy_content_type(self):
        self.assertEqual(
            set(get_perms_for_model(Ticket).values_list("codename", flat=True)),
            {"add_ticket", "change_ticket", "delete_ticket", "view_ticket"},
        )
        self.assertIn(
            "add_supervisorreview",
            set(get_perms_for_model(SupervisorReview).values_list("codename", flat=True)),
        )
        self.assertEqual(
            set(get_perms_for_model(Project).values_list("codename", flat=True)),
            {"add_project", "change_project", "delete_project", "view_project"},
        )


class ProxyInheritanceModeTests(TestCase):
    def setUp(self):
        self.project = Project.objects.create(name="shared")
        self.ticket = Ticket.objects.get(pk=self.project.pk)
        self.review = SupervisorReview.objects.get(pk=self.project.pk)
        self.user = User.objects.create_user(username="jack")

    def test_inherit_mode_restores_shared_base_permissions(self):
        with mock.patch.object(Ticket, "guardian_proxy_permission_mode", "inherit"):
            self.assertEqual(get_proxy_permission_mode(Ticket), "inherit")
            self.assertEqual(get_content_type(self.ticket), get_content_type(self.project))
            assign_perm("change_project", self.user, self.ticket)
            self.assertTrue(self.user.has_perm("change_project", self.project))
            self.assertEqual(list(get_objects_for_user(self.user, "change_project", Project)), [self.project])
            self.assertFalse(self.user.has_perm("change_project", self.review))

    def test_global_mode_applies_to_proxies_without_an_attribute(self):
        with (
            mock.patch.object(guardian_settings, "PROXY_PERMISSION_MODE", "isolate"),
            mock.patch.object(Ticket, "guardian_proxy_permission_mode", None),
        ):
            self.assertEqual(get_proxy_permission_mode(Ticket), "isolate")
            assign_perm("change_ticket", self.user, self.ticket)
            self.assertFalse(self.user.has_perm("change_project", self.project))

        with (
            mock.patch.object(guardian_settings, "PROXY_PERMISSION_MODE", "inherit"),
            mock.patch.object(Ticket, "guardian_proxy_permission_mode", None),
        ):
            self.assertEqual(get_proxy_permission_mode(Ticket), "inherit")

    def test_invalid_mode_is_rejected(self):
        with mock.patch.object(Ticket, "guardian_proxy_permission_mode", "shared"):
            with self.assertRaises(ValueError):
                get_content_type(Ticket)


class LegacyBaseContentTypeTests(TestCase):
    """Projects that pin GUARDIAN_GET_CONTENT_TYPE keep their old behaviour."""

    def setUp(self):
        self.project = Project.objects.create(name="legacy")
        self.ticket = Ticket.objects.get(pk=self.project.pk)
        self.user = User.objects.create_user(username="jill")

    def test_custom_content_type_function_overrides_proxy_isolation(self):
        with mock.patch.object(guardian_settings, "GET_CONTENT_TYPE", f"{__name__}.base_content_type"):
            self.assertEqual(get_content_type(self.ticket), base_content_type(self.ticket))
            assign_perm("change_project", self.user, self.ticket)
            self.assertTrue(self.user.has_perm("change_project", self.project))
            # Project has a direct permission model, so the grant lands there
            # with Project's own permission rather than a proxy permission.
            self.assertEqual(ProjectUserObjectPermission.objects.count(), 1)
            self.assertEqual(
                ProjectUserObjectPermission.objects.get().permission.content_type.model,
                "project",
            )

    def test_defaults_are_unchanged(self):
        self.assertEqual(guardian_settings.GET_CONTENT_TYPE, "guardian.ctypes.get_default_content_type")
        self.assertEqual(guardian_settings.PROXY_PERMISSION_MODE, "inherit")
