from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext

from guardian.core import ObjectPermissionChecker
from guardian.delegation import make_shared_group_rule
from guardian.shortcuts import get_objects_for_user
from guardian.testapp.models import Project

User = get_user_model()


class DelegationConsistencyTests(TestCase):
    """Property-style checks that bulk and per-object decisions agree."""

    def setUp(self):
        self.team = Group.objects.create(name="team")
        self.actor = User.objects.create_user(username="actor", email="a@example.com")
        self.principal = User.objects.create_user(username="principal", email="p@example.com")
        self.actor.groups.add(self.team)
        self.principal.groups.add(self.team)
        self.projects = [Project.objects.create(name=f"p{i}") for i in range(6)]
        self.rule = make_shared_group_rule(name="team-cover", group=self.team, permissions={"change_project"})

    def grant(self, user, obj, codename="change_project"):
        from guardian.utils import get_user_obj_perms_model

        get_user_obj_perms_model(obj).objects.get_or_create(
            user=user,
            permission=Permission.objects.get(content_type__app_label="testapp", codename=codename),
            content_object=obj,
        )

    def test_bulk_matches_every_single_check(self):
        for index, project in enumerate(self.projects):
            if index in {0, 2, 4}:
                self.grant(self.actor, project)
            if index in {2, 3, 5}:
                self.grant(self.principal, project)

        bulk = set(
            get_objects_for_user(
                self.actor,
                ["testapp.change_project"],
                Project.objects.all(),
                on_behalf_of=self.principal,
                delegation_rules=[self.rule],
            ).values_list("pk", flat=True)
        )
        checker = ObjectPermissionChecker(self.actor)
        single = {
            project.pk
            for project in self.projects
            if checker.has_perm("change_project", project, on_behalf_of=self.principal, delegation_rules=[self.rule])
        }
        self.assertEqual(bulk, single)
        self.assertEqual(bulk, {self.projects[2].pk})

    def test_bulk_matches_single_with_group_permissions(self):
        group = Group.objects.create(name="approvers")
        self.actor.groups.add(group)
        self.principal.groups.add(group)
        from guardian.utils import get_group_obj_perms_model

        for project in self.projects[:3]:
            get_group_obj_perms_model(project).objects.create(
                group=group,
                permission=Permission.objects.get(content_type__app_label="testapp", codename="change_project"),
                content_object=project,
            )
        bulk = set(
            get_objects_for_user(
                self.actor,
                ["testapp.change_project"],
                Project.objects.all(),
                on_behalf_of=self.principal,
                delegation_rules=[self.rule],
            ).values_list("pk", flat=True)
        )
        checker = ObjectPermissionChecker(self.actor)
        single = {
            project.pk
            for project in self.projects
            if checker.has_perm("change_project", project, on_behalf_of=self.principal, delegation_rules=[self.rule])
        }
        self.assertEqual(bulk, single)
        self.assertEqual(bulk, {project.pk for project in self.projects[:3]})

    def test_any_perm_matches_single(self):
        for index, project in enumerate(self.projects):
            if index in {0, 1}:
                self.grant(self.actor, project)
                self.grant(self.principal, project)
            if index == 2:
                self.grant(self.actor, project, "delete_project")
                self.grant(self.principal, project, "delete_project")
        rule = make_shared_group_rule(
            name="team-cover",
            group=self.team,
            permissions={"change_project", "delete_project"},
        )
        perms = ["testapp.change_project", "testapp.delete_project"]
        bulk = set(
            get_objects_for_user(
                self.actor,
                perms,
                Project.objects.all(),
                on_behalf_of=self.principal,
                delegation_rules=[rule],
                any_perm=True,
            ).values_list("pk", flat=True)
        )
        checker = ObjectPermissionChecker(self.actor)
        single = {
            project.pk
            for project in self.projects
            if checker.has_perm(perms[0], project, on_behalf_of=self.principal, delegation_rules=[rule])
            or checker.has_perm(perms[1], project, on_behalf_of=self.principal, delegation_rules=[rule])
        }
        self.assertEqual(bulk, single)
        self.assertEqual(bulk, {project.pk for project in self.projects[:3]})

    def test_explanation_does_not_query_per_object_loop(self):
        for project in self.projects:
            self.grant(self.actor, project)
            self.grant(self.principal, project)
        checker = ObjectPermissionChecker(self.actor)
        with CaptureQueriesContext(connection) as first:
            checker.explain_perm(
                "change_project", self.projects[0], on_behalf_of=self.principal, delegation_rules=[self.rule]
            )
        with CaptureQueriesContext(connection) as second:
            checker.explain_perm(
                "change_project", self.projects[1], on_behalf_of=self.principal, delegation_rules=[self.rule]
            )
        self.assertEqual(len(first), len(second))
