from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.test import TestCase

from guardian.core import ObjectPermissionChecker
from guardian.delegation import (
    DelegationQuerySetError,
    evaluate_delegation,
    make_shared_group_rule,
    permission_source,
)
from guardian.shortcuts import get_objects_for_user
from guardian.testapp.models import Project
from guardian.utils import get_user_obj_perms_model

User = get_user_model()


def project_perm(codename):
    return Permission.objects.get(content_type__app_label="testapp", codename=codename)


class DelegationFixtureTestCase(TestCase):
    """Two users with different direct permissions plus one shared group."""

    fixtures = ["delegation.json"]

    def setUp(self):
        self.actor = User.objects.get(username="delegator")
        self.principal = User.objects.get(username="principal")
        self.team = Group.objects.get(name="delegation-team")
        self.alpha = Project.objects.get(name="alpha")
        self.beta = Project.objects.get(name="beta")
        self.gamma = Project.objects.get(name="gamma")
        self.rule = make_shared_group_rule(
            name="team-cover",
            group=self.team,
            permissions=["change_project", "delete_project"],
        )

    def objects(self, **kwargs):
        return get_objects_for_user(
            self.actor,
            kwargs.pop("perms", ["testapp.change_project"]),
            Project.objects.all(),
            on_behalf_of=kwargs.pop("on_behalf_of", self.principal),
            delegation_rules=kwargs.pop("delegation_rules", [self.rule]),
            **kwargs,
        )

    def test_fixture_has_different_direct_permissions(self):
        self.assertTrue(self.actor.has_perm("change_project", self.alpha))
        self.assertFalse(self.principal.has_perm("change_project", self.alpha))
        self.assertFalse(self.actor.has_perm("change_project", self.gamma))
        self.assertTrue(self.principal.has_perm("change_project", self.gamma))
        self.assertTrue(self.actor.has_perm("delete_project", self.alpha))
        self.assertTrue(self.principal.has_perm("delete_project", self.alpha))

    def test_bulk_and_single_agree_on_change_project(self):
        expected = {self.beta.pk}
        bulk = set(self.objects().values_list("pk", flat=True))
        single = {
            obj.pk
            for obj in Project.objects.all()
            if ObjectPermissionChecker(self.actor).has_perm(
                "change_project", obj, on_behalf_of=self.principal, delegation_rules=[self.rule]
            )
        }
        self.assertEqual(bulk, expected)
        self.assertEqual(single, expected)

    def test_actor_only_object_is_excluded(self):
        self.assertFalse(
            ObjectPermissionChecker(self.actor).has_perm(
                "change_project", self.alpha, on_behalf_of=self.principal, delegation_rules=[self.rule]
            )
        )
        self.assertNotIn(self.alpha, self.objects())

    def test_principal_only_object_is_excluded(self):
        self.assertFalse(
            ObjectPermissionChecker(self.actor).has_perm(
                "change_project", self.gamma, on_behalf_of=self.principal, delegation_rules=[self.rule]
            )
        )
        self.assertNotIn(self.gamma, self.objects())

    def test_shared_group_permission_counts_for_both(self):
        # delete_project is granted by the shared group, so both parties hold it.
        result = self.objects(perms=["testapp.delete_project"])
        self.assertEqual(set(result.values_list("pk", flat=True)), {self.alpha.pk})
        self.assertTrue(
            ObjectPermissionChecker(self.actor).has_perm(
                "delete_project", self.alpha, on_behalf_of=self.principal, delegation_rules=[self.rule]
            )
        )

    def test_group_principal_in_bulk(self):
        result = self.objects(perms=["testapp.delete_project"], on_behalf_of=self.team)
        self.assertEqual(set(result.values_list("pk", flat=True)), {self.alpha.pk})

    def test_on_behalf_of_many_principals_unions(self):
        other = User.objects.create_user(username="other", email="other@example.com")
        other.groups.add(self.team)
        UserObjectPermission = get_user_obj_perms_model(self.alpha)
        UserObjectPermission.objects.create(
            user=other,
            permission=project_perm("change_project"),
            content_object=self.alpha,
        )
        result = self.objects(on_behalf_of=[self.principal, other])
        self.assertEqual(set(result.values_list("pk", flat=True)), {self.alpha.pk, self.beta.pk})

    def test_explain_identifies_who_limits_permission(self):
        checker = ObjectPermissionChecker(self.actor)
        allowed = checker.explain_perm(
            "change_project", self.beta, on_behalf_of=self.principal, delegation_rules=[self.rule]
        )
        self.assertTrue(allowed.allowed)
        self.assertEqual(allowed.blocked_by, None)
        self.assertEqual(allowed.actor_source.source, "direct")
        self.assertEqual(allowed.principal_source.source, "direct")

        principal_blocked = checker.explain_perm(
            "change_project", self.gamma, on_behalf_of=self.principal, delegation_rules=[self.rule]
        )
        self.assertFalse(principal_blocked.allowed)
        self.assertEqual(principal_blocked.blocked_by, "actor")
        self.assertIn("actor", principal_blocked.reason)

    def test_explain_without_principal_reports_candidates(self):
        checker = ObjectPermissionChecker(self.actor)
        explanation = checker.explain_perm("change_project", self.beta, delegation_rules=[self.rule])
        self.assertTrue(explanation.allowed)
        self.assertEqual(explanation.principal, self.principal)
        self.assertEqual(explanation.blocked_by, None)
        self.assertTrue(explanation.candidates)

    def test_principal_required_perm_is_traced(self):
        rule = make_shared_group_rule(
            name="needs-approval",
            group=self.team,
            permissions=["change_project"],
            principal_required_perm="delete_project",
        )
        checker = ObjectPermissionChecker(self.actor)
        beta = checker.explain_perm("change_project", self.beta, on_behalf_of=self.principal, delegation_rules=[rule])
        self.assertFalse(beta.allowed)
        self.assertEqual(beta.blocked_by, "principal_required")
        self.assertFalse(beta.required_source.allowed)

        gamma = checker.explain_perm("change_project", self.gamma, on_behalf_of=self.principal, delegation_rules=[rule])
        self.assertFalse(gamma.allowed)
        self.assertEqual(gamma.blocked_by, "actor")

    def test_no_rules_configured_fails_closed(self):
        self.assertFalse(
            ObjectPermissionChecker(self.actor).has_perm("change_project", self.beta, on_behalf_of=self.principal)
        )
        self.assertEqual(
            set(
                get_objects_for_user(
                    self.actor,
                    ["testapp.change_project"],
                    Project.objects.all(),
                    on_behalf_of=self.principal,
                ).values_list("pk", flat=True)
            ),
            set(),
        )

    def test_custom_rule_refused_for_bulk(self):
        class PerObjectOnlyRule:
            name = "per-object-only"

            def covers(self, codenames):
                return True

            def applies_to(self, perm, obj):
                return True

            def candidate_principals(self, actor):
                return []

            def allows(self, actor, principal, perm, obj):
                return False

        with self.assertRaises(DelegationQuerySetError):
            self.objects(delegation_rules=[PerObjectOnlyRule()])

    def test_delegation_writes_no_permission_rows(self):
        UserObjectPermission = get_user_obj_perms_model(self.beta)
        before = UserObjectPermission.objects.count()
        self.objects()
        list(
            ObjectPermissionChecker(self.actor).explain_perm(
                "change_project", self.beta, on_behalf_of=self.principal, delegation_rules=[self.rule]
            )
            for _ in range(2)
        )
        self.assertEqual(UserObjectPermission.objects.count(), before)

    def test_permission_source_reports_groups(self):
        source = permission_source(self.principal, "delete_project", self.alpha)
        self.assertTrue(source.allowed)
        self.assertFalse(source.direct)
        self.assertEqual(source.via_groups, ("delegation-team",))

    def test_rule_conditions_can_differ_between_objects(self):
        # The actor holds change on alpha and beta, the principal on beta and gamma:
        # the only mutual object is beta, regardless of iteration order.
        first = evaluate_delegation(self.actor, self.principal, "change_project", self.beta, [self.rule])
        second = evaluate_delegation(self.actor, self.principal, "change_project", self.alpha, [self.rule])
        self.assertTrue(first.allowed)
        self.assertFalse(second.allowed)
        self.assertEqual(first.rule_name, "team-cover")
