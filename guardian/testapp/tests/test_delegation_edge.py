from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.test import TestCase

from guardian.core import ObjectPermissionChecker
from guardian.delegation import (
    ObjectPermissionDelegationRule,
    evaluate_delegation,
    get_delegation_rules,
    permission_source,
)
from guardian.testapp.models import Project
from guardian.utils import get_group_obj_perms_model, get_user_obj_perms_model

User = get_user_model()


def perm(codename):
    return Permission.objects.get(content_type__app_label="testapp", codename=codename)


class DelegationEdgeTests(TestCase):
    def setUp(self):
        self.actor = User.objects.create_user(username="actor", email="actor@example.com")
        self.principal = User.objects.create_user(username="principal", email="p@example.com")
        self.outsider = User.objects.create_user(username="outsider", email="o@example.com")
        self.alpha = Project.objects.create(name="alpha")
        self.beta = Project.objects.create(name="beta")
        self.rule = ObjectPermissionDelegationRule(
            name="named-principal",
            permissions={"change_project"},
            principals=lambda actor: [self.principal],
        )

    def grant(self, user, codename, obj):
        model = get_user_obj_perms_model(obj)
        return model.objects.create(user=user, permission=perm(codename), content_object=obj)

    def test_incorrect_principal_is_not_delegated(self):
        self.grant(self.actor, "change_project", self.alpha)
        self.grant(self.outsider, "change_project", self.alpha)
        evaluation = evaluate_delegation(self.actor, self.outsider, "change_project", self.alpha, [self.rule])
        self.assertFalse(evaluation.allowed)
        self.assertIn("not a candidate", evaluation.reason)

    def test_actor_missing_own_permission_is_reported(self):
        self.grant(self.principal, "change_project", self.alpha)
        evaluation = evaluate_delegation(self.actor, self.principal, "change_project", self.alpha, [self.rule])
        self.assertFalse(evaluation.allowed)
        self.assertEqual(evaluation.blocked_by, "actor")
        self.assertFalse(evaluation.actor_source.allowed)

    def test_principal_missing_permission_is_reported(self):
        self.grant(self.actor, "change_project", self.alpha)
        evaluation = evaluate_delegation(self.actor, self.principal, "change_project", self.alpha, [self.rule])
        self.assertFalse(evaluation.allowed)
        self.assertEqual(evaluation.blocked_by, "principal")
        self.assertTrue(evaluation.actor_source.allowed)

    def test_require_actor_permission_false_allows_one_sided_principal(self):
        rule = ObjectPermissionDelegationRule(
            name="principal-only",
            permissions={"change_project"},
            principals=lambda actor: [self.principal],
            require_actor_permission=False,
        )
        self.grant(self.principal, "change_project", self.alpha)
        self.assertTrue(
            ObjectPermissionChecker(self.actor).has_perm(
                "change_project", self.alpha, on_behalf_of=self.principal, delegation_rules=[rule]
            )
        )

    def test_permission_scope_is_limited(self):
        self.grant(self.actor, "change_project", self.alpha)
        self.grant(self.principal, "change_project", self.alpha)
        self.assertFalse(
            ObjectPermissionChecker(self.actor).has_perm(
                "delete_project", self.alpha, on_behalf_of=self.principal, delegation_rules=[self.rule]
            )
        )

    def test_content_type_scope_is_limited(self):
        rule = ObjectPermissionDelegationRule(
            name="projects-only",
            permissions={"change_project"},
            principals=lambda actor: [self.principal],
            content_types=[Project],
        )
        self.grant(self.actor, "change_project", self.alpha)
        self.grant(self.principal, "change_project", self.alpha)
        self.assertTrue(evaluate_delegation(self.actor, self.principal, "change_project", self.alpha, [rule]).allowed)
        self.assertTrue(rule.applies_to("change_project", self.alpha))

    def test_inactive_actor_is_denied(self):
        self.grant(self.actor, "change_project", self.alpha)
        self.grant(self.principal, "change_project", self.alpha)
        self.actor.is_active = False
        self.actor.save(update_fields=["is_active"])
        self.assertFalse(
            ObjectPermissionChecker(self.actor).has_perm(
                "change_project", self.alpha, on_behalf_of=self.principal, delegation_rules=[self.rule]
            )
        )

    def test_settings_rule_factory_is_used(self):
        with self.settings(GUARDIAN_DELEGATION_RULES=lambda: [self.rule]):
            self.assertEqual(len(get_delegation_rules()), 1)
            self.grant(self.actor, "change_project", self.alpha)
            self.grant(self.principal, "change_project", self.alpha)
            self.assertTrue(
                ObjectPermissionChecker(self.actor).has_perm("change_project", self.alpha, on_behalf_of=self.principal)
            )

    def test_superuser_principal_is_approved(self):
        superuser = User.objects.create_superuser(username="root", email="root@example.com", password="x")
        self.grant(self.actor, "change_project", self.alpha)
        source = permission_source(superuser, "change_project", self.alpha)
        self.assertTrue(source.allowed)
        self.assertEqual(source.source, "superuser")

    def test_group_principal_source_is_direct(self):
        group = Group.objects.create(name="group")
        model = get_group_obj_perms_model(self.alpha)
        model.objects.create(group=group, permission=perm("change_project"), content_object=self.alpha)
        source = permission_source(group, "change_project", self.alpha)
        self.assertTrue(source.allowed)
        self.assertTrue(source.direct)

    def test_group_actor_is_refused_even_with_rules(self):
        self.grant(self.actor, "change_project", self.alpha)
        self.grant(self.principal, "change_project", self.alpha)
        group = Group.objects.create(name="actor-group")
        evaluation = evaluate_delegation(group, self.principal, "change_project", self.alpha, [self.rule])
        self.assertFalse(evaluation.allowed)
        self.assertIn("user actor", evaluation.reason)

    def test_inactive_principal_is_not_a_candidate(self):
        self.grant(self.actor, "change_project", self.alpha)
        self.grant(self.principal, "change_project", self.alpha)
        self.principal.is_active = False
        self.principal.save(update_fields=["is_active"])
        self.assertFalse(
            ObjectPermissionChecker(self.actor).has_perm(
                "change_project", self.alpha, on_behalf_of=self.principal, delegation_rules=[self.rule]
            )
        )
