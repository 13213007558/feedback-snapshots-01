"""Contract tests for list and single-object authorization.

Every expected result is derived from permission rows read back through the
ORM (direct, group and global grants), never from the shortcut or backend
under test. Each scenario names the matching policy the business selected,
so a configuration change shows up in the failure report instead of silently
changing the expected set.

Deactivated subjects are expected to see nothing. ``get_objects_for_user``
currently still enumerates object grants for them; that documented gap is
pinned by a strict xfail so it flips to a failure as soon as an upgrade
changes the behavior in either direction.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.db.models import QuerySet
from django.test import TestCase

import pytest

from guardian.shortcuts import assign_perm, get_objects_for_user
from guardian.testapp.models import Project
from guardian.testapp.tests.conf import skipUnlessTestApp
from guardian.utils import get_group_obj_perms_model, get_user_obj_perms_model

User = get_user_model()

APP = "testapp"
VIEW = "view_project"
CHANGE = "change_project"
DELETE = "delete_project"
ADD = "add_project"


@dataclass(frozen=True)
class ListPolicy:
    """Business-selected matching policy passed to ``get_objects_for_user``."""

    label: str
    perms: tuple[str, ...]
    any_perm: bool = False
    use_groups: bool = True
    accept_global_perms: bool = True

    @property
    def full_perms(self) -> list[str]:
        return [f"{APP}.{perm}" for perm in self.perms]

    def describe(self) -> str:
        return (
            f"perms={self.perms} any_perm={self.any_perm} "
            f"use_groups={self.use_groups} accept_global_perms={self.accept_global_perms}"
        )


@dataclass(frozen=True)
class PermissionSnapshot:
    """ORM-backed permission facts for one subject."""

    is_active: bool
    direct: dict[int, frozenset[str]]
    group: dict[int, frozenset[str]]
    global_user: frozenset[str]
    global_group: frozenset[str]

    def object_perms(self, obj: Project, use_groups: bool) -> frozenset[str]:
        perms = set(self.direct.get(obj.pk, frozenset()))
        if use_groups:
            perms.update(self.group.get(obj.pk, frozenset()))
        return frozenset(perms)

    def effective_global_perms(self, accept_global_perms: bool) -> frozenset[str]:
        if not accept_global_perms or not self.is_active:
            return frozenset()
        return self.global_user | self.global_group


def read_object_perms(
    model, user_or_group_filter: dict, generic: bool, ctype: ContentType
) -> dict[int, frozenset[str]]:
    """Reads object grants for a permission model and normalizes the object pk."""
    filters = dict(user_or_group_filter)
    if generic:
        pk_field = "object_pk"
        filters["content_type"] = ctype
    else:
        pk_field = "content_object_id"
    rows = model.objects.filter(**filters).values_list(pk_field, "permission__codename")

    grants: defaultdict[int, set[str]] = defaultdict(set)
    for object_pk, codename in rows:
        grants[int(object_pk)].add(codename)
    return {pk: frozenset(codenames) for pk, codenames in grants.items()}


def read_permission_snapshot(user) -> PermissionSnapshot:
    user_model = get_user_obj_perms_model(Project)
    group_model = get_group_obj_perms_model(Project)
    ctype = ContentType.objects.get_for_model(Project)

    is_active = User.objects.filter(pk=user.pk).values_list("is_active", flat=True).get()

    return PermissionSnapshot(
        is_active=is_active,
        direct=read_object_perms(
            user_model,
            {"user": user},
            generic=user_model.objects.is_generic(),
            ctype=ctype,
        ),
        group=read_object_perms(
            group_model,
            {"group__in": user.groups.all()},
            generic=group_model.objects.is_generic(),
            ctype=ctype,
        ),
        global_user=frozenset(user.user_permissions.filter(content_type=ctype).values_list("codename", flat=True)),
        global_group=frozenset(
            Permission.objects.filter(group__in=user.groups.all(), content_type=ctype).values_list(
                "codename", flat=True
            )
        ),
    )


def list_visible(snapshot: PermissionSnapshot, policy: ListPolicy, obj: Project) -> bool:
    """Business rule: a deactivated subject is never authorized."""
    if not snapshot.is_active:
        return False
    global_perms = snapshot.effective_global_perms(policy.accept_global_perms)
    object_perms = snapshot.object_perms(obj, use_groups=policy.use_groups)
    verdicts = [perm in global_perms or perm in object_perms for perm in policy.perms]
    return any(verdicts) if policy.any_perm else all(verdicts)


def detail_visible(snapshot: PermissionSnapshot, perm: str, obj: Project) -> bool:
    """Business rule: deactivated subjects are denied; global grants do not apply."""
    return snapshot.is_active and perm in snapshot.object_perms(obj, use_groups=True)


def detail_visible_for_policy(snapshot: PermissionSnapshot, policy: ListPolicy, obj: Project) -> bool:
    verdicts = [detail_visible(snapshot, perm, obj) for perm in policy.perms]
    return any(verdicts) if policy.any_perm else all(verdicts)


ACTIVE_LIST_POLICIES = (
    ListPolicy("view-any-source", (VIEW,)),
    ListPolicy("view-direct-only", (VIEW,), use_groups=False),
    ListPolicy("view-and-change-all", (VIEW, CHANGE)),
    ListPolicy("view-and-change-all-direct-only", (VIEW, CHANGE), use_groups=False),
    ListPolicy("view-and-change-any", (VIEW, CHANGE), any_perm=True),
    ListPolicy("view-and-add-all", (VIEW, ADD)),
    ListPolicy("view-and-add-any", (VIEW, ADD), any_perm=True),
    ListPolicy("add-global", (ADD,)),
    ListPolicy("add-object-only-global-ignored", (ADD,), accept_global_perms=False),
    ListPolicy("add-global-without-groups", (ADD,), use_groups=False),
    ListPolicy("delete-global-via-group", (DELETE,)),
    ListPolicy("delete-global-without-groups", (DELETE,), use_groups=False),
    ListPolicy("delete-object-only-global-ignored", (DELETE,), accept_global_perms=False),
)

# Objects inside the restricted queryset. Objects granted outside these names
# ("outside_scope" and "inactive_outside_scope") must never appear.
RESTRICTED_NAMES = (
    "direct_view",
    "group_view",
    "direct_and_group",
    "group_split",
    "all_three",
    "foreign_group",
    "unassigned",
)

RESTRICTED_LIST_POLICIES = (
    ListPolicy("restricted-view-any-source", (VIEW,), accept_global_perms=False),
    ListPolicy("restricted-view-and-change-all", (VIEW, CHANGE), accept_global_perms=False),
    ListPolicy("restricted-view-and-change-any", (VIEW, CHANGE), any_perm=True, accept_global_perms=False),
    ListPolicy("restricted-add-global", (ADD,)),
    ListPolicy("restricted-delete-global", (DELETE,)),
    ListPolicy("restricted-delete-object-only", (DELETE,), accept_global_perms=False),
)

INACTIVE_LIST_POLICIES = (
    ListPolicy("inactive-view-any-source", (VIEW,), accept_global_perms=False),
    ListPolicy("inactive-view-direct-only", (VIEW,), use_groups=False, accept_global_perms=False),
    ListPolicy("inactive-view-and-change-all", (VIEW, CHANGE), accept_global_perms=False),
    ListPolicy("inactive-view-and-change-any", (VIEW, CHANGE), any_perm=True, accept_global_perms=False),
    ListPolicy("inactive-view-global-config", (VIEW,)),
    ListPolicy("inactive-add-global-assigned", (ADD,)),
    ListPolicy("inactive-delete-group-global-assigned", (DELETE,)),
)

INACTIVE_RESTRICTED_NAMES = (
    "inactive_direct",
    "inactive_group",
    "inactive_both",
    "direct_view",
    "outside_scope",
)

INACTIVE_RESTRICTED_POLICIES = (
    ListPolicy("inactive-restricted-view", (VIEW,), accept_global_perms=False),
    ListPolicy("inactive-restricted-add-global", (ADD,)),
)

DETAIL_POLICIES = (
    *(ListPolicy(f"detail-{perm}", (perm,), accept_global_perms=False) for perm in (VIEW, CHANGE, ADD, DELETE)),
    ListPolicy("detail-view-and-change-all", (VIEW, CHANGE), accept_global_perms=False),
    ListPolicy("detail-view-and-change-any", (VIEW, CHANGE), any_perm=True, accept_global_perms=False),
)


@skipUnlessTestApp
class AuthorizationContractTest(TestCase):
    """List visibility and per-object detail decisions for one grant matrix."""

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create_user("contract-active")
        cls.inactive = User.objects.create_user("contract-inactive", is_active=False)

        cls.team_a = Group.objects.create(name="contract-team-a")
        cls.team_b = Group.objects.create(name="contract-team-b")
        cls.team_inactive = Group.objects.create(name="contract-team-inactive")
        cls.outsider = Group.objects.create(name="contract-outsider")
        cls.user.groups.add(cls.team_a, cls.team_b)
        cls.inactive.groups.add(cls.team_inactive)

        names = (
            "direct_view",
            "group_view",
            "direct_and_group",
            "group_split",
            "all_three",
            "partial_combined",
            "direct_both",
            "unassigned",
            "foreign_group",
            "outside_scope",
            "inactive_direct",
            "inactive_group",
            "inactive_both",
            "inactive_outside_scope",
        )
        cls.projects = {name: Project.objects.create(name=name) for name in names}
        p = cls.projects

        # Active subject: direct grants.
        assign_perm(VIEW, cls.user, p["direct_view"])
        assign_perm(VIEW, cls.user, p["direct_and_group"])
        assign_perm(VIEW, cls.user, p["all_three"])
        assign_perm(CHANGE, cls.user, p["all_three"])
        assign_perm(DELETE, cls.user, p["all_three"])
        assign_perm(VIEW, cls.user, p["direct_both"])
        assign_perm(CHANGE, cls.user, p["direct_both"])
        assign_perm(VIEW, cls.user, p["outside_scope"])

        # Active subject: group grants.
        assign_perm(VIEW, cls.team_a, p["group_view"])
        assign_perm(CHANGE, cls.team_a, p["direct_and_group"])
        assign_perm(VIEW, cls.team_a, p["group_split"])
        assign_perm(CHANGE, cls.team_b, p["group_split"])
        assign_perm(CHANGE, cls.team_a, p["all_three"])
        assign_perm(CHANGE, cls.team_a, p["partial_combined"])
        assign_perm(VIEW, cls.outsider, p["foreign_group"])

        # Inactive subject: direct and group grants that must not authorize.
        assign_perm(VIEW, cls.inactive, p["inactive_direct"])
        assign_perm(VIEW, cls.team_inactive, p["inactive_group"])
        assign_perm(VIEW, cls.inactive, p["inactive_both"])
        assign_perm(CHANGE, cls.team_inactive, p["inactive_both"])
        assign_perm(VIEW, cls.inactive, p["inactive_outside_scope"])

        # Global grants: one directly on the user, one through a group.
        assign_perm(f"{APP}.{ADD}", cls.user)
        assign_perm(f"{APP}.{DELETE}", cls.team_a)
        assign_perm(f"{APP}.{ADD}", cls.inactive)
        assign_perm(f"{APP}.{DELETE}", cls.team_inactive)

    def _report(
        self,
        scenario: str,
        policy: ListPolicy,
        snapshot: PermissionSnapshot,
        base_objects: list[Project],
        expected: list[Project],
        actual: list[Project],
    ) -> str:
        expected_pks = {obj.pk for obj in expected}
        actual_pks = {obj.pk for obj in actual}
        base_pks = {obj.pk for obj in base_objects}
        reported_objects = list(base_objects) + [obj for obj in actual if obj.pk not in base_pks]

        lines = [
            f"scenario: {scenario}",
            f"policy: {policy.describe()}",
            f"subject: is_active={snapshot.is_active}",
            f"orm grants: user_global={sorted(snapshot.global_user)} "
            f"group_global={sorted(snapshot.global_group)} "
            f"honored_global={sorted(snapshot.effective_global_perms(policy.accept_global_perms))}",
            f"queryset: {sorted(obj.name for obj in base_objects)}",
            f"expected: {sorted(obj.name for obj in expected)}",
            f"actual: {sorted(obj.name for obj in actual)}",
            f"missing: {sorted(obj.name for obj in expected if obj.pk not in actual_pks)}",
            f"extra: {sorted(obj.name for obj in actual if obj.pk not in expected_pks)}",
            "per-object:",
        ]
        for obj in sorted(reported_objects, key=lambda item: item.name):
            lines.append(
                f"  {obj.name}: expected={obj.pk in expected_pks} actual={obj.pk in actual_pks} "
                f"direct={sorted(snapshot.direct.get(obj.pk, ()))} "
                f"group={sorted(snapshot.group.get(obj.pk, ()))}"
            )
        return "\n".join(lines)

    def _assert_list_contract(self, user, policy: ListPolicy, queryset, scenario: str):
        snapshot = read_permission_snapshot(user)
        base_objects = list(queryset)
        expected = [obj for obj in base_objects if list_visible(snapshot, policy, obj)]
        actual_qs = get_objects_for_user(
            user,
            policy.full_perms,
            queryset,
            use_groups=policy.use_groups,
            any_perm=policy.any_perm,
            accept_global_perms=policy.accept_global_perms,
        )
        self.assertIsInstance(actual_qs, QuerySet)
        actual = list(actual_qs)
        self.assertEqual(
            sorted(obj.name for obj in actual),
            sorted(obj.name for obj in expected),
            self._report(scenario, policy, snapshot, base_objects, expected, actual),
        )

    def _assert_detail_contract(self, user, policy: ListPolicy, queryset, scenario: str):
        snapshot = read_permission_snapshot(user)
        base_objects = list(queryset)
        expected = [obj for obj in base_objects if detail_visible_for_policy(snapshot, policy, obj)]
        full_perms = policy.full_perms
        if policy.any_perm:
            actual = [obj for obj in base_objects if any(user.has_perm(perm, obj) for perm in full_perms)]
        else:
            actual = [obj for obj in base_objects if user.has_perms(full_perms, obj)]
        self.assertEqual(
            sorted(obj.name for obj in actual),
            sorted(obj.name for obj in expected),
            self._report(scenario, policy, snapshot, base_objects, expected, actual),
        )

    def _inactive_list_breaches(self, queryset, policies, surface: str) -> list[str]:
        """Collects every deactivated-subject list result that leaks an object."""
        snapshot = read_permission_snapshot(self.inactive)
        base_objects = list(queryset)
        breaches = []
        for policy in policies:
            actual = list(
                get_objects_for_user(
                    self.inactive,
                    policy.full_perms,
                    queryset,
                    use_groups=policy.use_groups,
                    any_perm=policy.any_perm,
                    accept_global_perms=policy.accept_global_perms,
                )
            )
            if actual:
                breaches.append(
                    self._report(
                        f"{surface}/{policy.label}",
                        policy,
                        snapshot,
                        base_objects,
                        [],
                        actual,
                    )
                )
        return breaches

    # List contract

    def test_active_list_contract(self):
        for policy in ACTIVE_LIST_POLICIES:
            with self.subTest(scenario=policy.label):
                self._assert_list_contract(
                    self.user,
                    policy,
                    Project.objects.all(),
                    f"list/active/{policy.label}",
                )

    def test_active_list_contract_is_scoped_to_the_given_queryset(self):
        queryset = Project.objects.filter(name__in=RESTRICTED_NAMES)
        for policy in RESTRICTED_LIST_POLICIES:
            with self.subTest(scenario=policy.label):
                self._assert_list_contract(
                    self.user,
                    policy,
                    queryset,
                    f"list/active/restricted/{policy.label}",
                )

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "Documented contract: inactive users receive empty results from guardian shortcuts, "
            "but get_objects_for_user still enumerates object grants. This becomes XPASS once the "
            "upgrade fixes the behavior, and fails if the leak changes shape."
        ),
    )
    def test_inactive_list_contract(self):
        breaches = self._inactive_list_breaches(
            Project.objects.all(),
            INACTIVE_LIST_POLICIES,
            "list/inactive",
        )
        self.assertEqual(breaches, [], "\n\n".join(breaches))

    @pytest.mark.xfail(
        strict=True,
        reason=(
            "Documented contract: inactive users receive empty results from guardian shortcuts, "
            "but get_objects_for_user still enumerates object grants inside the given queryset."
        ),
    )
    def test_inactive_list_contract_is_scoped_to_the_given_queryset(self):
        breaches = self._inactive_list_breaches(
            Project.objects.filter(name__in=INACTIVE_RESTRICTED_NAMES),
            INACTIVE_RESTRICTED_POLICIES,
            "list/inactive/restricted",
        )
        self.assertEqual(breaches, [], "\n\n".join(breaches))

    # Detail contract

    def test_active_detail_contract(self):
        for policy in DETAIL_POLICIES:
            with self.subTest(scenario=policy.label):
                self._assert_detail_contract(
                    self.user,
                    policy,
                    Project.objects.all(),
                    f"detail/active/{policy.label}",
                )

    def test_inactive_detail_contract(self):
        for policy in DETAIL_POLICIES:
            with self.subTest(scenario=policy.label):
                self._assert_detail_contract(
                    self.inactive,
                    policy,
                    Project.objects.all(),
                    f"detail/inactive/{policy.label}",
                )

    # Cross-surface contract

    def test_list_and_detail_agree_when_global_permissions_are_excluded(self):
        queryset = Project.objects.all()
        policies = (
            ListPolicy("agree-view", (VIEW,), accept_global_perms=False),
            ListPolicy("agree-view-and-change-all", (VIEW, CHANGE), accept_global_perms=False),
            ListPolicy("agree-view-and-change-any", (VIEW, CHANGE), any_perm=True, accept_global_perms=False),
        )
        for policy in policies:
            with self.subTest(scenario=policy.label):
                snapshot = read_permission_snapshot(self.user)
                base_objects = list(queryset)
                actual = list(
                    get_objects_for_user(
                        self.user,
                        policy.full_perms,
                        queryset,
                        use_groups=True,
                        any_perm=policy.any_perm,
                        accept_global_perms=False,
                    )
                )
                expected = [obj for obj in base_objects if detail_visible_for_policy(snapshot, policy, obj)]
                self.assertEqual(
                    sorted(obj.name for obj in actual),
                    sorted(obj.name for obj in expected),
                    self._report(
                        f"cross-surface/agree/{policy.label}",
                        policy,
                        snapshot,
                        base_objects,
                        expected,
                        actual,
                    ),
                )

    def test_list_expands_to_queryset_for_global_permission_while_detail_does_not(self):
        policy = ListPolicy("global-add-divergence", (ADD,))
        snapshot = read_permission_snapshot(self.user)
        base_objects = list(Project.objects.all())
        actual = list(get_objects_for_user(self.user, policy.full_perms, Project.objects.all()))
        self.assertEqual(
            sorted(obj.name for obj in actual),
            sorted(obj.name for obj in base_objects),
            self._report(
                "cross-surface/global/list-honors-global",
                policy,
                snapshot,
                base_objects,
                base_objects,
                actual,
            ),
        )

        detail_actual = [obj for obj in base_objects if self.user.has_perm(f"{APP}.{ADD}", obj)]
        self.assertEqual(
            detail_actual,
            [],
            self._report(
                "cross-surface/global/detail-ignores-global",
                policy,
                snapshot,
                base_objects,
                [],
                detail_actual,
            ),
        )

    def test_inactive_detail_denies_regardless_of_object_grants(self):
        policy = ListPolicy("inactive-detail-divergence", (VIEW,), accept_global_perms=False)
        snapshot = read_permission_snapshot(self.inactive)
        base_objects = list(Project.objects.all())
        granted = [obj for obj in base_objects if snapshot.object_perms(obj, use_groups=True)]
        self.assertNotEqual(granted, [], "fixture must grant the inactive subject at least one object")

        detail_actual = [obj for obj in base_objects if self.inactive.has_perm(f"{APP}.{VIEW}", obj)]
        self.assertEqual(
            detail_actual,
            [],
            self._report(
                "cross-surface/inactive/detail-denies",
                policy,
                snapshot,
                base_objects,
                [],
                detail_actual,
            ),
        )
