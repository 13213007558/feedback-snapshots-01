---
title: Delegated Permissions
description: Let one user exercise object permissions for another without writing grant rows.
---

# Delegated permissions

Some workflows need one person to act for another — a colleague completing a
batch approval, an assistant covering for someone on leave. Guardian supports
this with **delegation rules**. Delegation is evaluated at check time and never
writes rows to the object-permission tables.

The important property is that the same rule object drives both:

- `ObjectPermissionChecker.has_perm(..., on_behalf_of=...)` for one-object
  checks, and
- `get_objects_for_user(..., on_behalf_of=...)` for bulk queryset filtering.

A bulk action and the individual checks that guard each row therefore reach the
same conclusion. `ObjectPermissionChecker.explain_perm()` and
`guardian.delegation.evaluate_delegation()` expose which condition blocked a
permission.

## Defining a rule

`ObjectPermissionDelegationRule` is the declarative rule. The default
`require_actor_permission=True` means **both** the actor and the principal must
hold the permission on the object themselves:

```python
from guardian.delegation import ObjectPermissionDelegationRule

def my_reports(actor):
    return actor.profile.backup_for.all()  # users this actor covers

rule = ObjectPermissionDelegationRule(
    name="backup-approvals",
    permissions={"change_project", "delete_project"},
    principals=my_reports,
)
```

Rules are installed with the `GUARDIAN_DELEGATION_RULES` setting. It accepts a
callable returning rules, an iterable, a single rule, or a dotted path:

```python
# settings.py
GUARDIAN_DELEGATION_RULES = "myapp.delegation.rules"
```

```python
# myapp/delegation.py
from guardian.delegation import make_shared_group_rule

from django.contrib.auth.models import Group

def rules():
    return [
        make_shared_group_rule(
            name="team-cover",
            group=Group.objects.get(name="delegation-team"),
            permissions={"change_project"},
        )
    ]
```

With no rules configured, delegation fails closed: `on_behalf_of` checks return
`False` and bulk filtering returns an empty queryset.

## Shared teams

`make_shared_group_rule()` is the common "our team covers for each other" case.
Any member of the group may act for any other member (and the group itself):

```python
from guardian.delegation import make_shared_group_rule

rule = make_shared_group_rule(
    name="team-cover",
    group=team,
    permissions={"change_project"},
)
```

## Checking one object

```python
from guardian.core import ObjectPermissionChecker

checker = ObjectPermissionChecker(request.user)
if checker.has_perm("change_project", project, on_behalf_of=colleague):
    ...
```

Pass `delegation_rules=[...]` to override the setting for one call. This is
useful in tests and background jobs.

### Locating the limiting condition

```python
explanation = checker.explain_perm("change_project", project, on_behalf_of=colleague)

explanation.allowed          # final decision
explanation.rule_name        # rule that matched
explanation.blocked_by       # None, "actor", "principal", "principal_required" or "rule"
explanation.actor_source     # direct / group / superuser source
explanation.principal_source
explanation.required_source  # when principal_required_perm is set
explanation.candidates       # evaluated candidate principals
```

`explanation.reason` is a readable sentence for logs and admin displays.
`permission_source()` can be used on its own to inspect who holds a permission
and through which group.

## Filtering a queryset

```python
from guardian.shortcuts import get_objects_for_user

projects = get_objects_for_user(
    request.user,
    ["testapp.change_project"],
    Project.objects.all(),
    on_behalf_of=colleague,
)
```

`on_behalf_of` accepts a single user/group, a queryset, or a list. The result is
the union across principals, reusing the same rule conditions as the per-object
check.

## Requiring an approval permission

The permission being delegated is not always the only gate. Use
`principal_required_perm` to demand an additional permission from the principal:

```python
rule = ObjectPermissionDelegationRule(
    name="approved-change",
    permissions={"change_project"},
    principals=my_reports,
    principal_required_perm="approve_project",
)
```

`explain_perm()` then reports `blocked_by == "principal_required"` when the
principal lacks that approval.

## Custom rules

A custom rule implements `covers`, `applies_to`, `candidate_principals` and
`allows`. It works for per-object checks directly. Bulk filtering additionally
needs `allowed_objects`, because guardian must translate the rule into SQL
rather than evaluating every object in Python. Rules without `allowed_objects`
raise `DelegationQuerySetError` when used with `get_objects_for_user`, rather
than silently broadening the result.

```python
class ContractApprovedRule:
    name = "contract-approved"

    def covers(self, codenames):
        return "change_project" in codenames

    def applies_to(self, perm, obj):
        return obj._meta.label_lower == "testapp.project"

    def candidate_principals(self, actor):
        return [actor.profile.backup_for]

    def allows(self, actor, principal, perm, obj):
        return obj.contract_signed and actor == obj.backup_actor
```

## Security notes

- Delegation never grants permissions through global `User.user_permissions` or
  `Group.permissions`; it only changes the decision for the current check.
- Rules fail closed. Unknown principals, inactive users, self-delegation and
  missing rules all return `False`.
- Because the rule layer reads the same object-permission rows as normal checks,
  revoking a principal's permission immediately revokes the delegated ability.
