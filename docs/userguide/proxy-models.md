---
title: Proxy Models
description: Giving Django proxy models independent object permissions, or sharing the concrete model's permissions.
---

# Proxy Models

A Django [proxy model](https://docs.djangoproject.com/en/stable/topics/db/models/#proxy-models)
is a different Python class over the same database table. A common example is
one "ticket" table exposed as two views: a `Ticket` work-order view for
ordinary handlers and a `SupervisorReview` view for supervisors.

By default django-guardian resolves a proxy to its concrete model's
`ContentType`. That means both views share one set of object permissions:
whatever a supervisor may do to a row, an ordinary handler may do to the same
row. If the two views must be authorized separately, tell Guardian to isolate
the proxy.

## Choosing a rule

Three options are available, from least to most explicit:

| Option | Scope | Proxy content type | Use when |
|---|---|---|---|
| Do nothing | Project default | Concrete model | The proxy is only a presentation/behaviour variation and both views belong to the same authorization domain |
| `GUARDIAN_PROXY_PERMISSION_MODE = "isolate"` | Whole project | Each proxy, per model | Every proxy in the project should be a separate authorization domain |
| `guardian_proxy_permission_mode = "isolate"` on the proxy | One model | That proxy only | Only some proxies need separate authorization (recommended) |

The two modes are:

- **`"inherit"`** (default, historical behaviour) — the proxy uses the
  concrete model's content type. Permissions granted on the base model are
  visible through the proxy, and permissions granted through the proxy are
  stored against the base model, so they are visible to every inheriting
  proxy and to the base model itself.
- **`"isolate"`** — the proxy gets its own content type. Django creates a
  separate permission set for it (`add_ticket`, `change_ticket`,
  `delete_ticket`, `view_ticket`, plus any `Meta.permissions`), and its
  object permissions are stored with that content type. They are invisible to
  the other proxy and to the concrete model.

```python
from django.db import models

from myapp.models import Project


class Ticket(Project):
    guardian_proxy_permission_mode = "isolate"

    class Meta:
        proxy = True


class SupervisorReview(Project):
    guardian_proxy_permission_mode = "isolate"

    class Meta:
        proxy = True
```

The per-model attribute wins over the project-wide setting, so a project-wide
`"isolate"` policy can keep one proxy on `"inherit"`, and vice versa. Set the
attribute to `None` to fall back to the project-wide value. An unknown value
raises `ValueError` when permissions are first resolved for the model.

!!! note "Custom `GUARDIAN_GET_CONTENT_TYPE` wins"

    `GUARDIAN_PROXY_PERMISSION_MODE` is only consulted by the default
    content-type function. Applications that point
    `GUARDIAN_GET_CONTENT_TYPE` at their own function keep complete control:
    the custom function's result is authoritative and the proxy mode is
    ignored. This preserves existing deployments that map proxies to a base
    content type, for example polymorphic model libraries.

!!! warning "Run migrations after switching a proxy to isolate"

    The proxy's content type and its default permissions are created by
    Django's `migrate` command (`create_contenttypes` / `create_permissions`).
    Run `python manage.py migrate` after the change; otherwise permission
    codenames such as `change_ticket` do not exist yet and `assign_perm` will
    raise `Permission.DoesNotExist`.

## When inheriting the base model grant is appropriate

Use `"inherit"` when the proxy does **not** represent a different group of
actors. Typical cases:

- the proxy only changes the default manager, ordering, or `__str__`;
- the proxy only adds helper methods or admin configuration;
- the proxy is a compatibility alias kept during a refactor;
- a single role is allowed to act on a row, and the proxy merely controls how
  the row is displayed.

Use `"isolate"` when the answer to "may this role change this row?" can differ
between the views. If an ordinary handler may edit a ticket but must not be
able to approve it, that difference must live in the permission data, not in
view code that happens to check a different codename.

## Authorization matrix

The examples below use one `Project` row of `pk=1`, exposed as
`Ticket` and `SupervisorReview`, both configured with
`guardian_proxy_permission_mode = "isolate"`. Each row of the matrix is a
separate test; the grants do not accumulate.

| Operation | Base `Project` | `Ticket` view | `SupervisorReview` view |
|---|---|---|---|
| `assign_perm("change_ticket", user, ticket)` | no | **yes** | no |
| `assign_perm("change_ticket", group, ticket)`, user in group | no | **yes** | no |
| `assign_perm("change_supervisorreview", user, review)` | no | no | **yes** |
| `assign_perm("change_project", user, project)` | **yes** | no | no |
| `get_objects_for_user(user, "change_ticket", Ticket)` | – | row returned | not returned |
| `get_objects_for_user(user, "change_supervisorreview", SupervisorReview)` | not returned | – | row returned |
| `get_objects_for_user(user, "change_project", Project)` | row returned only after a base grant | not returned | not returned |
| `get_objects_for_group(group, "change_ticket", Ticket)` | – | row returned only for a ticket grant | not returned |
| `get_user_perms(user, review)` after a ticket grant | – | – | empty |
| `get_users_with_perms(review)` after a ticket grant | – | – | empty |
| `remove_perm("change_ticket", user, ticket)` | unchanged | removed | unchanged |

Key points:

- A direct grant and a group grant are both scoped to the content type of the
  view used to create them.
- Bulk reads are performed per content type as well. A user with a ticket
  grant is not returned by a supervisor-review query, and vice versa.
- The base model is a third, independent content type. A base grant does not
  flow into isolated proxies, and an isolated proxy grant does not flow into
  the base model.
- Permission codenames are per content type. `change_project` is not a valid
  codename on an isolated proxy; use `change_ticket` or
  `change_supervisorreview` instead. Passing the base codename to a proxy
  raises `Permission.DoesNotExist`, and mixing a fully qualified base
  permission with a proxy queryset raises `MixedContentTypeError` rather than
  silently returning rows.

## Combining isolated and inheriting proxies

Mixing is supported but easy to misread. Given `Ticket` with `"isolate"` and
`SupervisorReview` with `"inherit"`:

- a grant through `SupervisorReview` is stored against `Project`, so it is
  also visible on the `Project` instance and on the base model queryset;
- that same grant is **not** visible through `Ticket`, because `Ticket` reads
  its own content type;
- a base `Project` grant is visible through `SupervisorReview` (and through
  the proxy when `accept_global_perms` is in play) but never through `Ticket`.

For that reason, prefer one policy per concrete model and write the reason
next to the proxy class. If you need a temporary overlap, prefer granting to
the base model explicitly rather than relying on an inheriting proxy.

## Verifying a configuration

The test suite ships with `Ticket` and `SupervisorReview` proxy models and a
matrix test in `guardian/testapp/tests/test_proxy_permissions.py`; use it as a
template for your own application:

```python
from guardian.shortcuts import assign_perm, get_objects_for_user

assign_perm("change_ticket", user, Ticket.objects.get(pk=project.pk))

assert get_objects_for_user(user, "change_ticket", Ticket).exists()
assert not get_objects_for_user(
    user, "change_supervisorreview", SupervisorReview
).exists()
assert not get_objects_for_user(user, "change_project", Project).exists()
```

Also assert the reverse direction (grant on the review view, check the ticket
view), and assert the group-grant direction, so a future change to the proxy
mode cannot silently widen access.
