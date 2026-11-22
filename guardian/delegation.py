"""Delegated object-permission rules.

A delegation rule lets an *actor* exercise an object permission for another
*principal* — for example an employee completing a batch action for a
colleague who is away. Delegation is evaluated at check time and never writes
rows to the object-permission tables.

The same rule objects are used by:

* :class:`guardian.core.ObjectPermissionChecker` for one-object checks
  (``has_perm(..., on_behalf_of=...)`` and ``explain_perm(...)``).
* :func:`guardian.shortcuts.get_objects_for_user` for bulk filtering
  (``on_behalf_of=...``).

Because both paths call the same rule conditions, a bulk result and the
per-object checks that guard each row reach the same conclusion.

Rules are installed in one of two ways:

* ``GUARDIAN_DELEGATION_RULES`` — a callable returning rules, an iterable of
  rules, a single rule, or a dotted path resolving to one of those.
* The ``delegation_rules=`` argument on the checker/shortcut, which overrides
  the setting for that call.

Object permissions alone are not always enough. Use
``principal_required_perm`` to demand an additional approval permission from
the principal. Both the actor's and the principal's permissions are checked by
default (``require_actor_permission=True``), which is what enforces "both
people must be approved". :func:`evaluate_delegation` reports which side
blocked a permission so callers can trace a decision back to its condition.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from django.conf import settings as django_settings
from django.contrib.auth import get_user_model
from django.db.models import Model, QuerySet
from django.utils.module_loading import import_string

from guardian.conf import settings as guardian_settings
from guardian.ctypes import get_content_type
from guardian.exceptions import GuardianError
from guardian.utils import get_anonymous_user, get_group_obj_perms_model, get_user_obj_perms_model


class DelegationQuerySetError(GuardianError):
    """Raised when a rule cannot be translated into a queryset filter.

    Custom rules that want to support bulk filtering must implement
    ``allowed_objects``; rules that only implement ``allows`` are still usable
    for per-object checks.
    """


def _codename(perm: str) -> str:
    """Return the bare codename from ``app_label.codename`` or a codename."""
    if "." in perm:
        return perm.rsplit(".", 1)[1]
    return perm


def _model_from_object(obj: Model | type[Model]) -> type[Model]:
    return obj if isinstance(obj, type) and issubclass(obj, Model) else type(obj)


def _identity_key(identity: Any) -> tuple[str, Any] | None:
    if identity is None:
        return None
    if isinstance(identity, get_user_model()):
        if not identity.is_active:
            return None
        return ("user", identity.pk)
    group_model = get_group_obj_perms_model().group.field.related_model
    if isinstance(identity, group_model):
        return ("group", identity.pk)
    return None


def _filter_rows_by_object(rows: QuerySet, obj: Model) -> QuerySet:
    model = rows.model
    if model.objects.is_generic():
        return rows.filter(content_type=get_content_type(obj), object_pk=str(obj.pk))
    return rows.filter(content_object=obj)


@dataclass(frozen=True)
class PermissionSource:
    """Where one identity's permission on one object comes from.

    Attributes:
        allowed: Whether the identity effectively holds the permission.
        direct: A row assigned directly to the identity.
        via_groups: Names of groups that grant the permission.
        superuser: The identity is an active superuser.
    """

    allowed: bool
    direct: bool = False
    via_groups: tuple[str, ...] = ()
    superuser: bool = False

    @property
    def source(self) -> str | None:
        """Human-readable source: ``superuser``, ``direct``, ``group`` or none."""
        if not self.allowed:
            return None
        if self.superuser:
            return "superuser"
        if self.direct:
            return "direct"
        if self.via_groups:
            return "group"
        return "none"

    @property
    def reason(self) -> str:
        """Explain the source in one sentence."""
        if not self.allowed:
            return "no direct or group permission"
        if self.superuser:
            return "active superuser"
        if self.direct:
            return "direct permission"
        return "permission from groups: " + ", ".join(self.via_groups)


def permission_source(identity: Any, perm: str, obj: Model) -> PermissionSource:
    """Describe how ``identity`` holds ``perm`` on ``obj``.

    The lookup includes direct object permissions and permissions inherited
    through group membership, matching ``user.has_perm(perm, obj)``. Model-wide
    global permissions are intentionally not treated as object approvals. It
    does not consult delegation rules, so callers can inspect the underlying
    approval conditions.
    """
    codename = _codename(perm)
    key = _identity_key(identity)
    if key is None:
        return PermissionSource(False)

    kind, _ = key
    if kind == "user":
        user = identity
        if not user.is_active:
            return PermissionSource(False)
        if user.is_superuser:
            return PermissionSource(True, superuser=True)
        ctype = get_content_type(obj)
        user_rows = _filter_rows_by_object(
            get_user_obj_perms_model(obj).objects.filter(
                user=user,
                permission__codename=codename,
                permission__content_type=ctype,
            ),
            obj,
        )
        group_rows = _filter_rows_by_object(
            get_group_obj_perms_model(obj).objects.filter(
                group__user=user,
                permission__codename=codename,
                permission__content_type=ctype,
            ),
            obj,
        )
        direct = user_rows.exists()
        groups = tuple(sorted(set(group_rows.values_list("group__name", flat=True))))
        return PermissionSource(bool(direct or groups), direct=direct, via_groups=groups)

    group = identity
    ctype = get_content_type(obj)
    rows = _filter_rows_by_object(
        get_group_obj_perms_model(obj).objects.filter(
            group=group,
            permission__codename=codename,
            permission__content_type=ctype,
        ),
        obj,
    )
    direct = rows.exists()
    return PermissionSource(direct, direct=direct)


@dataclass(frozen=True)
class RuleEvaluation:
    """One rule's decision for one actor/principal/permission/object tuple."""

    applicable: bool
    allowed: bool
    reason: str
    rule_name: str
    principal: Any = None
    actor_source: PermissionSource | None = None
    principal_source: PermissionSource | None = None
    required_source: PermissionSource | None = None


@dataclass(frozen=True)
class DelegationEvaluation:
    """Structured result of evaluating every configured rule once."""

    allowed: bool
    reason: str
    principal: Any = None
    rule_name: str | None = None
    actor_source: PermissionSource | None = None
    principal_source: PermissionSource | None = None
    required_source: PermissionSource | None = None

    @property
    def blocked_by(self) -> str | None:
        """Which condition blocked the permission: actor, principal, required, rule."""
        if self.allowed:
            return None
        if self.actor_source is not None and not self.actor_source.allowed:
            return "actor"
        if self.principal_source is not None and not self.principal_source.allowed:
            return "principal"
        if self.required_source is not None and not self.required_source.allowed:
            return "principal_required"
        return "rule"


@dataclass(frozen=True)
class PermissionExplanation:
    """Full explanation of one permission check, including delegation."""

    allowed: bool
    perm: str
    reason: str
    rule_name: str | None = None
    principal: Any = None
    actor_source: PermissionSource | None = None
    principal_source: PermissionSource | None = None
    required_source: PermissionSource | None = None
    candidates: tuple[DelegationEvaluation, ...] = ()

    @property
    def blocked_by(self) -> str | None:
        """Which condition blocked the permission: actor, principal, required, rule."""
        if self.allowed:
            return None
        if self.actor_source is not None and not self.actor_source.allowed:
            return "actor"
        if self.principal_source is not None and not self.principal_source.allowed:
            return "principal"
        if self.required_source is not None and not self.required_source.allowed:
            return "principal_required"
        return "rule"


@runtime_checkable
class DelegationRule(Protocol):
    """Protocol implemented by delegation rules.

    Rules are consulted only after the actor's own permission check, or
    directly when ``on_behalf_of`` is supplied. They must fail closed.
    ``candidate_principals`` is what lets bulk queryset filtering use the same
    rule as per-object checks.
    """

    name: str

    def covers(self, codenames: Iterable[str]) -> bool: ...

    def applies_to(self, perm: str, obj: Model | type[Model]) -> bool: ...

    def candidate_principals(self, actor: Any) -> Iterable[Any]: ...

    def allows(self, actor: Any, principal: Any, perm: str, obj: Model) -> bool: ...


@dataclass(frozen=True)
class ObjectPermissionDelegationRule:
    """A declarative delegation rule based on object permissions.

    Parameters:
        name: Stable rule name used in explanations.
        permissions: Codenames this rule can delegate. ``None`` means every
            codename for the object's content type.
        principals: A callable taking the actor and returning user/group
            instances, a static iterable, or a single user/group. Groups are
            expanded to their members, and the group itself remains a valid
            principal so group-level permissions can be delegated too.
        require_actor_permission: If true (the default), the actor must hold
            the permission themselves before delegation is effective. This is
            what enforces "both people must be approved".
        principal_required_perm: Optional additional codename the principal
            must hold on the same object before the rule allows delegation.
        content_types: Optional set of model classes this rule applies to.
    """

    name: str
    permissions: frozenset[str] | Iterable[str] | None = None
    principals: Any = None
    require_actor_permission: bool = True
    principal_required_perm: str | None = None
    content_types: frozenset[type[Model]] | Iterable[type[Model]] | None = None

    def __post_init__(self):
        if self.permissions is not None:
            object.__setattr__(
                self,
                "permissions",
                frozenset(_codename(perm) for perm in self.permissions),
            )
        if self.content_types is not None:
            resolved = set()
            for allowed in self.content_types:
                if isinstance(allowed, type) and issubclass(allowed, Model):
                    resolved.add(get_content_type(allowed))
                else:
                    resolved.add(allowed)
            object.__setattr__(self, "content_types", frozenset(resolved))

    def covers(self, codenames: Iterable[str]) -> bool:
        if self.permissions is None:
            return True
        return {_codename(perm) for perm in codenames}.issubset(self.permissions)

    def applies_to(self, perm: str, obj: Model | type[Model]) -> bool:
        if self.permissions is not None and _codename(perm) not in self.permissions:
            return False
        if self.content_types is not None:
            return get_content_type(_model_from_object(obj)) in self.content_types
        return True

    def _source_principals(self, actor: Any) -> Iterable[Any]:
        source = self.principals
        if callable(source):
            source = source(actor)
        if source is None:
            return ()
        if _identity_key(source) is not None:
            return (source,)
        return source

    def candidate_principals(self, actor: Any) -> list[Any]:
        """Resolve principals for ``actor``, expanding groups to members."""
        seen: set[tuple[str, Any]] = set()
        candidates: list[Any] = []
        actor_key = _identity_key(actor)

        def add(identity: Any) -> None:
            key = _identity_key(identity)
            if key is None or key == actor_key or key in seen:
                return
            seen.add(key)
            candidates.append(identity)

        group_model = get_group_obj_perms_model().group.field.related_model
        for identity in self._source_principals(actor):
            add(identity)
            if isinstance(identity, group_model):
                for member in get_user_model().objects.filter(groups=identity):
                    add(member)
        return candidates

    def evaluate(self, actor: Any, principal: Any, perm: str, obj: Model) -> RuleEvaluation:
        codename = _codename(perm)
        if not self.applies_to(perm, obj):
            return RuleEvaluation(
                applicable=False,
                allowed=False,
                reason=(
                    f"rule {self.name!r} does not cover permission {codename!r} "
                    f"for {_model_from_object(obj)._meta.label}"
                ),
                rule_name=self.name,
                principal=principal,
            )

        principal_keys = {
            key for key in (_identity_key(candidate) for candidate in self.candidate_principals(actor)) if key
        }
        if _identity_key(principal) not in principal_keys:
            return RuleEvaluation(
                applicable=False,
                allowed=False,
                reason=f"principal {principal!r} is not a candidate under rule {self.name!r}",
                rule_name=self.name,
                principal=principal,
            )

        actor_source = permission_source(actor, codename, obj)
        principal_source = permission_source(principal, codename, obj)
        required_source = (
            permission_source(principal, self.principal_required_perm, obj) if self.principal_required_perm else None
        )

        if self.require_actor_permission and not actor_source.allowed:
            allowed = False
            reason = f"rule {self.name!r}: actor {actor!r} lacks {codename!r} on this object"
        elif not principal_source.allowed:
            allowed = False
            reason = f"rule {self.name!r}: principal {principal!r} lacks {codename!r} on this object"
        elif required_source is not None and not required_source.allowed:
            allowed = False
            required_perm = self.principal_required_perm or ""
            reason = (
                f"rule {self.name!r}: principal {principal!r} lacks required permission "
                f"{_codename(required_perm)!r} on this object"
            )
        else:
            allowed = True
            reason = f"rule {self.name!r}: actor and principal are both approved"

        return RuleEvaluation(
            applicable=True,
            allowed=allowed,
            reason=reason,
            rule_name=self.name,
            principal=principal,
            actor_source=actor_source,
            principal_source=principal_source,
            required_source=required_source,
        )

    def allows(self, actor: Any, principal: Any, perm: str, obj: Model) -> bool:
        return self.evaluate(actor, principal, perm, obj).allowed

    def _is_candidate(self, actor: Any, principal: Any) -> bool:
        principal_key = _identity_key(principal)
        return principal_key is not None and any(
            _identity_key(candidate) == principal_key for candidate in self.candidate_principals(actor)
        )

    def allowed_objects(
        self,
        actor: Any,
        principal: Any,
        perms: Iterable[str],
        queryset: QuerySet,
        *,
        any_perm: bool = False,
        use_groups: bool = True,
        with_superuser: bool = True,
    ) -> QuerySet:
        """Return the objects where this rule authorizes ``actor`` for ``principal``.

        This is the queryset counterpart of :meth:`evaluate`; it must reach the
        same conclusion for every object. It reuses guardian's regular
        permission filtering for each party, then intersects the two result
        sets. Direct and group object permissions count; model-wide global
        permissions do not, matching :func:`permission_source`.
        """
        codenames = [_codename(perm) for perm in perms]
        if not self.covers(codenames) or not all(self.applies_to(code, queryset.model) for code in codenames):
            return queryset.none()
        if not self._is_candidate(actor, principal):
            return queryset.none()

        actor_objects = (
            _objects_identity_has(
                actor,
                codenames,
                queryset,
                any_perm=any_perm,
                use_groups=use_groups,
                with_superuser=with_superuser,
            )
            if self.require_actor_permission
            else queryset
        )
        principal_objects = _objects_identity_has(
            principal,
            codenames,
            queryset,
            any_perm=any_perm,
            use_groups=use_groups,
            with_superuser=with_superuser,
        )
        if self.principal_required_perm:
            required_objects = _objects_identity_has(
                principal,
                [_codename(self.principal_required_perm)],
                queryset,
                any_perm=False,
                use_groups=use_groups,
                with_superuser=with_superuser,
            )
            principal_objects = principal_objects.filter(pk__in=required_objects.values("pk"))
        return actor_objects.filter(pk__in=principal_objects.values("pk")).distinct()


def _objects_identity_has(
    identity: Any,
    codenames: Iterable[str],
    queryset: QuerySet,
    *,
    any_perm: bool,
    use_groups: bool,
    with_superuser: bool,
) -> QuerySet:
    from guardian.shortcuts import get_objects_for_group, get_objects_for_user

    key = _identity_key(identity)
    if key is None:
        return queryset.none()
    if key[0] == "user" and not identity.is_active:
        return queryset.none()
    if key[0] == "user" and identity.is_superuser and not with_superuser:
        return queryset.none()
    if key[0] == "group":
        return get_objects_for_group(
            identity,
            list(codenames),
            queryset,
            any_perm=any_perm,
            accept_global_perms=False,
        )
    return get_objects_for_user(
        identity,
        list(codenames),
        queryset,
        use_groups=use_groups,
        any_perm=any_perm,
        with_superuser=with_superuser,
        accept_global_perms=False,
    )


def delegated_objects_for_principal(
    actor: Any,
    principal: Any,
    perms: Iterable[str],
    queryset: QuerySet,
    rules: Iterable[DelegationRule] | None = None,
    *,
    any_perm: bool = False,
    use_groups: bool = True,
    with_superuser: bool = True,
) -> QuerySet:
    """Return objects the actor may operate on behalf of one principal.

    The result is the union of every applicable rule, and each rule uses the
    same conditions as per-object checks. With no rules configured, or when the
    principal is not a candidate, the result is an empty queryset.
    """
    if actor is not None and isinstance(actor, get_user_model()) and not actor.is_authenticated:
        actor = get_anonymous_user()
    codenames = [_codename(perm) for perm in perms]
    actor_key = _identity_key(actor)
    if actor_key is None or actor_key[0] != "user":
        return queryset.none()
    result = queryset.none()
    for rule in _resolve_rules(rules):
        if not hasattr(rule, "allowed_objects"):
            raise DelegationQuerySetError(
                f"Delegation rule {getattr(rule, 'name', rule)!r} cannot filter querysets. "
                "Implement allowed_objects() or use ObjectPermissionDelegationRule."
            )
        if not rule.covers(codenames):
            continue
        if not all(rule.applies_to(code, queryset.model) for code in codenames):
            continue
        result = result | rule.allowed_objects(
            actor,
            principal,
            codenames,
            queryset,
            any_perm=any_perm,
            use_groups=use_groups,
            with_superuser=with_superuser,
        )
    return result.distinct()


def get_delegation_rules() -> list[DelegationRule]:
    """Return the delegation rules configured for this process.

    ``GUARDIAN_DELEGATION_RULES`` may be a callable, an iterable of rules, a
    single rule, or a dotted path resolving to one of those. An empty value
    disables delegation. The setting is read on every call so tests and
    long-running processes can change it without reimporting guardian.
    """
    configured = getattr(django_settings, "GUARDIAN_DELEGATION_RULES", None)
    if configured is None:
        configured = getattr(guardian_settings, "DELEGATION_RULES", None)
    if configured is None:
        return []
    if isinstance(configured, str):
        configured = import_string(configured)
    rules = configured() if callable(configured) and not hasattr(configured, "allows") else configured
    if hasattr(rules, "allows") and hasattr(rules, "candidate_principals"):
        return [rules]
    return list(rules)


def _resolve_rules(rules: Iterable[DelegationRule] | None) -> list[DelegationRule]:
    return get_delegation_rules() if rules is None else list(rules)


def _candidate_matches(rule: DelegationRule, actor: Any, principal: Any) -> bool:
    principal_key = _identity_key(principal)
    if principal_key is None:
        return False
    return any(_identity_key(candidate) == principal_key for candidate in rule.candidate_principals(actor))


def evaluate_delegation(
    actor: Any,
    principal: Any,
    perm: str,
    obj: Model,
    rules: Iterable[DelegationRule] | None = None,
) -> DelegationEvaluation:
    """Evaluate delegation for one actor/principal/permission/object tuple.

    This is the single decision function shared by per-object checks and the
    explanation API. It fails closed and does not mutate permissions.
    """
    if actor is not None and isinstance(actor, get_user_model()) and not actor.is_authenticated:
        actor = get_anonymous_user()
    codename = _codename(perm)
    resolved_rules = _resolve_rules(rules)

    actor_key = _identity_key(actor)
    if actor_key is None:
        return DelegationEvaluation(False, "delegation requires an active user actor")
    if actor_key[0] != "user":
        return DelegationEvaluation(False, "delegation requires a user actor")
    if _identity_key(principal) is None:
        return DelegationEvaluation(False, "delegation requires a user or group principal", principal=principal)
    if _identity_key(actor) == _identity_key(principal):
        return DelegationEvaluation(False, "an actor cannot delegate to themselves", principal=principal)
    if not resolved_rules:
        return DelegationEvaluation(
            False,
            "no delegation rules configured (set GUARDIAN_DELEGATION_RULES)",
            principal=principal,
        )

    actor_source = permission_source(actor, codename, obj)
    principal_source = permission_source(principal, codename, obj)
    no_match_reason: str | None = None
    denial_reason: str | None = None
    required_source: PermissionSource | None = None
    matched_rule: str | None = None

    for rule in resolved_rules:
        if hasattr(rule, "evaluate"):
            evaluation = rule.evaluate(actor, principal, codename, obj)
            if not evaluation.applicable:
                no_match_reason = no_match_reason or evaluation.reason
                continue
            matched_rule = evaluation.rule_name
            required_source = evaluation.required_source
            if evaluation.allowed:
                return DelegationEvaluation(
                    True,
                    evaluation.reason,
                    principal=principal,
                    rule_name=evaluation.rule_name,
                    actor_source=evaluation.actor_source,
                    principal_source=evaluation.principal_source,
                    required_source=evaluation.required_source,
                )
            denial_reason = denial_reason or evaluation.reason
        elif _candidate_matches(rule, actor, principal) and rule.applies_to(codename, obj):
            matched_rule = getattr(rule, "name", None)
            if rule.allows(actor, principal, codename, obj):
                return DelegationEvaluation(
                    True,
                    f"rule {matched_rule!r}: custom rule allowed",
                    principal=principal,
                    rule_name=matched_rule,
                    actor_source=actor_source,
                    principal_source=principal_source,
                )
            denial_reason = denial_reason or f"rule {matched_rule!r}: custom rule denied"

    if denial_reason is not None:
        reason = denial_reason
    else:
        reason = no_match_reason or f"no delegation rule covers {codename!r} for principal {principal!r}"
    return DelegationEvaluation(
        False,
        reason,
        principal=principal,
        rule_name=matched_rule,
        actor_source=actor_source,
        principal_source=principal_source,
        required_source=required_source,
    )


def delegation_allows(
    actor: Any,
    principal: Any,
    perm: str,
    obj: Model,
    rules: Iterable[DelegationRule] | None = None,
) -> bool:
    """Short form of :func:`evaluate_delegation`."""
    return evaluate_delegation(actor, principal, perm, obj, rules).allowed


def candidate_delegations(
    actor: Any,
    perm: str,
    obj: Model,
    rules: Iterable[DelegationRule] | None = None,
) -> list[DelegationEvaluation]:
    """Evaluate every candidate principal for automatic discovery.

    Used by ``explain_perm`` when no principal is named, so callers can see
    which colleagues the actor may act for and which condition blocks them.
    """
    if actor is not None and isinstance(actor, get_user_model()) and not actor.is_authenticated:
        actor = get_anonymous_user()
    codename = _codename(perm)
    results: list[DelegationEvaluation] = []
    seen: set[tuple[str, Any]] = set()
    for rule in _resolve_rules(rules):
        if not rule.applies_to(codename, obj):
            continue
        for principal in rule.candidate_principals(actor):
            key = _identity_key(principal)
            if key is None or key in seen:
                continue
            seen.add(key)
            results.append(evaluate_delegation(actor, principal, codename, obj, [rule]))
    return results


def shared_group_principals(group: Any) -> Callable[[Any], list[Any]]:
    """Return a principals callable that resolves a shared group and its members.

    ``group`` may be a group instance or a callable taking no arguments. The
    returned callable is intended for ``ObjectPermissionDelegationRule`` and
    treats every member (except the actor) plus the group itself as a principal.
    """

    def resolve(actor: Any) -> list[Any]:
        resolved = group() if callable(group) else group
        members = list(get_user_model().objects.filter(groups=resolved).exclude(pk=actor.pk))
        return [resolved, *members]

    return resolve


def make_shared_group_rule(
    *,
    name: str,
    group: Any,
    permissions: Iterable[str] | None = None,
    require_actor_permission: bool = True,
    principal_required_perm: str | None = None,
) -> ObjectPermissionDelegationRule:
    """Build a rule where members of one group cover for each other."""
    return ObjectPermissionDelegationRule(
        name=name,
        permissions=frozenset(permissions) if permissions is not None else None,
        principals=shared_group_principals(group),
        require_actor_permission=require_actor_permission,
        principal_required_perm=principal_required_perm,
    )
