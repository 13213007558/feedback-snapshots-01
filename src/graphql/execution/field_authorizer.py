"""Field-level authorization for the execution phase.

The same schema is often shared between requests with different privileges.
Which fields of that schema a request may access can therefore only be decided
at execution time, based on the authenticated runtime context (for example the
viewer, token scope or tenant carried by the resolve info's ``context``) and on
the concrete runtime type of the value being resolved.

A field authorizer plugs into the :class:`~graphql.execution.Executor` and is
consulted for every field before its resolver runs. When a field is not
authorized, its resolver is never invoked and the field is omitted from the
result, so authorization cannot be bypassed by filtering the response after
execution.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Protocol, TypeAlias, runtime_checkable

from ..pyutils import AwaitableOrValue, Undefined, UndefinedType
from ..type import GraphQLObjectType, GraphQLResolveInfo

__all__ = [
    "AllowListFieldAuthorizer",
    "FieldAuthorizationDecision",
    "FieldAuthorizationRule",
    "FieldAuthorizer",
    "RuleBasedFieldAuthorizer",
]

#: An entry of an allow list, either as a pair or a dot-separated string.
AllowedField: TypeAlias = tuple[str, str] | str

#: Whether access to a field is granted. May be returned synchronously or as an
#: awaitable, so that authorization rules can perform asynchronous checks.
FieldAuthorizationDecision: TypeAlias = AwaitableOrValue[bool]

#: A rule decides access to the fields of one object type. A plain boolean
#: grants or denies every field of the type, while a callable is invoked with
#: the field name and the owning type for each requested field. A callable may
#: abstain by returning :data:`~graphql.pyutils.Undefined`.
FieldAuthorizationRule: TypeAlias = (
    bool
    | Callable[
        [str, GraphQLObjectType],
        FieldAuthorizationDecision | UndefinedType,
    ]
)


@runtime_checkable
class FieldAuthorizer(Protocol):
    """Decide whether the currently requested field may be resolved.

    Implementations receive the :class:`~graphql.type.GraphQLResolveInfo` of
    the field that is about to be resolved. Its ``context`` carries the
    authenticated runtime context, ``parent_type`` is the object type that owns
    the field and ``field_name`` is the actual schema field name (independent of
    any response alias used in the query).

    Returning ``True`` runs the field as usual; returning ``False`` skips the
    resolver entirely and omits the field. The result may also be an awaitable
    resolving to a boolean for asynchronous authorization.

    A minimal authorizer only needs to implement :meth:`authorize_field`:

    >>> class DenyAll:
    ...     def authorize_field(self, info):
    ...         return False
    >>> isinstance(DenyAll(), FieldAuthorizer)
    True
    """

    def authorize_field(
        self, info: GraphQLResolveInfo
    ) -> FieldAuthorizationDecision | UndefinedType:
        """Authorize the field described by the given resolve info.

        :meta private:

        Returning :data:`~graphql.pyutils.Undefined` means that this authorizer
        does not make a decision for the field; the caller then applies its
        default decision.

        :param info: The resolve info of the field to authorize.
        :returns: Whether the field is authorized, optionally as an awaitable,
            or :data:`~graphql.pyutils.Undefined` to abstain.
        """
        ...


def _field_is_meta(info: GraphQLResolveInfo) -> bool:
    """Check whether the field is a built-in meta field such as __typename."""
    return info.field_name.startswith("__")


class RuleBasedFieldAuthorizer:
    """Authorize fields through declarative per-type rules.

    Rules are keyed by the name of the object type that owns the fields. A rule
    is either a boolean that grants or denies every field of the type, or a
    callable taking the field name and owning type that returns a decision (or
    an awaitable resolving to one). A callable may abstain by returning
    :data:`~graphql.pyutils.Undefined`.

    Types without a rule, and callable rules that abstain, fall back to
    ``default_decision``, which denies access by default.

    :param rules: Mapping of object type names to authorization rules.
    :param default_decision: Decision used when no rule matches or the matching
        rule abstains. Defaults to denying access.

    >>> from graphql import build_schema, execute_sync, parse
    >>> schema = build_schema('''
    ...     type User {
    ...       id: ID!
    ...       ssn: String
    ...     }
    ...
    ...     type Query {
    ...       viewer: User
    ...     }
    ... ''')
    >>> def is_internal(field_name, _parent_type):
    ...     return field_name != "ssn"
    >>> authorizer = RuleBasedFieldAuthorizer(
    ...     {"Query": True, "User": is_internal}
    ... )
    >>> result = execute_sync(
    ...     schema,
    ...     parse("{ viewer { id ssn } }"),
    ...     root_value={"viewer": {"id": "1", "ssn": "123-45-6789"}},
    ...     field_authorizer=authorizer,
    ... )
    >>> result.data
    {'viewer': {'id': '1'}}
    """

    def __init__(
        self,
        rules: dict[str, FieldAuthorizationRule],
        default_decision: bool = False,
    ) -> None:
        self.rules = rules
        self.default_decision = default_decision

    def authorize_field(
        self, info: GraphQLResolveInfo
    ) -> FieldAuthorizationDecision | UndefinedType:
        """Apply the configured rule for the field's owning type.

        :meta private:

        :param info: The resolve info of the field to authorize.
        :returns: The rule's decision, or ``default_decision`` when no rule
            matches or the rule abstains.
        """
        if _field_is_meta(info):
            return True
        rule = self.rules.get(info.parent_type.name)
        if rule is None:
            return self.default_decision
        if isinstance(rule, bool):
            return rule
        decision = rule(info.field_name, info.parent_type)
        if decision is Undefined:
            return self.default_decision
        return decision


class AllowListFieldAuthorizer:
    """Authorize only fields explicitly granted to a runtime context.

    The allow list contains ``(type_name, field_name)`` pairs. A field is
    authorized exactly when the type that owns it and its schema field name are
    both present in a pair. The check therefore applies to the concrete runtime
    object type, which makes it safe with interfaces and unions where the same
    selection is completed against different object types.

    Every other field is denied unless ``default_decision`` is changed.
    Built-in meta fields such as ``__typename`` are always allowed.

    :param allowed_fields: Pairs of ``(object type name, field name)`` that may
        be resolved. Dot-separated strings such as ``"User.id"`` are accepted
        as well.
    :param default_decision: Decision used for fields that are not on the allow
        list. Defaults to denying access.

    >>> from graphql import build_schema, execute_sync, parse
    >>> schema = build_schema('''
    ...     type User {
    ...       id: ID!
    ...       ssn: String
    ...     }
    ...
    ...     type Query {
    ...       viewer: User
    ...     }
    ... ''')
    >>> authorizer = AllowListFieldAuthorizer([("User", "id"), ("Query", "viewer")])
    >>> result = execute_sync(
    ...     schema,
    ...     parse("{ viewer { id ssn __typename } }"),
    ...     root_value={"viewer": {"id": "1", "ssn": "123-45-6789"}},
    ...     field_authorizer=authorizer,
    ... )
    >>> result.data
    {'viewer': {'id': '1', '__typename': 'User'}}
    """

    def __init__(
        self,
        allowed_fields: Iterable[AllowedField],
        default_decision: bool = False,
    ) -> None:
        self.allowed_fields = {self._as_pair(field) for field in allowed_fields}
        self.default_decision = default_decision

    @staticmethod
    def _as_pair(field: tuple[str, str] | str) -> tuple[str, str]:
        if isinstance(field, str):
            type_name, separator, field_name = field.partition(".")
            if not separator or not type_name or not field_name:
                msg = (
                    "Allow list entries must be (type, field) pairs or"
                    f" dot-separated strings, got {field!r}."
                )
                raise ValueError(msg)
            return type_name, field_name
        if isinstance(field, tuple) and len(field) == 2:
            return field
        msg = (
            "Allow list entries must be (type, field) pairs or dot-separated"
            f" strings, got {field!r}."
        )
        raise ValueError(msg)

    def authorize_field(self, info: GraphQLResolveInfo) -> bool:
        """Allow the field only when its type and name are on the allow list.

        :meta private:

        :param info: The resolve info of the field to authorize.
        :returns: ``True`` when the field is allowed, otherwise
            ``default_decision``.
        """
        if _field_is_meta(info):
            return True
        if (info.parent_type.name, info.field_name) in self.allowed_fields:
            return True
        return self.default_decision
