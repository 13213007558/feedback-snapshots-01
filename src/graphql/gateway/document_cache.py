"""Caching of parsed and validated GraphQL documents for gateways.

A gateway can reuse the parsed form of a document for every schema and permission
policy, because parsing does not depend on either of them. Validation is different:
a result that was accepted for one schema or one external permission policy must not
silently become an execution permit for another. This module therefore records the
schema and policy identity together with a cached validation result, and it exposes
an execution middleware that applies the current policy to every field before its
resolver runs.

The cache is deliberately conservative:

* A parsed document is reused across schemas and policies.
* A validated document is only reused for the exact same schema fingerprint, policy
  fingerprint, validation rules, and validation options.
* A schema change may reuse an existing validation result only when the change is
  made exclusively of safe, additive schema changes.
* A policy fingerprint change always invalidates the validation result, even if the
  document is unchanged. Authorization is then re-applied at execution time.
"""

from __future__ import annotations

import json
from collections import OrderedDict
from hashlib import sha256
from typing import TYPE_CHECKING, Any, NamedTuple, Protocol, cast, runtime_checkable

from ..error import GraphQLError
from ..execution import ExecutionResult, MiddlewareManager, execute, execute_sync
from ..language import DocumentNode, Source, parse, print_ast
from ..pyutils import is_awaitable
from ..type import (
    GraphQLArgument,
    GraphQLInputField,
    is_enum_type,
    is_input_object_type,
    is_interface_type,
    is_introspection_type,
    is_object_type,
    is_scalar_type,
    is_union_type,
)
from ..utilities.find_schema_changes import (
    SafeChange,
    SafeChangeType,
    find_schema_changes,
)
from ..utilities.get_default_value_ast import get_default_value_ast
from ..validation import specified_rules, validate

if TYPE_CHECKING:
    from collections.abc import Awaitable, Collection, Mapping

    from ..execution import Middleware
    from ..type import (
        GraphQLFieldResolver,
        GraphQLResolveInfo,
        GraphQLSchema,
        GraphQLTypeResolver,
    )
    from ..validation import ASTValidationRule

__all__ = [
    "AllowListPermissionPolicy",
    "CacheStats",
    "GatewayDocumentCache",
    "ParseResult",
    "PermissionPolicy",
    "PreparedOperation",
    "ValidationResult",
    "authorization_middleware",
    "get_authorization_fingerprint",
    "get_document_fingerprint",
    "get_schema_fingerprint",
]


AUTHORIZATION_ERROR_CODE = "FORBIDDEN"


def _digest(value: Any) -> str:
    """Return a stable SHA-256 digest for a JSON-compatible value."""
    encoded = json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
        default=repr,
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def _text_digest(value: str) -> str:
    """Return a stable SHA-256 digest for a text value."""
    return sha256(value.encode("utf-8")).hexdigest()


def _applied_directives(node: Any, key: str = "directives") -> list[str]:
    """Get the printed directives applied via a schema element's AST nodes.

    Both the definition itself and its extensions are considered, so adding a
    permission-sensitive directive to an extension changes the schema fingerprint.

    The ``extensions`` mapping is also included, because applications often carry
    field-level authorization metadata there when a schema is built programmatically.
    """
    ast_nodes = [getattr(node, "ast_node", None)]
    ast_nodes.extend(getattr(node, "extension_ast_nodes", ()) or ())
    directives = [
        print_ast(directive)
        for ast_node in ast_nodes
        if ast_node is not None
        for directive in getattr(ast_node, key, None) or ()
    ]
    extensions = getattr(node, "extensions", None)
    if extensions:
        directives.append(_digest(extensions))
    return sorted(directives)


def _input_value_data(
    name: str, input_value: GraphQLArgument | GraphQLInputField
) -> dict[str, Any]:
    """Build the validation-relevant identity of an argument or input field."""
    default_ast = get_default_value_ast(input_value)
    return {
        "name": name,
        "type": str(input_value.type),
        "default": print_ast(default_ast) if default_ast is not None else None,
        "description": input_value.description,
        "deprecation_reason": input_value.deprecation_reason,
    }


def _field_data(name: str, field: Any) -> dict[str, Any]:
    """Build the validation-relevant identity of an output field."""
    return {
        "name": name,
        "type": str(field.type),
        "args": [
            _input_value_data(arg_name, field.args[arg_name])
            for arg_name in sorted(field.args)
        ],
        "description": field.description,
        "deprecation_reason": field.deprecation_reason,
    }


def _type_data(type_: Any) -> dict[str, Any]:
    """Build the validation-relevant identity of a named type."""
    if is_scalar_type(type_):
        return {
            "kind": "SCALAR",
            "name": type_.name,
            "description": type_.description,
        }
    if is_object_type(type_) or is_interface_type(type_):
        return {
            "kind": "OBJECT" if is_object_type(type_) else "INTERFACE",
            "name": type_.name,
            "interfaces": sorted(interface.name for interface in type_.interfaces),
            "fields": [
                _field_data(field_name, type_.fields[field_name])
                for field_name in sorted(type_.fields)
            ],
            "description": type_.description,
        }
    if is_union_type(type_):
        return {
            "kind": "UNION",
            "name": type_.name,
            "types": sorted(member.name for member in type_.types),
            "description": type_.description,
        }
    if is_enum_type(type_):
        return {
            "kind": "ENUM",
            "name": type_.name,
            "values": [
                {
                    "name": value_name,
                    "description": type_.values[value_name].description,
                    "deprecation_reason": (type_.values[value_name].deprecation_reason),
                }
                for value_name in sorted(type_.values)
            ],
            "description": type_.description,
        }
    if is_input_object_type(type_):
        return {
            "kind": "INPUT_OBJECT",
            "name": type_.name,
            "is_one_of": type_.is_one_of,
            "fields": [
                _input_value_data(field_name, type_.fields[field_name])
                for field_name in sorted(type_.fields)
            ],
            "description": type_.description,
        }
    # All GraphQL named types are covered above. Keep a stable fallback so that a
    # future type kind cannot accidentally share a fingerprint with another kind.
    return {"kind": type(type_).__name__, "name": getattr(type_, "name", None)}


def _directive_data(directive: Any) -> dict[str, Any]:
    """Build the validation-relevant identity of a directive definition."""
    return {
        "name": directive.name,
        "locations": sorted(location.name for location in directive.locations),
        "is_repeatable": directive.is_repeatable,
        "args": [
            _input_value_data(arg_name, directive.args[arg_name])
            for arg_name in sorted(directive.args)
        ],
        "description": directive.description,
        "deprecation_reason": directive.deprecation_reason,
    }


def get_schema_fingerprint(schema: GraphQLSchema) -> str:
    """Get a stable fingerprint of the validation-relevant parts of a schema.

    The fingerprint covers root operation types, named types, fields, arguments,
    input fields, enum values, implemented interfaces, union members, and directive
    definitions. It intentionally does not cover resolvers, because they do not
    affect whether a document is valid. It does include the authorization metadata
    reported by :func:`get_authorization_fingerprint`, so attaching a scope directive
    or policy extension always changes the schema identity.

    Two separately built schemas with the same validation-relevant structure have
    the same fingerprint:

    >>> from graphql import build_schema
    >>> first = build_schema("type Query { greeting: String }")
    >>> second = build_schema("type Query { greeting: String }")
    >>> get_schema_fingerprint(first) == get_schema_fingerprint(second)
    True
    >>> len(get_schema_fingerprint(first))
    64

    :param schema: The GraphQL schema to fingerprint.
    :returns: A hexadecimal SHA-256 fingerprint of the schema structure.
    """
    type_map = schema.type_map
    payload = {
        "query": schema.query_type.name if schema.query_type else None,
        "mutation": schema.mutation_type.name if schema.mutation_type else None,
        "subscription": (
            schema.subscription_type.name if schema.subscription_type else None
        ),
        "authorization": get_authorization_fingerprint(schema),
        "types": [
            _type_data(type_map[type_name])
            for type_name in sorted(type_map)
            if not is_introspection_type(type_map[type_name])
        ],
        "directives": [
            _directive_data(directive)
            for directive in sorted(schema.directives, key=lambda item: item.name)
        ],
    }
    return _digest(payload)


def _metadata_entry(node: Any) -> dict[str, Any] | None:
    """Get the policy metadata of a schema element, or None when it has none."""
    directives = _applied_directives(node)
    extensions = getattr(node, "extensions", None)
    if not directives and not extensions:
        return None
    return {
        "directives": directives,
        "extensions": _digest(extensions) if extensions else None,
    }


def get_authorization_fingerprint(schema: GraphQLSchema) -> str:
    """Build a fingerprint of the policy metadata attached to a schema.

    GraphQL validation does not interpret application directives or extension
    metadata, but a gateway often uses them to declare required scopes. A cached
    validation result may therefore only be reused when this metadata is unchanged.
    This is intentionally stricter than :func:`find_schema_changes`, which reports
    an added directive as safe and would otherwise miss a newly attached scope.

    Only schema elements that actually carry metadata are included, so adding a
    plain field or type without policy annotations does not change the fingerprint.

    :param schema: The schema to inspect.
    :returns: A hexadecimal SHA-256 fingerprint of the attached policy metadata.

    >>> from graphql import build_schema
    >>> schema = build_schema("type Query { greeting: String }")
    >>> len(get_authorization_fingerprint(schema))
    64
    """
    types_payload: dict[str, Any] = {}
    for type_name in sorted(schema.type_map):
        type_ = schema.type_map[type_name]
        if is_introspection_type(type_):
            continue
        type_entry: dict[str, Any] = {}
        type_metadata = _metadata_entry(type_)
        if type_metadata:
            type_entry["self"] = type_metadata
        fields: Any = getattr(type_, "fields", None)
        for field_name, field in (fields or {}).items():
            field_entry: dict[str, Any] = {}
            field_metadata = _metadata_entry(field)
            if field_metadata:
                field_entry["self"] = field_metadata
            args: Any = getattr(field, "args", None)
            for arg_name, arg in (args or {}).items():
                arg_metadata = _metadata_entry(arg)
                if arg_metadata:
                    field_entry["args"] = field_entry.get("args", {})
                    field_entry["args"][arg_name] = arg_metadata
            if field_entry:
                type_entry["fields"] = type_entry.get("fields", {})
                type_entry["fields"][field_name] = field_entry
        values: Any = getattr(type_, "values", None)
        for value_name, value in (values or {}).items():
            value_metadata = _metadata_entry(value)
            if value_metadata:
                type_entry["values"] = type_entry.get("values", {})
                type_entry["values"][value_name] = value_metadata
        if type_entry:
            types_payload[type_name] = type_entry
    payload: dict[str, Any] = {
        "schema": _metadata_entry(schema),
        "types": types_payload,
    }
    return _digest(payload)


def get_document_fingerprint(document: DocumentNode) -> str:
    r"""Get a stable fingerprint of an executable GraphQL document.

    The fingerprint is based on the printed AST, so two documents that differ only
    in comments or whitespace have the same fingerprint. Source locations are not
    part of the fingerprint.

    >>> from graphql import parse
    >>> first = parse("{ greeting }")
    >>> second = parse("# a comment\n{ greeting }")
    >>> get_document_fingerprint(first) == get_document_fingerprint(second)
    True

    :param document: The parsed GraphQL document to fingerprint.
    :returns: A hexadecimal SHA-256 fingerprint of the document.
    """
    return _text_digest(print_ast(document))


class ParseResult(NamedTuple):
    """A parsed document together with its cache metadata."""

    document: DocumentNode
    """The parsed document AST."""
    fingerprint: str
    """The fingerprint of the parsed document AST."""
    cache_hit: bool
    """Whether the document was taken from the parse cache."""


class ValidationResult(NamedTuple):
    """A cached validation result and its explicit applicability bindings."""

    errors: tuple[GraphQLError, ...]
    """Validation errors; empty when the document is valid."""
    schema_fingerprint: str
    """Fingerprint of the schema the validation result applies to."""
    policy_fingerprint: str | None
    """Fingerprint of the permission policy the result was accepted for."""
    cache_hit: bool
    """Whether an existing validation result was reused."""
    reused_for_schema_change: bool
    """Whether a safe schema change allowed the result to be reused."""
    rebound_from_schema_fingerprint: str | None
    """The previous schema fingerprint when the result was rebound."""

    @property
    def is_valid(self) -> bool:
        """Whether the document passed validation for this binding."""
        return not self.errors


class PreparedOperation(NamedTuple):
    """A parsed and validated operation, ready for an authorization-gated execution.

    The result records both the schema fingerprint and the permission policy
    fingerprint that the validation result applies to. Callers must treat this as
    validation metadata, not as an execution permit: execution always re-applies the
    current policy through :func:`authorization_middleware`.
    """

    document: DocumentNode
    """The parsed and validated document AST."""
    errors: tuple[GraphQLError, ...]
    """Validation errors; empty when the document is valid."""
    operation_name: str | None
    """The operation name supplied by the caller, if any."""
    schema_fingerprint: str
    """Fingerprint of the schema this preparation applies to."""
    policy_fingerprint: str | None
    """Fingerprint of the permission policy this preparation applies to."""
    parse_cache_hit: bool
    """Whether the parsed document came from the parse cache."""
    validation_cache_hit: bool
    """Whether the validation result came from the validation cache."""
    validation_reused: bool
    """Whether a safe schema change allowed validation reuse."""
    document_fingerprint: str
    """Fingerprint of the parsed document AST."""

    @property
    def is_valid(self) -> bool:
        """Whether the document passed validation for this binding."""
        return not self.errors

    @property
    def cache_info(self) -> dict[str, Any]:
        """Get JSON-friendly cache metadata for responses and logs."""
        return {
            "schema_fingerprint": self.schema_fingerprint,
            "policy_fingerprint": self.policy_fingerprint,
            "document_fingerprint": self.document_fingerprint,
            "parse_cache_hit": self.parse_cache_hit,
            "validation_cache_hit": self.validation_cache_hit,
            "validation_reused": self.validation_reused,
        }


class CacheStats(NamedTuple):
    """A snapshot of cache hit and miss counters."""

    parse_hits: int
    """Number of parsed documents served from the parse cache."""
    parse_misses: int
    """Number of documents that had to be parsed."""
    validation_hits: int
    """Number of validation results served from the validation cache."""
    validation_misses: int
    """Number of documents that had to be validated."""
    validation_reuses: int
    """Number of validation results reused after a safe schema change."""


@runtime_checkable
class PermissionPolicy(Protocol):
    """An external permission policy used to authorize fields at execution time.

    ``fingerprint`` identifies the policy version. When it changes, cached validation
    results are not reused, even when the document and schema are unchanged.

    ``authorize_field`` is called for each field before its resolver runs. It receives
    the field's :class:`~graphql.type.GraphQLResolveInfo`; the authenticated request
    state is available as ``info.context``. Returning ``False`` blocks the field, and
    the resolver must not run. An awaitable decision is also supported for
    asynchronous policy backends.

    A minimal policy only needs the two members:

    >>> class DenyAll:
    ...     fingerprint = "deny-all-v1"
    ...     def authorize_field(self, info):
    ...         return False
    >>> isinstance(DenyAll(), PermissionPolicy)
    True
    """

    fingerprint: str
    """Identity of the external permission policy version."""

    def authorize_field(self, info: GraphQLResolveInfo) -> bool | Awaitable[bool]:
        """Authorize one field before its resolver runs.

        :param info: Resolve info of the field that is about to be resolved.
        :returns: Whether the field may be resolved, optionally as an awaitable.

        >>> class DenyAll:
        ...     fingerprint = "deny-all-v1"
        ...     def authorize_field(self, info):
        ...         return False
        >>> isinstance(DenyAll(), PermissionPolicy)
        True
        """
        ...


class AllowListPermissionPolicy:
    """A simple permission policy that allows explicitly listed schema fields.

    Entries are ``(type_name, field_name)`` pairs such as ``("User", "email")``.
    The type name is the concrete object type reported in ``info.parent_type``, so
    the same rule works for fields reached through interfaces and unions.

    Built-in meta fields (``__typename``, ``__schema``, and ``__type``) are allowed by
    this policy. Every other field is denied unless ``default_decision`` is changed.

    The policy fingerprint is derived from the allowed fields and the default
    decision. Pass an explicit ``fingerprint`` when the external policy has its own
    version identifier.

    :param allowed_fields: Pairs of schema type names and field names to allow.
    :param fingerprint: Optional external policy version identifier.
    :param default_decision: Decision for fields not on the allow list.

    >>> policy = AllowListPermissionPolicy([("Query", "viewer"), ("User", "name")])
    >>> policy.fingerprint.startswith("allow-list:")
    True
    >>> policy.allowed_fields == {("Query", "viewer"), ("User", "name")}
    True
    """

    fingerprint: str
    """Identity of the external permission policy version."""

    def __init__(
        self,
        allowed_fields: Collection[tuple[str, str]],
        *,
        fingerprint: str | None = None,
        default_decision: bool = False,
    ) -> None:
        """Initialize the allow-list policy.

        :param allowed_fields: Pairs of schema type names and field names to allow.
        :param fingerprint: Optional external policy version identifier.
        :param default_decision: Decision for fields not on the allow list.
        """
        self.allowed_fields = {tuple(field) for field in allowed_fields}
        self.default_decision = default_decision
        self.fingerprint = fingerprint or "allow-list:" + _digest(
            {
                "allowed_fields": sorted(self.allowed_fields),
                "default_decision": default_decision,
            }
        )

    def authorize_field(self, info: GraphQLResolveInfo) -> bool:
        """Allow only fields whose concrete type and name are on the allow list.

        :param info: Resolve info of the field that is about to be resolved.
        :returns: Whether the field may be resolved.

        >>> from graphql import build_schema, execute_sync, parse
        >>> schema = build_schema("type Query { greeting: String }")
        >>> policy = AllowListPermissionPolicy([("Query", "greeting")])
        >>> result = execute_sync(
        ...     schema,
        ...     parse("{ greeting }"),
        ...     root_value={"greeting": "Hello"},
        ...     middleware=[authorization_middleware(policy)],
        ... )
        >>> result.data
        {'greeting': 'Hello'}
        """
        if info.field_name.startswith("__"):
            return True
        if (info.parent_type.name, info.field_name) in self.allowed_fields:
            return True
        return self.default_decision


def _denied_error(info: GraphQLResolveInfo) -> GraphQLError:
    """Build the error raised when the current policy denies a field."""
    field = f"{info.parent_type.name}.{info.field_name}"
    return GraphQLError(
        f"Not authorized to access field '{field}'.",
        extensions={"code": AUTHORIZATION_ERROR_CODE, "field": field},
    )


def authorization_middleware(policy: PermissionPolicy) -> Any:
    """Build execution middleware that enforces a permission policy per field.

    The middleware is consulted before each field resolver. A denied field produces
    a ``FORBIDDEN`` field error and its resolver never runs. This gate is independent
    of the validation cache: even when a validation result is served from cache, the
    current policy is applied again for every request and every field.

    >>> from graphql import build_schema, execute_sync, parse
    >>> class DenyEmail:
    ...     fingerprint = "deny-email-v1"
    ...     def authorize_field(self, info):
    ...         return info.field_name != "email"
    >>> schema = build_schema('''
    ...     type User { name: String email: String }
    ...     type Query { viewer: User }
    ... ''')
    >>> result = execute_sync(
    ...     schema,
    ...     parse("{ viewer { name email } }"),
    ...     root_value={"viewer": {"name": "Ada", "email": "ada@example.com"}},
    ...     middleware=[authorization_middleware(DenyEmail())],
    ... )
    >>> result.data
    {'viewer': {'name': 'Ada', 'email': None}}
    >>> result.errors[0].extensions
    {'code': 'FORBIDDEN', 'field': 'User.email'}

    :param policy: The permission policy to enforce.
    :returns: Middleware suitable for the ``middleware`` argument of execution.
    """

    def middleware(next_: Any, root: Any, info: GraphQLResolveInfo, **args: Any) -> Any:
        if info.field_name == "__typename":
            # The concrete type name is structural response metadata. It never
            # exposes a field value, and clients rely on it for caching and for
            # interpreting abstract types, so the policy does not gate it.
            return next_(root, info, **args)
        decision = policy.authorize_field(info)
        if is_awaitable(decision):

            async def authorize_and_resolve() -> Any:
                if not await cast("Awaitable[bool]", decision):
                    raise _denied_error(info)
                result = next_(root, info, **args)
                if is_awaitable(result):
                    return await cast("Awaitable[Any]", result)
                return result

            return authorize_and_resolve()
        if not decision:
            raise _denied_error(info)
        return next_(root, info, **args)

    return middleware


class _CacheCounters:
    """Mutable cache counters, exposed as immutable snapshots."""

    __slots__ = (
        "parse_hits",
        "parse_misses",
        "validation_hits",
        "validation_misses",
        "validation_reuses",
    )

    def __init__(self) -> None:
        self.parse_hits = 0
        self.parse_misses = 0
        self.validation_hits = 0
        self.validation_misses = 0
        self.validation_reuses = 0

    def snapshot(self) -> CacheStats:
        return CacheStats(
            self.parse_hits,
            self.parse_misses,
            self.validation_hits,
            self.validation_misses,
            self.validation_reuses,
        )


class _ParseEntry(NamedTuple):
    document: DocumentNode
    fingerprint: str


class _ValidationEntry(NamedTuple):
    schema: GraphQLSchema
    schema_fingerprint: str
    policy_fingerprint: str | None
    validation_fingerprint: str
    document_fingerprint: str
    errors: tuple[GraphQLError, ...]
    authorization_metadata: str


# Schema changes that can only add new capabilities. A previously accepted document
# stays valid when one of these changes is applied, because no existing type, field,
# argument, or enum value is removed or narrowed.
_REUSE_SAFE_CHANGE_TYPES = frozenset(
    {
        SafeChangeType.TYPE_ADDED,
        SafeChangeType.OPTIONAL_INPUT_FIELD_ADDED,
        SafeChangeType.OPTIONAL_ARG_ADDED,
        SafeChangeType.DIRECTIVE_ADDED,
        SafeChangeType.FIELD_ADDED,
        SafeChangeType.DIRECTIVE_REPEATABLE_ADDED,
        SafeChangeType.DIRECTIVE_LOCATION_ADDED,
        SafeChangeType.OPTIONAL_DIRECTIVE_ARG_ADDED,
        SafeChangeType.ARG_DEFAULT_VALUE_ADDED,
        SafeChangeType.INPUT_FIELD_DEFAULT_VALUE_ADDED,
    }
)


def _schema_change_allows_reuse(
    old_schema: GraphQLSchema, new_schema: GraphQLSchema
) -> bool:
    """Check whether a schema change is purely additive for a cached result.

    Only changes that can exclusively add new capabilities are accepted. A change
    that merely reclassifies an existing element as safe (for example a weakened
    type or a changed default) is not enough to reuse an accepted result. The check
    intentionally requires at least one reported change, so an unrecognized
    difference can never be silently treated as compatible.
    """
    try:
        changes = find_schema_changes(old_schema, new_schema)
    except Exception:  # incompatible schemas must force a miss
        return False
    return bool(changes) and all(
        isinstance(change, SafeChange) and change.type in _REUSE_SAFE_CHANGE_TYPES
        for change in changes
    )


def _parse_key(source: Source, options: Mapping[str, Any]) -> tuple[Any, ...]:
    """Build a parse cache key from source text and parse options."""
    return (
        _text_digest(source.body),
        source.name,
        (source.location_offset.line, source.location_offset.column),
        tuple(sorted(options.items())),
    )


def _validation_fingerprint(
    rules: Collection[type[ASTValidationRule]] | None,
    max_errors: int | None,
    hide_suggestions: bool,
    allow_empty_selection_sets: bool,
) -> str:
    """Build a fingerprint for validation rule and option choices."""
    selected_rules = specified_rules if rules is None else tuple(rules)
    return _digest(
        {
            "rules": [
                getattr(rule, "__module__", "")
                + "."
                + getattr(
                    rule,
                    "__qualname__",
                    getattr(rule, "__name__", repr(rule)),
                )
                for rule in selected_rules
            ],
            "max_errors": max_errors,
            "hide_suggestions": hide_suggestions,
            "allow_empty_selection_sets": allow_empty_selection_sets,
        }
    )


def _policy_fingerprint(
    policy: PermissionPolicy | None, policy_fingerprint: str | None
) -> str | None:
    """Resolve and validate a permission policy fingerprint."""
    if policy is not None:
        fingerprint = getattr(policy, "fingerprint", None)
        if not isinstance(fingerprint, str) or not fingerprint:
            msg = (
                "A permission policy must provide a non-empty string fingerprint,"
                " so cached validation results can be bound to the policy version."
            )
            raise TypeError(msg)
        if policy_fingerprint is not None and policy_fingerprint != fingerprint:
            msg = (
                "policy_fingerprint does not match the permission policy's"
                f" fingerprint: {policy_fingerprint!r} != {fingerprint!r}."
            )
            raise ValueError(msg)
        return fingerprint
    if policy_fingerprint is not None and (
        not isinstance(policy_fingerprint, str) or not policy_fingerprint
    ):
        msg = "policy_fingerprint must be a non-empty string when provided."
        raise TypeError(msg)
    return policy_fingerprint


def _manager_middleware(manager: MiddlewareManager) -> Any:
    """Adapt a middleware manager to a single middleware function."""

    def middleware(next_: Any, root: Any, info: GraphQLResolveInfo, **args: Any) -> Any:
        return manager.get_field_resolver(next_)(root, info, **args)

    return middleware


class GatewayDocumentCache:
    """Cache parsed and validated GraphQL documents for a gateway.

    Parsing is cached independently of schemas and policies. Validation results are
    bound to a schema fingerprint, a permission policy fingerprint, and the validation
    options. The same cache can therefore be shared by requests that use different
    schemas or external permission policies without letting one request's validation
    result authorize another request's fields.

    A policy change always forces validation to run again. A purely additive schema
    change may reuse a validation result, because the accepted document remains valid
    under the new schema. Execution still applies the current policy to every field.

    >>> from graphql import build_schema
    >>> cache = GatewayDocumentCache()
    >>> schema = build_schema("type Query { greeting: String }")
    >>> prepared = cache.prepare(schema, "{ greeting }")
    >>> prepared.is_valid
    True
    >>> prepared.parse_cache_hit
    False
    >>> cache.prepare(schema, "{ greeting }").parse_cache_hit
    True
    >>> cache.prepare(schema, "{ greeting }").validation_cache_hit
    True

    :param max_entries: Maximum number of entries kept per cache layer.
    """

    def __init__(self, max_entries: int = 256) -> None:
        """Initialize the cache.

        :param max_entries: Maximum number of entries kept per cache layer.
        """
        if max_entries < 1:
            msg = "max_entries must be at least 1."
            raise ValueError(msg)
        self.max_entries = max_entries
        self._parse_cache: OrderedDict[tuple[Any, ...], _ParseEntry] = OrderedDict()
        self._validation_cache: OrderedDict[
            tuple[str, str, str | None, str], _ValidationEntry
        ] = OrderedDict()
        self._counters = _CacheCounters()

    @property
    def stats(self) -> CacheStats:
        """Get a snapshot of the cache counters."""
        return self._counters.snapshot()

    def clear(self) -> None:
        """Remove all cached entries and reset the counters.

        >>> cache = GatewayDocumentCache()
        >>> cache.clear()
        >>> cache.stats.parse_hits
        0
        """
        self._parse_cache.clear()
        self._validation_cache.clear()
        self._counters = _CacheCounters()

    def _remember(self, cache: OrderedDict[Any, Any], key: Any, value: Any) -> None:
        cache[key] = value
        cache.move_to_end(key)
        while len(cache) > self.max_entries:
            cache.popitem(last=False)

    def parse(self, source: str | Source, **parse_options: Any) -> ParseResult:
        """Parse a source document, reusing a cached AST when possible.

        Parse options are forwarded to :func:`graphql.parse`. The cache key includes
        the source text, source name, location offset, and all parse options.

        :param source: GraphQL source text or a source object.
        :returns: The parsed document and its cache metadata.

        >>> cache = GatewayDocumentCache()
        >>> cache.parse("{ greeting }").cache_hit
        False
        >>> cache.parse("{ greeting }").cache_hit
        True
        """
        source_obj = source if isinstance(source, Source) else Source(source)
        key = _parse_key(source_obj, parse_options)
        entry = self._parse_cache.get(key)
        if entry is not None:
            self._parse_cache.move_to_end(key)
            self._counters.parse_hits += 1
            return ParseResult(entry.document, entry.fingerprint, True)
        document = parse(source_obj, **parse_options)
        fingerprint = get_document_fingerprint(document)
        self._remember(self._parse_cache, key, _ParseEntry(document, fingerprint))
        self._counters.parse_misses += 1
        return ParseResult(document, fingerprint, False)

    def validate(
        self,
        schema: GraphQLSchema,
        document: DocumentNode,
        *,
        policy: PermissionPolicy | None = None,
        policy_fingerprint: str | None = None,
        rules: Collection[type[ASTValidationRule]] | None = None,
        max_errors: int | None = None,
        hide_suggestions: bool = False,
        allow_empty_selection_sets: bool = True,
    ) -> ValidationResult:
        """Validate a document and bind the result to a schema and policy identity.

        A validation result is reused only when the document fingerprint, schema
        fingerprint, policy fingerprint, rule selection, and validation options all
        match. A policy fingerprint change therefore always produces a cache miss and
        a fresh validation, even when the document is unchanged.

        A different schema fingerprint may still reuse the result when every reported
        schema change is purely additive and the attached policy metadata is unchanged.
        The returned metadata records the schema fingerprint that was rebound from.

        :param schema: The schema to validate against.
        :param document: The parsed document to validate.
        :param policy: Optional permission policy whose fingerprint is part of the
            cache binding.
        :param policy_fingerprint: Explicit policy fingerprint when no policy object
            is supplied.
        :param rules: Validation rules to apply. Defaults to the specified rules.
        :param max_errors: Maximum number of validation errors before validation stops.
        :param hide_suggestions: Whether suggestions are omitted from validation errors.
        :param allow_empty_selection_sets: Whether empty selection sets are allowed.
        :returns: Validation errors and the explicit applicability binding.

        >>> from graphql import build_schema, parse
        >>> cache = GatewayDocumentCache()
        >>> schema = build_schema("type Query { greeting: String }")
        >>> cache.validate(schema, parse("{ greeting }")).is_valid
        True
        >>> cache.validate(schema, parse("{ missing }")).is_valid
        False
        """
        document_fingerprint = get_document_fingerprint(document)
        schema_fingerprint = get_schema_fingerprint(schema)
        authorization_metadata = get_authorization_fingerprint(schema)
        policy_id = _policy_fingerprint(policy, policy_fingerprint)
        validation_id = _validation_fingerprint(
            rules, max_errors, hide_suggestions, allow_empty_selection_sets
        )
        key = (
            document_fingerprint,
            schema_fingerprint,
            policy_id,
            validation_id,
        )
        entry = self._validation_cache.get(key)
        if entry is not None:
            self._validation_cache.move_to_end(key)
            self._counters.validation_hits += 1
            return ValidationResult(
                entry.errors,
                entry.schema_fingerprint,
                entry.policy_fingerprint,
                True,
                False,
                None,
            )

        # A safe schema change can keep an existing accepted result applicable. The
        # policy identity must match exactly; a tightened policy is never bypassed.
        for candidate_key in reversed(tuple(self._validation_cache)):
            candidate = self._validation_cache[candidate_key]
            if (
                candidate.document_fingerprint == document_fingerprint
                and candidate.policy_fingerprint == policy_id
                and candidate.validation_fingerprint == validation_id
                and candidate.schema_fingerprint != schema_fingerprint
                and candidate.authorization_metadata == authorization_metadata
                and not candidate.errors
                and _schema_change_allows_reuse(candidate.schema, schema)
            ):
                self._remember(
                    self._validation_cache,
                    key,
                    candidate._replace(
                        schema=schema,
                        schema_fingerprint=schema_fingerprint,
                    ),
                )
                self._counters.validation_reuses += 1
                return ValidationResult(
                    candidate.errors,
                    schema_fingerprint,
                    policy_id,
                    True,
                    True,
                    candidate.schema_fingerprint,
                )

        errors = tuple(
            validate(
                schema,
                document,
                rules,
                max_errors,
                hide_suggestions=hide_suggestions,
                allow_empty_selection_sets=allow_empty_selection_sets,
            )
        )
        self._remember(
            self._validation_cache,
            key,
            _ValidationEntry(
                schema,
                schema_fingerprint,
                policy_id,
                validation_id,
                document_fingerprint,
                errors,
                authorization_metadata,
            ),
        )
        self._counters.validation_misses += 1
        return ValidationResult(
            errors, schema_fingerprint, policy_id, False, False, None
        )

    def prepare(
        self,
        schema: GraphQLSchema,
        source: str | Source,
        *,
        policy: PermissionPolicy | None = None,
        policy_fingerprint: str | None = None,
        operation_name: str | None = None,
        rules: Collection[type[ASTValidationRule]] | None = None,
        max_errors: int | None = None,
        hide_suggestions: bool = False,
        allow_empty_selection_sets: bool = True,
        **parse_options: Any,
    ) -> PreparedOperation:
        """Parse and validate a source document, reusing cached stages safely.

        The parse cache is schema- and policy-independent. The validation result is
        bound to the current schema and policy identity as described by
        :meth:`validate`.

        :param schema: The schema to validate against.
        :param source: GraphQL source text or a source object.
        :param policy: Optional permission policy whose fingerprint is part of the
            validation binding.
        :param policy_fingerprint: Explicit policy fingerprint when no policy object
            is supplied.
        :param operation_name: Operation name supplied by the caller, if any.
        :param rules: Validation rules to apply. Defaults to the specified rules.
        :param max_errors: Maximum number of validation errors before validation stops.
        :param hide_suggestions: Whether suggestions are omitted from validation errors.
        :param allow_empty_selection_sets: Whether empty selection sets are allowed.
        :returns: The prepared operation with cache and binding metadata.

        >>> from graphql import build_schema
        >>> cache = GatewayDocumentCache()
        >>> schema = build_schema("type Query { greeting: String }")
        >>> cache.prepare(schema, "{ greeting }").is_valid
        True
        """
        parsed = self.parse(source, **parse_options)
        validation = self.validate(
            schema,
            parsed.document,
            policy=policy,
            policy_fingerprint=policy_fingerprint,
            rules=rules,
            max_errors=max_errors,
            hide_suggestions=hide_suggestions,
            allow_empty_selection_sets=allow_empty_selection_sets,
        )
        return PreparedOperation(
            parsed.document,
            validation.errors,
            operation_name,
            validation.schema_fingerprint,
            validation.policy_fingerprint,
            parsed.cache_hit,
            validation.cache_hit,
            validation.reused_for_schema_change,
            parsed.fingerprint,
        )

    def execute_sync(
        self,
        schema: GraphQLSchema,
        source: str | Source,
        *,
        policy: PermissionPolicy,
        root_value: Any = None,
        context_value: Any = None,
        variable_values: dict[str, Any] | None = None,
        operation_name: str | None = None,
        field_resolver: GraphQLFieldResolver | None = None,
        type_resolver: GraphQLTypeResolver | None = None,
        middleware: Middleware = None,
        check_sync: bool = False,
        hide_suggestions: bool = False,
        rules: Collection[type[ASTValidationRule]] | None = None,
        max_errors: int | None = None,
        **parse_options: Any,
    ) -> ExecutionResult:
        """Prepare a document and execute it with per-field policy enforcement.

        Validation errors are returned without executing anything. On a successful
        preparation, every field passes through :func:`authorization_middleware`
        before its resolver runs. A validation cache hit never skips this gate.

        :param schema: The schema to validate and execute against.
        :param source: GraphQL source text or a source object.
        :param policy: The permission policy to enforce for this request.
        :param root_value: Initial root value passed to the operation.
        :param context_value: Application context value passed to every resolver.
        :param variable_values: Runtime variable values keyed by variable name.
        :param operation_name: Name of the operation to execute.
        :param field_resolver: Resolver used when a field does not define its own.
        :param type_resolver: Resolver used when an abstract type does not define its
            own type resolver.
        :param middleware: Additional execution middleware to apply after the policy
            gate.
        :param check_sync: Whether execution should verify that no awaitable values are
            returned.
        :param hide_suggestions: Whether suggestions are omitted from errors.
        :param rules: Validation rules to apply. Defaults to the specified rules.
        :param max_errors: Maximum number of validation errors before validation stops.
        :returns: The execution result, with gateway cache metadata in extensions.

        >>> from graphql import build_schema
        >>> schema = build_schema("type Query { greeting: String }")
        >>> policy = AllowListPermissionPolicy([("Query", "greeting")])
        >>> GatewayDocumentCache().execute_sync(
        ...     schema,
        ...     "{ greeting }",
        ...     policy=policy,
        ...     root_value={"greeting": "Hello"},
        ... ).data
        {'greeting': 'Hello'}
        """
        prepared = self.prepare(
            schema,
            source,
            policy=policy,
            operation_name=operation_name,
            rules=rules,
            max_errors=max_errors,
            hide_suggestions=hide_suggestions,
            **parse_options,
        )
        if prepared.errors:
            return ExecutionResult(
                data=None,
                errors=list(prepared.errors),
                extensions={"gateway": prepared.cache_info},
            )
        # Re-check authorization at execution time. A validation result is only a
        # statement about the document's shape, never an execution permit. The
        # middleware below consults the current policy for every field before its
        # resolver runs, so a policy tightening is effective even when the document
        # and the validation result both came from a cache.
        policy_middleware = authorization_middleware(policy)
        if middleware is None:
            combined_middleware: Middleware = [policy_middleware]
        elif isinstance(middleware, MiddlewareManager):
            combined_middleware = [
                policy_middleware,
                _manager_middleware(middleware),
            ]
        elif isinstance(middleware, list | tuple):
            combined_middleware = [policy_middleware, *middleware]
        else:
            combined_middleware = [policy_middleware, middleware]
        result = execute_sync(
            schema,
            prepared.document,
            root_value=root_value,
            context_value=context_value,
            variable_values=variable_values,
            operation_name=operation_name,
            field_resolver=field_resolver,
            type_resolver=type_resolver,
            middleware=combined_middleware,
            check_sync=check_sync,
            hide_suggestions=hide_suggestions,
        )
        extensions = dict(result.extensions or {})
        extensions["gateway"] = prepared.cache_info
        return ExecutionResult(result.data, result.errors, extensions)

    async def execute(
        self,
        schema: GraphQLSchema,
        source: str | Source,
        *,
        policy: PermissionPolicy,
        root_value: Any = None,
        context_value: Any = None,
        variable_values: dict[str, Any] | None = None,
        operation_name: str | None = None,
        field_resolver: GraphQLFieldResolver | None = None,
        type_resolver: GraphQLTypeResolver | None = None,
        middleware: Middleware = None,
        hide_suggestions: bool = False,
        rules: Collection[type[ASTValidationRule]] | None = None,
        max_errors: int | None = None,
        **parse_options: Any,
    ) -> ExecutionResult:
        """Prepare a document and execute it asynchronously with policy enforcement.

        This is the asynchronous counterpart of :meth:`execute_sync`. Validation
        results and parsed documents are reused in the same way, and every field still
        passes through the current permission policy before its resolver runs.

        :param schema: The schema to validate and execute against.
        :param source: GraphQL source text or a source object.
        :param policy: The permission policy to enforce for this request.
        :param root_value: Initial root value passed to the operation.
        :param context_value: Application context value passed to every resolver.
        :param variable_values: Runtime variable values keyed by variable name.
        :param operation_name: Name of the operation to execute.
        :param field_resolver: Resolver used when a field does not define its own.
        :param type_resolver: Resolver used when an abstract type does not define its
            own type resolver.
        :param middleware: Additional execution middleware to apply after the policy
            gate.
        :param hide_suggestions: Whether suggestions are omitted from errors.
        :param rules: Validation rules to apply. Defaults to the specified rules.
        :param max_errors: Maximum number of validation errors before validation stops.
        :returns: The execution result, with gateway cache metadata in extensions.

        >>> from graphql import build_schema
        >>> schema = build_schema("type Query { greeting: String }")
        >>> policy = AllowListPermissionPolicy([("Query", "greeting")])
        >>> GatewayDocumentCache().execute_sync(
        ...     schema,
        ...     "{ greeting }",
        ...     policy=policy,
        ...     root_value={"greeting": "Hello"},
        ... ).data
        {'greeting': 'Hello'}
        """
        prepared = self.prepare(
            schema,
            source,
            policy=policy,
            operation_name=operation_name,
            rules=rules,
            max_errors=max_errors,
            hide_suggestions=hide_suggestions,
            **parse_options,
        )
        if prepared.errors:
            return ExecutionResult(
                data=None,
                errors=list(prepared.errors),
                extensions={"gateway": prepared.cache_info},
            )
        policy_middleware = authorization_middleware(policy)
        if middleware is None:
            combined_middleware: Middleware = [policy_middleware]
        elif isinstance(middleware, MiddlewareManager):
            combined_middleware = [
                policy_middleware,
                _manager_middleware(middleware),
            ]
        elif isinstance(middleware, list | tuple):
            combined_middleware = [policy_middleware, *middleware]
        else:
            combined_middleware = [policy_middleware, middleware]
        result = execute(
            schema,
            prepared.document,
            root_value=root_value,
            context_value=context_value,
            variable_values=variable_values,
            operation_name=operation_name,
            field_resolver=field_resolver,
            type_resolver=type_resolver,
            middleware=combined_middleware,
            hide_suggestions=hide_suggestions,
        )
        if is_awaitable(result):
            result = await cast("Awaitable[ExecutionResult]", result)
        result = cast("ExecutionResult", result)
        extensions = dict(result.extensions or {})
        extensions["gateway"] = prepared.cache_info
        return ExecutionResult(result.data, result.errors, extensions)
