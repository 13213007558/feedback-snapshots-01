# Copyright 2021-2025 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Turn Cerbos ``PlanResources`` output into list-query predicates.

Cerbos answers a ``PlanResources`` call with one of three filter kinds:

* ``KIND_ALWAYS_ALLOWED``  - every resource of the kind is authorized;
* ``KIND_ALWAYS_DENIED``   - no resource is authorized;
* ``KIND_CONDITIONAL``     - a boolean expression over resource attributes.

The expression has to be applied *before* pagination, otherwise rows can be
hidden from later pages or leak through a page boundary.  This module:

1. normalizes the two wire shapes (HTTP dataclasses and gRPC protobuf) into
   one AST;
2. converts the operators the backing store understands into a parameterized
   query fragment (SQL by default);
3. keeps any subtree that cannot be translated for an in-memory fallback, so
   the conjunction of both parts stays equivalent to the original plan.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Sequence

from cerbos.engine.v1 import engine_pb2
from cerbos.response.v1 import response_pb2
from cerbos.sdk import model

# Operators emitted by the Cerbos query planner.  See:
# https://docs.cerbos.dev/cerbos/latest/policies/filtering/
_LOGICAL_OPS = frozenset({"and", "or", "not"})
_COMPARISON_OPS = frozenset({"eq", "ne", "lt", "lte", "gt", "gte", "in"})
_STRING_OPS = frozenset({"starts_with", "ends_with", "contains"})
_SET_OPS = frozenset(
    {"intersects", "intersects_pairs", "is_set", "union_sets", "size"}
)
ALL_OPS = _LOGICAL_OPS | _COMPARISON_OPS | _STRING_OPS | _SET_OPS

# Operators the default SQL conversion can emit.  Everything else forces the
# containing subtree onto the in-memory fallback.  ``list`` is a structural
# node (the operand of ``in``) rather than a predicate.
SQL_CAPABLE_OPS = _LOGICAL_OPS | _COMPARISON_OPS | {"list"}

_RESOURCE_VAR_PREFIXES = ("R.attr.", "request.resource.attr.")
_RESOURCE_SCOPED_VARS = ("R.", "request.resource.")


class PlanFilterKind(str, Enum):
    ALWAYS_ALLOWED = "KIND_ALWAYS_ALLOWED"
    ALWAYS_DENIED = "KIND_ALWAYS_DENIED"
    CONDITIONAL = "KIND_CONDITIONAL"


class PlanFilterError(Exception):
    """Base class for plan conversion failures."""


class UnsupportedPlanOperator(PlanFilterError):
    """Raised when no store handler is registered for an operator."""

    def __init__(self, operator: str):
        super().__init__(f"operator {operator!r} cannot be converted")
        self.operator = operator


class UnsupportedPlanVariable(PlanFilterError):
    """Raised when a variable does not resolve to a resource attribute."""

    def __init__(self, variable: str):
        super().__init__(
            f"variable {variable!r} is not a resource attribute and cannot be "
            "pushed into a resource query"
        )
        self.variable = variable


@dataclass(frozen=True)
class Literal:
    value: Any


@dataclass(frozen=True)
class Variable:
    """A resource attribute reference, e.g. ``R.attr.department``."""

    name: str


@dataclass(frozen=True)
class Expression:
    operator: str
    operands: tuple["Node", ...]


Node = Literal | Variable | Expression


@dataclass(frozen=True)
class QueryPlan:
    """Normalized representation of a ``PlanResources`` filter.

    ``condition`` is ``None`` for the two unconditional kinds.
    """

    kind: PlanFilterKind
    condition: Node | None = None

    @classmethod
    def from_http(cls, response: model.PlanResourcesResponse) -> "QueryPlan":
        return _from_http_filter(response.filter)

    @classmethod
    def from_grpc(cls, response: response_pb2.PlanResourcesResponse) -> "QueryPlan":
        return _from_grpc_filter(response.filter)

    @classmethod
    def from_any(cls, response: Any) -> "QueryPlan":
        if isinstance(response, model.PlanResourcesResponse):
            return cls.from_http(response)
        if isinstance(response, response_pb2.PlanResourcesResponse):
            return cls.from_grpc(response)
        if isinstance(response, model.PlanResourcesFilter):
            return _from_http_filter(response)
        if isinstance(response, engine_pb2.PlanResourcesFilter):
            return _from_grpc_filter(response)
        raise TypeError(f"unsupported plan response type: {type(response)!r}")


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

def _kind_from_name(name: str | int) -> PlanFilterKind:
    if isinstance(name, int):
        name = engine_pb2.PlanResourcesFilter.Kind.Name(name)
    return PlanFilterKind(name)


def _from_http_filter(flt: model.PlanResourcesFilter | None) -> QueryPlan:
    if flt is None:
        raise PlanFilterError("plan response contains no filter")
    kind = PlanFilterKind(flt.kind.value if isinstance(flt.kind, Enum) else flt.kind)
    condition = _normalize_http(flt.condition) if kind is PlanFilterKind.CONDITIONAL else None
    return QueryPlan(kind=kind, condition=_simplify(condition))


def _from_grpc_filter(flt: engine_pb2.PlanResourcesFilter) -> QueryPlan:
    kind = _kind_from_name(flt.kind)
    condition = (
        _normalize_grpc(flt.condition) if kind is PlanFilterKind.CONDITIONAL else None
    )
    return QueryPlan(kind=kind, condition=_simplify(condition))


def _normalize_http(node: Any) -> Node:
    if isinstance(node, model.PlanResourcesValue):
        return Literal(node.value)
    if isinstance(node, model.PlanResourcesVariable):
        return Variable(_canonical_variable(node.variable))
    if isinstance(node, model.PlanResourcesExpression):
        return Expression(
            node.expression.operator,
            tuple(_normalize_http(op) for op in node.expression.operands),
        )
    raise PlanFilterError(f"unrecognized HTTP plan operand: {node!r}")


def _normalize_grpc(node: engine_pb2.PlanResourcesFilter.Expression.Operand) -> Node:
    which = node.WhichOneof("node")
    if which == "value":
        return Literal(_proto_value(node.value))
    if which == "variable":
        return Variable(_canonical_variable(node.variable))
    if which == "expression":
        return Expression(
            node.expression.operator,
            tuple(_normalize_grpc(op) for op in node.expression.operands),
        )
    raise PlanFilterError(f"unrecognized gRPC plan operand: {node!r}")


def _canonical_variable(name: str) -> str:
    """Normalize the two wire spellings onto ``R.attr.*`` / ``R.*``."""
    if name.startswith("request.resource.attr."):
        return "R.attr." + name[len("request.resource.attr."):]
    if name.startswith("request.resource."):
        return "R." + name[len("request.resource."):]
    return name


def _proto_value(value: Any) -> Any:
    kind = value.WhichOneof("kind")
    if kind == "null_value":
        return None
    return getattr(value, kind)


def _simplify(node: Node | None) -> Node | None:
    """Fold constant ``and``/``or``/``not`` subtrees the way CEL would."""
    if not isinstance(node, Expression):
        return node
    operator = node.operator
    operands = tuple(_simplify(op) for op in node.operands)

    if operator == "not":
        inner = operands[0]
        if isinstance(inner, Literal):
            return Literal(not bool(inner.value))
        return Expression(operator, (inner,))

    if operator == "and":
        flattened: list[Node] = []
        for op in operands:
            if isinstance(op, Literal) and not bool(op.value):
                return Literal(False)
            if isinstance(op, Literal):
                continue
            if isinstance(op, Expression) and op.operator == "and":
                flattened.extend(op.operands)
            else:
                flattened.append(op)
        if not flattened:
            return Literal(True)
        if len(flattened) == 1:
            return flattened[0]
        return Expression(operator, tuple(flattened))

    if operator == "or":
        flattened = []
        for op in operands:
            if isinstance(op, Literal) and bool(op.value):
                return Literal(True)
            if isinstance(op, Literal):
                continue
            if isinstance(op, Expression) and op.operator == "or":
                flattened.extend(op.operands)
            else:
                flattened.append(op)
        if not flattened:
            return Literal(False)
        if len(flattened) == 1:
            return flattened[0]
        return Expression(operator, tuple(flattened))

    return Expression(operator, operands)


# ---------------------------------------------------------------------------
# Variable resolution and operator handlers
# ---------------------------------------------------------------------------

def default_column_resolver(variable: str) -> str:
    """Map a resource-attribute variable onto a SQL column name.

    ``R.attr.foo`` / ``request.resource.attr.foo`` -> ``foo``;
    ``R.id`` / ``request.resource.id`` -> ``id``.
    """
    for prefix in _RESOURCE_VAR_PREFIXES:
        if variable.startswith(prefix):
            return variable[len(prefix):]
    for prefix in _RESOURCE_SCOPED_VARS:
        if variable.startswith(prefix):
            return variable[len(prefix):]
    raise UnsupportedPlanVariable(variable)


def ensure_resource_variable(variable: str) -> None:
    if not (
        variable.startswith(_RESOURCE_VAR_PREFIXES)
        or variable.startswith(_RESOURCE_SCOPED_VARS)
    ):
        raise UnsupportedPlanVariable(variable)


ColumnResolver = Callable[[str], str]
# A handler returns (sql_fragment, params).  Params are appended in order.
OperatorHandler = Callable[[Sequence[Node], ColumnResolver], tuple[str, list[Any]]]


# ---------------------------------------------------------------------------
# SQL conversion
# ---------------------------------------------------------------------------

_SQL_COMPARISONS = {
    "eq": "=",
    "ne": "!=",
    "lt": "<",
    "lte": "<=",
    "gt": ">",
    "gte": ">=",
}


def _comparison_pair(
    operands: Sequence[Node],
) -> tuple[Variable, Literal] | None:
    if len(operands) != 2:
        return None
    left, right = operands
    if isinstance(left, Variable) and isinstance(right, Literal):
        return left, right
    if isinstance(right, Variable) and isinstance(left, Literal):
        return right, left
    return None


def to_sql(
    node: Node,
    column_resolver: ColumnResolver = default_column_resolver,
    handlers: dict[str, OperatorHandler] | None = None,
) -> tuple[str, list[Any]]:
    """Convert a normalized node to ``(sql_fragment, bind_params)``.

    Raises :class:`UnsupportedPlanOperator` / :class:`UnsupportedPlanVariable`
    when a subtree cannot be expressed with the registered handlers.  Callers
    that want a fallback should use :func:`list_query` instead of catching
    half-built fragments.
    """
    handlers = handlers or {}
    return _to_sql(node, column_resolver, handlers)


def _to_sql(
    node: Node,
    column_resolver: ColumnResolver,
    handlers: dict[str, OperatorHandler],
) -> tuple[str, list[Any]]:
    if isinstance(node, Literal):
        return ("1" if bool(node.value) else "0", [])

    if isinstance(node, Variable):
        ensure_resource_variable(node.name)
        return column_resolver(node.name), []

    operator = node.operator
    if operator in handlers:
        return handlers[operator](node.operands, column_resolver)

    if operator in _LOGICAL_OPS:
        return _logical_to_sql(node, column_resolver, handlers)

    if operator in _SQL_COMPARISONS:
        return _comparison_to_sql(node, column_resolver)

    if operator == "in":
        return _in_to_sql(node, column_resolver)

    raise UnsupportedPlanOperator(operator)


def _logical_to_sql(
    node: Expression,
    column_resolver: ColumnResolver,
    handlers: dict[str, OperatorHandler],
) -> tuple[str, list[Any]]:
    if node.operator == "not":
        fragment, params = _to_sql(node.operands[0], column_resolver, handlers)
        return f"NOT ({fragment})", params

    connector = " AND " if node.operator == "and" else " OR "
    fragments: list[str] = []
    params: list[Any] = []
    for operand in node.operands:
        fragment, inner_params = _to_sql(operand, column_resolver, handlers)
        fragments.append(f"({fragment})")
        params.extend(inner_params)
    return connector.join(fragments), params


def _comparison_to_sql(
    node: Expression, column_resolver: ColumnResolver
) -> tuple[str, list[Any]]:
    pair = _comparison_pair(node.operands)
    if pair is None:
        raise UnsupportedPlanOperator(node.operator)
    variable, literal = pair
    ensure_resource_variable(variable.name)
    column = column_resolver(variable.name)

    if node.operator == "eq":
        if literal.value is None:
            return f"{column} IS NULL", []
        return f"{column} = ?", [literal.value]
    if node.operator == "ne":
        if literal.value is None:
            return f"{column} IS NOT NULL", []
        return f"{column} != ?", [literal.value]
    if literal.value is None:
        raise UnsupportedPlanOperator(node.operator)
    return f"{column} {_SQL_COMPARISONS[node.operator]} ?", [literal.value]


def _in_to_sql(
    node: Expression, column_resolver: ColumnResolver
) -> tuple[str, list[Any]]:
    operands = node.operands
    if len(operands) != 2 or not isinstance(operands[0], Variable):
        raise UnsupportedPlanOperator("in")
    candidate = operands[1]
    if not isinstance(candidate, Expression) or candidate.operator != "list":
        raise UnsupportedPlanOperator("in")
    if any(not isinstance(op, Literal) for op in candidate.operands):
        raise UnsupportedPlanOperator("in")
    values = [op.value for op in candidate.operands]
    ensure_resource_variable(operands[0].name)
    column = column_resolver(operands[0].name)
    placeholders = ", ".join("?" for _ in values)
    return f"{column} IN ({placeholders})", values


# ---------------------------------------------------------------------------
# In-memory evaluation of the fallback subtree
# ---------------------------------------------------------------------------

def evaluate(node: Node, row: dict[str, Any]) -> bool:
    """Evaluate a node against a resource row (a mapping of attr -> value)."""
    if isinstance(node, Literal):
        return bool(node.value)

    if isinstance(node, Variable):
        return _row_value(row, node.name)

    operator = node.operator
    operands = node.operands

    if operator == "and":
        return all(evaluate(op, row) for op in operands)
    if operator == "or":
        return any(evaluate(op, row) for op in operands)
    if operator == "not":
        return not evaluate(operands[0], row)
    if operator == "list":
        return [_operand_value(op, row) for op in operands]

    values = [_operand_value(op, row) for op in operands]

    if operator == "eq":
        return values[0] == values[1]
    if operator == "ne":
        return values[0] != values[1]
    if operator == "lt":
        return values[0] < values[1]
    if operator == "lte":
        return values[0] <= values[1]
    if operator == "gt":
        return values[0] > values[1]
    if operator == "gte":
        return values[0] >= values[1]
    if operator == "in":
        return values[0] in values[1]
    if operator == "starts_with":
        return isinstance(values[0], str) and values[0].startswith(values[1])
    if operator == "ends_with":
        return isinstance(values[0], str) and values[0].endswith(values[1])
    if operator == "contains":
        return values[1] in values[0]
    if operator == "intersects":
        return bool(set(values[0]) & set(values[1]))
    if operator == "intersects_pairs":
        return any(a == b for a in values[0] for b in values[1])
    if operator == "is_set":
        return isinstance(values[0], (list, set, tuple))
    if operator == "size":
        return len(values[0])
    if operator == "union_sets":
        return list(set(values[0]) | set(values[1]))
    raise UnsupportedPlanOperator(operator)


def _operand_value(node: Node, row: dict[str, Any]) -> Any:
    if isinstance(node, Literal):
        return node.value
    if isinstance(node, Variable):
        return _row_value(row, node.name)
    return evaluate(node, row)


def _row_value(row: dict[str, Any], variable: str) -> Any:
    for prefix in _RESOURCE_VAR_PREFIXES:
        if variable.startswith(prefix):
            return row.get(variable[len(prefix):])
    for prefix in _RESOURCE_SCOPED_VARS:
        if variable.startswith(prefix):
            return row.get(variable[len(prefix):])
    raise UnsupportedPlanVariable(variable)


# ---------------------------------------------------------------------------
# Splitting translatable and untranslatable subtrees
# ---------------------------------------------------------------------------

def _node_uses_unsupported(
    node: Node,
    column_resolver: ColumnResolver,
    handlers: dict[str, OperatorHandler],
) -> bool:
    if isinstance(node, (Literal, Variable)):
        if isinstance(node, Variable):
            try:
                ensure_resource_variable(node.name)
                column_resolver(node.name)
            except PlanFilterError:
                return True
        return False

    operator = node.operator
    if operator not in SQL_CAPABLE_OPS and operator not in handlers:
        return True
    return any(
        _node_uses_unsupported(op, column_resolver, handlers) for op in node.operands
    )


def _split(
    node: Node,
    column_resolver: ColumnResolver,
    handlers: dict[str, OperatorHandler],
) -> tuple[Node | None, Node | None]:
    """Split ``node`` into (pushdown subtree, in-memory subtree).

    The split is only valid at ``and`` boundaries: an unsupported operand
    nested under ``or`` cannot be detached without changing semantics, so the
    whole subtree stays on the fallback path.
    """
    if not _node_uses_unsupported(node, column_resolver, handlers):
        return node, None

    if isinstance(node, Expression) and node.operator == "and":
        push_parts: list[Node] = []
        fallback_parts: list[Node] = []
        for operand in node.operands:
            push, fallback = _split(operand, column_resolver, handlers)
            if push is not None:
                push_parts.append(push)
            if fallback is not None:
                fallback_parts.append(fallback)
        push_node = _merge("and", push_parts)
        fallback_node = _merge("and", fallback_parts)
        return push_node, fallback_node

    return None, node


def _merge(operator: str, parts: list[Node]) -> Node | None:
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    return Expression(operator, tuple(parts))


@dataclass(frozen=True)
class ListQuery:
    """A ready-to-run decomposition of a plan for a list endpoint.

    Attributes:
        decision: the normalized filter kind.
        sql: parameterized fragment to AND into the store query (``None``
            means no pushdown constraint; ``"0"`` means deny everything).
        params: bind parameters for ``sql``.
        fallback: AST subtree that must still be evaluated per candidate row.
    """

    decision: PlanFilterKind
    sql: str | None
    params: list[Any] = field(default_factory=list)
    fallback: Node | None = None

    def filter_rows(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Apply the in-memory fallback to rows already returned by the store."""
        if self.fallback is None:
            return list(rows)
        return [row for row in rows if evaluate(self.fallback, row)]

    @property
    def denies_all(self) -> bool:
        return self.decision is PlanFilterKind.ALWAYS_DENIED or self.sql == "0"


def list_query(
    plan: QueryPlan,
    column_resolver: ColumnResolver = default_column_resolver,
    handlers: dict[str, OperatorHandler] | None = None,
) -> ListQuery:
    """Decompose a plan into a store fragment plus an in-memory fallback.

    The store fragment and the fallback predicate are conjuncts, so applying
    both (store first, then the fallback before pagination) is equivalent to
    evaluating the original plan on every row.
    """
    handlers = handlers or {}

    if plan.kind is PlanFilterKind.ALWAYS_DENIED:
        return ListQuery(decision=plan.kind, sql="0")
    if plan.kind is PlanFilterKind.ALWAYS_ALLOWED:
        return ListQuery(decision=plan.kind, sql=None)

    condition = _simplify(plan.condition)
    if isinstance(condition, Literal):
        if condition.value:
            return ListQuery(decision=plan.kind, sql="1")
        return ListQuery(
            decision=plan.kind, sql="0", fallback=Literal(False)
        )
    if condition is None:
        raise PlanFilterError("conditional plan is missing a condition")

    push_node, fallback_node = _split(condition, column_resolver, handlers)
    if push_node is None:
        return ListQuery(decision=plan.kind, sql=None, fallback=fallback_node)

    sql, params = _to_sql(push_node, column_resolver, handlers)
    return ListQuery(
        decision=plan.kind, sql=sql, params=params, fallback=fallback_node
    )
