# Copyright 2021-2025 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

import sqlite3

import pytest

from cerbos.sdk.model import (
    PlanResourcesResponse,
    PlanResourcesValue,
    PlanResourcesVariable,
)
from cerbos.sdk.plan_filter import (
    Expression,
    Literal,
    PlanFilterKind,
    QueryPlan,
    UnsupportedPlanOperator,
    UnsupportedPlanVariable,
    Variable,
    evaluate,
    list_query,
    to_sql,
)

from .fixtures import ORACLES, ROWS, build_grpc_plans, build_http_plans


@pytest.fixture
def http_plans():
    return build_http_plans()


@pytest.fixture
def grpc_plans():
    return build_grpc_plans()


# ---------------------------------------------------------------------------
# In-memory store helper: authorization constraints are applied BEFORE
# pagination, mirroring how a real list endpoint must compose the query.
# ---------------------------------------------------------------------------

def _open_store():
    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE docs (id TEXT PRIMARY KEY, department TEXT, geography TEXT,"
        " owner TEXT, level INTEGER, active INTEGER)"
    )
    conn.executemany(
        "INSERT INTO docs VALUES (:id, :department, :geography, :owner,"
        " :level, :active)",
        ROWS,
    )
    conn.commit()
    return conn


def _authorized_ids(query, fallback_rows=None):
    """Run a ListQuery against the store and return authorized ids."""
    conn = _open_store()
    try:
        if query.denies_all:
            return []
        sql = "SELECT id FROM docs"
        params: list = []
        if query.sql is not None:
            sql += f" WHERE {query.sql}"
            params = list(query.params)
        sql += " ORDER BY id"
        store_rows = conn.execute(sql, params).fetchall()
        ids = [row[0] for row in store_rows]
        if query.fallback is not None:
            by_id = {row["id"]: row for row in ROWS}
            ids = [i for i in ids if evaluate(query.fallback, by_id[i])]
        return ids
    finally:
        conn.close()


def _paginate(query, limit, offset):
    """Page through an authorized, ordered id list."""
    return _authorized_ids(query)[offset : offset + limit]


def _oracle_ids(scenario):
    return sorted(row["id"] for row in ROWS if ORACLES[scenario](row))


# ---------------------------------------------------------------------------
# Normalization: HTTP dataclasses and gRPC protos yield the same AST.
# ---------------------------------------------------------------------------

def test_wire_shapes_normalize_identically(http_plans, grpc_plans):
    for scenario in http_plans:
        http_plan = QueryPlan.from_any(http_plans[scenario])
        grpc_plan = QueryPlan.from_any(grpc_plans[scenario])
        assert http_plan == grpc_plan, scenario
        assert http_plan.kind == grpc_plan.kind


def test_http_response_wrapper(http_plans):
    response = PlanResourcesResponse(
        request_id="req-1",
        action="view",
        resource_kind="docs",
        policy_version="default",
        filter=http_plans["conditional"],
    )
    plan = QueryPlan.from_http(response)
    assert plan.kind is PlanFilterKind.CONDITIONAL
    assert isinstance(plan.condition, Expression)


def test_grpc_variable_prefix_is_normalized(http_plans, grpc_plans):
    grpc = QueryPlan.from_any(grpc_plans["conditional"])
    http = QueryPlan.from_any(http_plans["conditional"])
    variables = {
        node.name for node in _walk(grpc.condition) if isinstance(node, Variable)
    }
    # gRPC uses request.resource.attr.*; HTTP uses R.attr.*.  Both wire
    # spellings canonicalize onto R.attr.* and resolve to the same columns.
    assert variables == {"R.attr.department", "R.attr.geography"}
    assert grpc == http
    sql, params = to_sql(grpc.condition)
    assert "department = ?" in sql
    assert "geography = ?" in sql
    assert params == ["marketing", "GB"]


def _walk(node):
    yield node
    if isinstance(node, Expression):
        for operand in node.operands:
            yield from _walk(operand)


# ---------------------------------------------------------------------------
# Unconditional kinds
# ---------------------------------------------------------------------------

def test_always_allowed(http_plans, grpc_plans):
    for plans in (http_plans, grpc_plans):
        query = list_query(QueryPlan.from_any(plans["allow"]))
        assert query.sql is None
        assert query.fallback is None
        assert not query.denies_all
        assert _authorized_ids(query) == _oracle_ids("allow")


def test_always_denied(http_plans, grpc_plans):
    for plans in (http_plans, grpc_plans):
        query = list_query(QueryPlan.from_any(plans["deny"]))
        assert query.denies_all
        assert _authorized_ids(query) == []
        assert _oracle_ids("deny") == []


# ---------------------------------------------------------------------------
# Fully translatable conditional: pure SQL pushdown, no fallback needed.
# ---------------------------------------------------------------------------

def test_conditional_pure_pushdown_matches_per_item_check(http_plans, grpc_plans):
    for plans in (http_plans, grpc_plans):
        plan = QueryPlan.from_any(plans["conditional"])
        query = list_query(plan)
        assert query.fallback is None
        assert query.sql is not None
        assert _authorized_ids(query) == _oracle_ids("conditional")


def test_conditional_expected_ids(http_plans):
    query = list_query(QueryPlan.from_any(http_plans["conditional"]))
    assert _authorized_ids(query) == ["E01", "E02", "E03", "E05", "E07"]


# ---------------------------------------------------------------------------
# Partially uncompilable condition: translatable branch goes to SQL, the
# intersects() branch is retained as an in-memory fallback.
# ---------------------------------------------------------------------------

def test_partial_plan_splits_pushdown_and_fallback(http_plans, grpc_plans):
    for plans in (http_plans, grpc_plans):
        plan = QueryPlan.from_any(plans["partial"])
        query = list_query(plan)
        assert query.sql == "department = ?"
        assert query.params == ["sales"]
        assert isinstance(query.fallback, Expression)
        assert query.fallback.operator == "intersects"
        assert _authorized_ids(query) == _oracle_ids("partial")


def test_partial_plan_expected_ids(http_plans):
    query = list_query(QueryPlan.from_any(http_plans["partial"]))
    # E03 and E04 are sales; only E03 carries the "red" tag requirement...
    # neither actually does, so the fallback narrows the SQL candidate set.
    assert _authorized_ids(query) == []
    # ...and relaxing the fallback shows the SQL branch alone was broader.
    conn_rows = [row for row in ROWS if row["department"] == "sales"]
    assert {row["id"] for row in conn_rows} == {"E03", "E04"}


def test_fully_untranslatable_keeps_everything_in_fallback(http_plans):
    from cerbos.sdk.model import PlanResourcesExpression
    expr = PlanResourcesExpression(
        expression=PlanResourcesExpression.Expr(
            operator="intersects",
            operands=[
                PlanResourcesVariable(variable="R.attr.tags"),
                PlanResourcesExpression(
                    expression=PlanResourcesExpression.Expr(
                        operator="list",
                        operands=[PlanResourcesValue(value="red")],
                    )
                ),
            ],
        )
    )
    from cerbos.sdk.model import PlanResourcesFilter, PlanResourcesFilterKind
    flt = PlanResourcesFilter(
        kind=PlanResourcesFilterKind.CONDITIONAL, condition=expr
    )
    plan = QueryPlan.from_any(flt)
    query = list_query(plan)
    assert query.sql is None
    assert query.fallback is not None
    got = sorted(
        row["id"] for row in ROWS if evaluate(query.fallback, row)
    )
    assert got == ["E01", "E02", "E06", "E08"]


def test_unsupported_operator_under_or_cannot_be_split(http_plans):
    # An unsupported branch inside OR must stay whole on the fallback path:
    # detaching it would change the truth table.
    from cerbos.sdk.model import PlanResourcesExpression
    expr = PlanResourcesExpression(
        expression=PlanResourcesExpression.Expr(
            operator="or",
            operands=[
                PlanResourcesExpression(
                    expression=PlanResourcesExpression.Expr(
                        operator="eq",
                        operands=[
                            PlanResourcesVariable(variable="R.attr.owner"),
                            PlanResourcesValue(value="alice"),
                        ],
                    )
                ),
                PlanResourcesExpression(
                    expression=PlanResourcesExpression.Expr(
                        operator="starts_with",
                        operands=[
                            PlanResourcesVariable(variable="R.attr.owner"),
                            PlanResourcesValue(value="z"),
                        ],
                    )
                ),
            ],
        )
    )
    from cerbos.sdk.model import PlanResourcesFilter, PlanResourcesFilterKind
    flt = PlanResourcesFilter(
        kind=PlanResourcesFilterKind.CONDITIONAL, condition=expr
    )
    plan = QueryPlan.from_any(flt)
    query = list_query(plan)
    assert query.sql is None
    assert query.fallback is not None


# ---------------------------------------------------------------------------
# Nested NOT / comparisons and null handling
# ---------------------------------------------------------------------------

def test_nested_not_and_comparison(http_plans, grpc_plans):
    for plans in (http_plans, grpc_plans):
        plan = QueryPlan.from_any(plans["nested"])
        query = list_query(plan)
        assert "NOT" in query.sql
        assert _authorized_ids(query) == _oracle_ids("nested")
    # No row satisfies level >= 3 AND owner == alice (alice is level 2).
    assert _oracle_ids("nested") == []


def test_null_equality_uses_is_null():
    node = Expression(
        "eq",
        (Variable("R.attr.owner"), Literal(None)),
    )
    sql, params = to_sql(node)
    assert sql == "owner IS NULL"
    assert params == []


def test_unknown_variable_rejected():
    node = Expression("eq", (Variable("P.attr.tenant"), Literal("acme")))
    with pytest.raises(UnsupportedPlanVariable):
        to_sql(node)
    # It can still be evaluated in memory only if the row happens to carry it;
    # a principal variable without row data fails loudly rather than silently
    # matching.
    with pytest.raises(UnsupportedPlanVariable):
        evaluate(node, {"owner": "alice"})


def test_unknown_operator_raises_directly():
    node = Expression(
        "starts_with", (Variable("R.attr.owner"), Literal("a"))
    )
    with pytest.raises(UnsupportedPlanOperator):
        to_sql(node)


def test_custom_handler_extends_sql_capabilities():
    def starts_with_handler(operands, column_resolver):
        variable, literal = operands
        column = column_resolver(variable.name)
        return f"{column} LIKE ?", [f"{literal.value}%"]

    node = Expression(
        "starts_with", (Variable("R.attr.owner"), Literal("a"))
    )
    sql, params = to_sql(node, handlers={"starts_with": starts_with_handler})
    assert sql == "owner LIKE ?"
    assert params == ["a%"]


# ---------------------------------------------------------------------------
# Pagination: filtering first means every page stays within the authorized
# id set, regardless of page size.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("limit", [1, 2, 3, 5, 100])
def test_pagination_never_leaks_unauthorized_rows(http_plans, limit):
    query = list_query(QueryPlan.from_any(http_plans["conditional"]))
    authorized = _oracle_ids("conditional")
    seen: list[str] = []
    offset = 0
    while True:
        page = _paginate(query, limit, offset)
        if not page:
            break
        assert all(i in authorized for i in page)
        seen.extend(page)
        offset += limit
    assert seen == authorized


def test_naive_pagination_after_fetch_hides_authorized_rows():
    # Demonstrate the failure mode this design exists to prevent: paging the
    # raw table and filtering rows only after fetching a page shrinks pages
    # instead of pulling further authorized rows in.  A geography == "US"
    # plan authorizes E02 and E06; the first raw page (E01..E03) contains
    # one denied row (E01) and one authorized row (E02).
    from cerbos.sdk.model import (
        PlanResourcesExpression,
        PlanResourcesFilter,
        PlanResourcesFilterKind,
        PlanResourcesValue,
        PlanResourcesVariable,
    )

    us_filter = PlanResourcesFilter(
        kind=PlanResourcesFilterKind.CONDITIONAL,
        condition=PlanResourcesExpression(
            expression=PlanResourcesExpression.Expr(
                operator="eq",
                operands=[
                    PlanResourcesVariable(variable="R.attr.geography"),
                    PlanResourcesValue(value="US"),
                ],
            )
        ),
    )
    query = list_query(QueryPlan.from_any(us_filter))
    limit = 2

    def oracle(row):
        return row["geography"] == "US"

    # Naive path: fetch a raw page of two rows, then filter in app code.
    naive_page = [row["id"] for row in ROWS[:limit] if oracle(row)]
    # Correct path: constrain the store query first, then paginate.
    correct_page = _paginate(query, limit, 0)

    # The naive page drops E01 and cannot backfill, returning one row; the
    # pushdown query skips denied rows and fills the page with E02 then E06.
    assert naive_page == ["E02"]
    assert correct_page == ["E02", "E06"]
    assert _authorized_ids(query) == ["E02", "E06"]


# ---------------------------------------------------------------------------
# Constant folding
# ---------------------------------------------------------------------------

def test_literal_subtrees_fold():
    plan = QueryPlan(
        kind=PlanFilterKind.CONDITIONAL,
        condition=Expression(
            "and",
            (Literal(True), Expression(
                "eq", (Variable("R.attr.department"), Literal("sales"))
            )),
        ),
    )
    query = list_query(plan)
    assert query.sql == "department = ?"
    assert query.params == ["sales"]


def test_constant_false_folds_to_deny_all():
    plan = QueryPlan(
        kind=PlanFilterKind.CONDITIONAL,
        condition=Expression(
            "and", (Literal(True), Literal(False))
        ),
    )
    query = list_query(plan)
    assert query.denies_all


# ---------------------------------------------------------------------------
# Deeply mixed trees and non-resource variables
# ---------------------------------------------------------------------------

def test_or_with_splittable_and_keeps_or_subtree_whole(http_plans):
    # (eq(owner,'alice')) OR (eq(department,'sales') AND intersects(tags,...))
    # The second OR arm contains an unsupported node: the arm cannot be pushed
    # down at all, but the first arm is still translatable on its own.
    from cerbos.sdk.model import (
        PlanResourcesExpression,
        PlanResourcesFilter,
        PlanResourcesFilterKind,
        PlanResourcesValue,
        PlanResourcesVariable,
    )

    def var(name):
        return PlanResourcesVariable(variable=name)

    def val(value):
        return PlanResourcesValue(value=value)

    def expr(operator, *operands):
        return PlanResourcesExpression(
            expression=PlanResourcesExpression.Expr(
                operator=operator, operands=list(operands)
            )
        )

    tree = expr(
        "or",
        expr("eq", var("R.attr.owner"), val("alice")),
        expr(
            "and",
            expr("eq", var("R.attr.department"), val("sales")),
            expr(
                "intersects", var("R.attr.tags"),
                expr("list", val("red")),
            ),
        ),
    )
    flt = PlanResourcesFilter(
        kind=PlanResourcesFilterKind.CONDITIONAL, condition=tree
    )
    plan = QueryPlan.from_any(flt)
    query = list_query(plan)
    # No split at the OR boundary: whole tree falls back, no SQL fragment.
    assert query.sql is None
    assert query.fallback is not None

    def oracle(row):
        return row["owner"] == "alice" or (
            row["department"] == "sales" and bool(set(row["tags"]) & {"red"})
        )

    got = sorted(
        row["id"] for row in ROWS if evaluate(query.fallback, row)
    )
    want = sorted(row["id"] for row in ROWS if oracle(row))
    assert got == want == ["E01"]


def test_principal_variable_forces_fallback_not_allow_all():
    # A condition referencing a principal attribute cannot become a resource
    # column predicate; it must stay on the in-memory path and fail loudly if
    # the row data cannot supply it.
    node = Expression(
        "eq", (Variable("P.attr.tenant"), Literal("acme"))
    )
    plan = QueryPlan(kind=PlanFilterKind.CONDITIONAL, condition=node)
    query = list_query(plan)
    assert query.sql is None
    assert query.fallback == node
    with pytest.raises(UnsupportedPlanVariable):
        evaluate(query.fallback, {"id": "E01"})


def test_mixed_resource_and_principal_and_splits_at_and():
    # eq(R.attr.department,'sales') AND eq(P.attr.tenant,'acme')
    # The resource arm pushes down; the principal arm stays in memory.
    node = Expression(
        "and",
        (
            Expression(
                "eq",
                (Variable("R.attr.department"), Literal("sales")),
            ),
            Expression(
                "eq",
                (Variable("P.attr.tenant"), Literal("acme")),
            ),
        ),
    )
    plan = QueryPlan(kind=PlanFilterKind.CONDITIONAL, condition=node)
    query = list_query(plan)
    assert query.sql == "department = ?"
    assert query.params == ["sales"]
    assert isinstance(query.fallback, Expression)
    assert query.fallback.operator == "eq"
    # Fallback cannot read P.attr from a resource row: fail-closed, not allow.
    with pytest.raises(UnsupportedPlanVariable):
        query.filter_rows([{"id": "E03", "department": "sales"}])


def test_in_operator_uses_placeholder_list(http_plans):
    from cerbos.sdk.model import (
        PlanResourcesExpression,
        PlanResourcesFilter,
        PlanResourcesFilterKind,
        PlanResourcesValue,
        PlanResourcesVariable,
    )

    tree = PlanResourcesExpression(
        expression=PlanResourcesExpression.Expr(
            operator="in",
            operands=[
                PlanResourcesVariable(variable="R.attr.department"),
                PlanResourcesExpression(
                    expression=PlanResourcesExpression.Expr(
                        operator="list",
                        operands=[
                            PlanResourcesValue(value="sales"),
                            PlanResourcesValue(value="finance"),
                        ],
                    )
                ),
            ],
        )
    )
    flt = PlanResourcesFilter(
        kind=PlanResourcesFilterKind.CONDITIONAL, condition=tree
    )
    query = list_query(QueryPlan.from_any(flt))
    assert query.sql == "department IN (?, ?)"
    assert query.params == ["sales", "finance"]
    assert _authorized_ids(query) == ["E03", "E04", "E05", "E06"]
