# Copyright 2021-2025 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Fixtures building local query plans in both SDK wire shapes.

The plans are hand-built equivalents of what Cerbos emits, so the suite runs
without a live PDP.  Every scenario exists twice: once as the HTTP
``PlanResourcesFilter`` dataclass and once as the gRPC
``engine_pb2.PlanResourcesFilter`` message.
"""


from google.protobuf.struct_pb2 import Value

from cerbos.engine.v1 import engine_pb2
from cerbos.sdk.model import (
    PlanResourcesExpression,
    PlanResourcesFilter,
    PlanResourcesFilterKind,
    PlanResourcesValue,
    PlanResourcesVariable,
)

# ---------------------------------------------------------------------------
# Tiny "real" table: an employee document store keyed by id.
# ---------------------------------------------------------------------------

ROWS = [
    {"id": "E01", "department": "marketing", "geography": "GB",
     "owner": "alice", "level": 2, "tags": ["red"], "active": True},
    {"id": "E02", "department": "marketing", "geography": "US",
     "owner": "bob", "level": 5, "tags": ["red", "blue"], "active": True},
    {"id": "E03", "department": "sales", "geography": "GB",
     "owner": "carol", "level": 1, "tags": ["blue"], "active": False},
    {"id": "E04", "department": "sales", "geography": "DE",
     "owner": "dave", "level": 4, "tags": ["green"], "active": True},
    {"id": "E05", "department": "finance", "geography": "GB",
     "owner": "erin", "level": 3, "tags": [], "active": True},
    {"id": "E06", "department": "finance", "geography": "US",
     "owner": "frank", "level": 7, "tags": ["red"], "active": False},
    {"id": "E07", "department": "engineering", "geography": "GB",
     "owner": "grace", "level": 6, "tags": ["blue", "green"], "active": True},
    {"id": "E08", "department": "engineering", "geography": "DE",
     "owner": "heidi", "level": 2, "tags": ["red"], "active": True},
]



def build_rows():
    return [dict(row) for row in ROWS]


# ---------------------------------------------------------------------------
# Ground-truth authorization predicates, one per plan scenario.
# ---------------------------------------------------------------------------

def oracle_always_allowed(row):
    return True


def oracle_always_denied(row):
    return False


def oracle_conditional(row):
    # R.attr.department == "marketing" OR R.attr.geography == "GB"
    return row["department"] == "marketing" or row["geography"] == "GB"


def oracle_partial(row):
    # translatable: department == "sales"; untranslatable: tags intersects ["red"]
    return row["department"] == "sales" and bool(set(row["tags"]) & {"red"})


def oracle_nested(row):
    # NOT (level < 3) AND owner == "alice"
    return (not (row["level"] < 3)) and row["owner"] == "alice"


# ---------------------------------------------------------------------------
# HTTP (dataclass) plan builders
# ---------------------------------------------------------------------------

def _http_val(value):
    return PlanResourcesValue(value=value)


def _http_var(name):
    return PlanResourcesVariable(variable=name)


def _http_expr(operator, *operands):
    return PlanResourcesExpression(
        expression=PlanResourcesExpression.Expr(
            operator=operator, operands=list(operands)
        )
    )


def http_plan(kind, condition=None):
    return PlanResourcesFilter(
        kind=PlanResourcesFilterKind(kind), condition=condition
    )



def build_http_plans():
    conditional = _http_expr(
        "or",
        _http_expr("eq", _http_var("R.attr.department"), _http_val("marketing")),
        _http_expr("eq", _http_var("R.attr.geography"), _http_val("GB")),
    )
    # Partially uncompilable: an AND where one branch uses `intersects`,
    # which has no generic SQL translation.
    partial = _http_expr(
        "and",
        _http_expr("eq", _http_var("R.attr.department"), _http_val("sales")),
        _http_expr(
            "intersects", _http_var("R.attr.tags"),
            _http_expr("list", _http_val("red")),
        ),
    )
    nested = _http_expr(
        "and",
        _http_expr(
            "not",
            _http_expr("lt", _http_var("R.attr.level"), _http_val(3)),
        ),
        _http_expr("eq", _http_var("R.attr.owner"), _http_val("alice")),
    )
    return {
        "allow": http_plan("KIND_ALWAYS_ALLOWED"),
        "deny": http_plan("KIND_ALWAYS_DENIED"),
        "conditional": http_plan("KIND_CONDITIONAL", conditional),
        "partial": http_plan("KIND_CONDITIONAL", partial),
        "nested": http_plan("KIND_CONDITIONAL", nested),
    }


# ---------------------------------------------------------------------------
# gRPC (protobuf) plan builders - same logical plans, different wire shape.
# ---------------------------------------------------------------------------

def _proto_val(value):
    msg = Value()
    if value is None:
        msg.null_value = 0
    elif isinstance(value, bool):
        msg.bool_value = value
    elif isinstance(value, (int, float)):
        msg.number_value = value
    else:
        msg.string_value = value
    return msg


Operand = engine_pb2.PlanResourcesFilter.Expression.Operand
Expression = engine_pb2.PlanResourcesFilter.Expression


def _grpc_val(value):
    return Operand(value=_proto_val(value))


def _grpc_var(name):
    return Operand(variable=name)


def _grpc_expr(operator, *operands):
    return Operand(
        expression=Expression(operator=operator, operands=list(operands))
    )


def grpc_plan(kind, condition=None):
    flt = engine_pb2.PlanResourcesFilter(kind=kind)
    if condition is not None:
        flt.condition.CopyFrom(condition)
    return flt



def build_grpc_plans():
    conditional = _grpc_expr(
        "or",
        _grpc_expr("eq", _grpc_var("request.resource.attr.department"),
                   _grpc_val("marketing")),
        _grpc_expr("eq", _grpc_var("request.resource.attr.geography"),
                   _grpc_val("GB")),
    )
    partial = _grpc_expr(
        "and",
        _grpc_expr("eq", _grpc_var("request.resource.attr.department"),
                   _grpc_val("sales")),
        _grpc_expr(
            "intersects", _grpc_var("request.resource.attr.tags"),
            _grpc_expr("list", _grpc_val("red")),
        ),
    )
    nested = _grpc_expr(
        "and",
        _grpc_expr(
            "not",
            _grpc_expr("lt", _grpc_var("request.resource.attr.level"),
                       _grpc_val(3)),
        ),
        _grpc_expr("eq", _grpc_var("request.resource.attr.owner"),
                   _grpc_val("alice")),
    )
    return {
        "allow": grpc_plan(engine_pb2.PlanResourcesFilter.KIND_ALWAYS_ALLOWED),
        "deny": grpc_plan(engine_pb2.PlanResourcesFilter.KIND_ALWAYS_DENIED),
        "conditional": grpc_plan(
            engine_pb2.PlanResourcesFilter.KIND_CONDITIONAL, conditional
        ),
        "partial": grpc_plan(
            engine_pb2.PlanResourcesFilter.KIND_CONDITIONAL, partial
        ),
        "nested": grpc_plan(
            engine_pb2.PlanResourcesFilter.KIND_CONDITIONAL, nested
        ),
    }


ORACLES = {
    "allow": oracle_always_allowed,
    "deny": oracle_always_denied,
    "conditional": oracle_conditional,
    "partial": oracle_partial,
    "nested": oracle_nested,
}
