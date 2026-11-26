# Copyright 2021-2025 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

"""A small in-memory policy decision point used for shadow checks.

The real Cerbos SDK talks to a Cerbos server over HTTP/gRPC.  Shadow testing a
candidate policy before it is promoted needs *two* decision points driven by the
same input, and it must work inside a single process without standing up a
second server.  This module provides a dependency-free, synchronous in-memory
engine that implements the subset of Cerbos semantics needed to demonstrate and
test shadow checks:

* resource policies made of allow/deny rules whose conditions are boolean
  expressions over principal (``P.attr.*``) and resource (``R.attr.*``)
  attributes;
* query-plan filters expressed with the same condition language;
* tri-state condition evaluation so that an expression referencing a missing
  attribute is *undefined* rather than silently true or false.

The condition language is intentionally tiny.  Nodes are plain tuples:

* ``("var", "R.attr.department")``
* ``("lit", <python value>)``
* ``("has", "R.attr.owner")``            - always defined, even if absent
* ``("and", node, node, ...)``
* ``("or", node, node, ...)``
* ``("not", node)``
* ``("eq", left, right)`` / ``("ne", left, right)``
"""

import time
from dataclasses import dataclass, field
from typing import Any

from cerbos.sdk.model import (
    CheckResourcesResponse,
    CheckResourcesResult,
    Effect,
    PlanResourcesExpression,
    PlanResourcesFilter,
    PlanResourcesFilterKind,
    PlanResourcesResponse,
    PlanResourcesValue,
    PlanResourcesVariable,
    Principal,
    Resource,
    ResourceAction,
    ResourceDesc,
)

# Tri-state evaluation result: True / False / None (undefined).
TriState = bool | None
Condition = tuple


class MissingAttributeError(Exception):
    """Raised internally when an expression reads an attribute that is absent."""


@dataclass
class PolicyRule:
    actions: frozenset[str]
    effect: Effect
    condition: Condition


@dataclass
class ResourcePolicy:
    resource_kind: str
    policy_version: str
    rules: list[PolicyRule] = field(default_factory=list)
    # Query-plan filter per action: maps action name to a condition node.
    plan_filters: dict[str, Condition] = field(default_factory=dict)
    # Filter kind overrides for actions that always allow/deny unconditionally.
    plan_kinds: dict[str, PlanResourcesFilterKind] = field(default_factory=dict)


def var(path: str) -> Condition:
    return ("var", path)


def lit(value: Any) -> Condition:
    return ("lit", value)


def has(path: str) -> Condition:
    return ("has", path)


def and_(*operands: Condition) -> Condition:
    return ("and", *operands)


def or_(*operands: Condition) -> Condition:
    return ("or", *operands)


def not_(operand: Condition) -> Condition:
    return ("not", operand)


def eq(left: Condition, right: Condition) -> Condition:
    return ("eq", left, right)


def ne(left: Condition, right: Condition) -> Condition:
    return ("ne", left, right)


def _lookup(path: str, principal: Principal, resource: Resource | ResourceDesc) -> Any:
    if path.startswith("R.attr."):
        name = path[len("R.attr.") :]
        attrs = resource.attr
    elif path.startswith("P.attr."):
        name = path[len("P.attr.") :]
        attrs = principal.attr
    else:
        raise MissingAttributeError(f"unsupported variable {path!r}")
    if name not in attrs:
        raise MissingAttributeError(f"attribute {path!r} is not defined")
    return attrs[name]


def _has(path: str, principal: Principal, resource: Resource | ResourceDesc) -> bool:
    if path.startswith("R.attr."):
        return path[len("R.attr.") :] in resource.attr
    if path.startswith("P.attr."):
        return path[len("P.attr.") :] in principal.attr
    return False


def evaluate(
    node: Condition, principal: Principal, resource: Resource | ResourceDesc
) -> TriState:
    """Evaluate a condition, returning ``None`` when it is undefined."""
    kind = node[0]
    try:
        if kind == "lit":
            return bool(node[1])
        if kind == "var":
            return bool(_lookup(node[1], principal, resource))
        if kind == "has":
            return _has(node[1], principal, resource)
        if kind == "not":
            inner = evaluate(node[1], principal, resource)
            return None if inner is None else not inner
        if kind in ("eq", "ne"):
            left = _eval_operand(node[1], principal, resource)
            right = _eval_operand(node[2], principal, resource)
            result = left == right
            return result if kind == "eq" else not result
        if kind == "and":
            return _eval_and(node[1:], principal, resource)
        if kind == "or":
            return _eval_or(node[1:], principal, resource)
    except MissingAttributeError:
        return None
    raise ValueError(f"unknown condition operator {kind!r}")


def _eval_operand(
    node: Condition, principal: Principal, resource: Resource | ResourceDesc
) -> Any:
    if node[0] == "lit":
        return node[1]
    if node[0] == "var":
        return _lookup(node[1], principal, resource)
    # Nested boolean expressions used inside a comparison are undefined if any
    # sub-expression is undefined.
    value = evaluate(node, principal, resource)
    if value is None:
        raise MissingAttributeError("undefined operand")
    return value


def _eval_and(operands, principal, resource) -> TriState:
    saw_undefined = False
    for operand in operands:
        value = evaluate(operand, principal, resource)
        if value is False:
            return False
        if value is None:
            saw_undefined = True
    return None if saw_undefined else True


def _eval_or(operands, principal, resource) -> TriState:
    saw_undefined = False
    for operand in operands:
        value = evaluate(operand, principal, resource)
        if value is True:
            return True
        if value is None:
            saw_undefined = True
    return None if saw_undefined else False


def _effect_for_action(
    policy: ResourcePolicy, action: str, principal: Principal, resource: Resource
) -> Effect:
    # Cerbos denies by default and a DENY rule overrides an ALLOW rule. Rules
    # whose condition is undefined simply do not match.
    allowed = False
    for rule in policy.rules:
        if action not in rule.actions:
            continue
        decision = evaluate(rule.condition, principal, resource)
        if decision is not True:
            continue
        if rule.effect == Effect.DENY:
            return Effect.DENY
        allowed = True
    return Effect.ALLOW if allowed else Effect.DENY


class InMemoryCerbosEngine:
    """Synchronous in-memory PDP holding one version of a set of policies."""

    def __init__(self, label: str, policies: list[ResourcePolicy]):
        self.label = label
        self._policies = {
            (policy.resource_kind, policy.policy_version): policy for policy in policies
        }
        # Optional artificial latency (seconds) used to simulate shadow timeouts.
        self.latency_secs: float = 0.0
        # When set, every decision call raises, simulating a failed candidate.
        self.failure: Exception | None = None

    def _policy(self, resource: Resource | ResourceDesc) -> ResourcePolicy:
        key = (resource.kind, resource.policy_version)
        if key not in self._policies:
            raise KeyError(
                "no policy for "
                f"kind={resource.kind!r} version={resource.policy_version!r}"
            )
        return self._policies[key]

    def _maybe_delay(self):
        if self.latency_secs:
            time.sleep(self.latency_secs)
        if self.failure is not None:
            raise self.failure

    def check_resources(
        self,
        principal: Principal,
        resources: list[ResourceAction],
        request_id: str,
    ) -> CheckResourcesResponse:
        self._maybe_delay()
        results: list[CheckResourcesResult] = []
        for resource_action in resources:
            resource = resource_action.resource
            policy = self._policy(resource)
            actions = {
                action: _effect_for_action(policy, action, principal, resource)
                for action in sorted(resource_action.actions)
            }
            results.append(CheckResourcesResult(resource=resource, actions=actions))
        return CheckResourcesResponse(request_id=request_id, results=results)

    def plan_resources(
        self,
        actions: list[str],
        principal: Principal,
        resource: ResourceDesc,
        request_id: str,
    ) -> PlanResourcesResponse:
        self._maybe_delay()
        policy = self._policy(resource)
        action = actions[0] if len(actions) == 1 else list(actions)
        kind = policy.plan_kinds.get(next(iter(actions)))
        condition = policy.plan_filters.get(next(iter(actions)))
        if kind is not None:
            plan_filter = PlanResourcesFilter(kind=kind)
        elif condition is not None:
            plan_filter = PlanResourcesFilter(
                kind=PlanResourcesFilterKind.CONDITIONAL,
                condition=_to_plan_condition(condition),
            )
        else:
            plan_filter = PlanResourcesFilter(
                kind=PlanResourcesFilterKind.ALWAYS_DENIED
            )
        return PlanResourcesResponse(
            request_id=request_id,
            action=action,
            resource_kind=resource.kind,
            policy_version=resource.policy_version,
            filter=plan_filter,
        )


def _to_plan_condition(node: Condition):
    """Translate a condition tuple into the SDK's plan operand model."""
    kind = node[0]
    if kind == "lit":
        return PlanResourcesValue(value=node[1])
    if kind == "var":
        return PlanResourcesVariable(variable=node[1])
    if kind == "has":
        # `has(R.attr.x)` is rendered as the membership test the engine itself
        # understands, keeping the round-trip through the SDK model faithful.
        return PlanResourcesExpression(
            expression=PlanResourcesExpression.Expr(
                operator="has",
                operands=[PlanResourcesVariable(variable=node[1])],
            )
        )
    operands = [_to_plan_condition(child) for child in node[1:]]
    return PlanResourcesExpression(
        expression=PlanResourcesExpression.Expr(operator=kind, operands=operands)
    )


def evaluate_plan_filter(
    response: PlanResourcesResponse,
    principal: Principal,
    resource: Resource,
) -> TriState:
    """Resolve a plan filter against a concrete resource.

    Returns a concrete ``bool`` for ``ALWAYS_*`` filters and for conditional
    filters whose every referenced attribute is present, or ``None`` when a
    conditional filter references a missing attribute (no conclusion can be
    drawn for that resource).
    """
    plan_filter = response.filter
    if plan_filter is None:
        return None
    if plan_filter.kind == PlanResourcesFilterKind.ALWAYS_ALLOWED:
        return True
    if plan_filter.kind == PlanResourcesFilterKind.ALWAYS_DENIED:
        return False
    condition = _from_plan_condition(plan_filter.condition)
    return evaluate(condition, principal, resource)


def _from_plan_condition(operand) -> Condition:
    if isinstance(operand, PlanResourcesValue):
        return lit(operand.value)
    if isinstance(operand, PlanResourcesVariable):
        return var(operand.variable)
    if isinstance(operand, PlanResourcesExpression):
        operator = operand.expression.operator
        children = tuple(
            _from_plan_condition(child) for child in operand.expression.operands
        )
        if operator == "has":
            return has(operand.expression.operands[0].variable)
        return (operator, *children)
    raise ValueError(f"unsupported plan operand {operand!r}")
