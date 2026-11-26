# Copyright 2021-2025 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Shared fixtures for shadow check tests.

Two policy versions are loaded into separate in-memory engines.  They are written
with deliberately different expression ordering/syntax but resolve to the same
decision for resources whose attributes are complete.  On a resource missing the
``owner`` attribute the two versions reach opposite decisions, and on a resource
missing every attribute the candidate plan is undefined.
"""

import pytest

from cerbos.sdk.model import Effect, Principal, Resource, ResourceDesc
from cerbos.sdk.shadow.engine import (
    InMemoryCerbosEngine,
    PolicyRule,
    ResourcePolicy,
    and_,
    eq,
    has,
    lit,
    not_,
    or_,
    var,
)

ACTION = "edit"
RESOURCE_KIND = "document"


def _conditions():
    department_is_marketing = eq(var("R.attr.department"), lit("marketing"))
    has_owner = has("R.attr.owner")
    return department_is_marketing, has_owner


def _approved_policy() -> ResourcePolicy:
    department_is_marketing, has_owner = _conditions()
    # A single conjunctive allow rule: both the department and the owner must match.
    allow = and_(department_is_marketing, has_owner)
    return ResourcePolicy(
        resource_kind=RESOURCE_KIND,
        policy_version="default",
        rules=[PolicyRule(frozenset({ACTION}), Effect.ALLOW, allow)],
        plan_filters={ACTION: allow},
    )


def _candidate_policy() -> ResourcePolicy:
    department_is_marketing, has_owner = _conditions()
    # The same permission expressed with the operands reordered and split across
    # two rules.  For complete resources the outcome is identical; the extra
    # fallback rule flips the decision when ``owner`` is absent.
    owned = and_(has_owner, department_is_marketing)
    unowned_with_department = and_(not_(has_owner), has("R.attr.department"))
    return ResourcePolicy(
        resource_kind=RESOURCE_KIND,
        policy_version="default",
        rules=[
            PolicyRule(frozenset({ACTION}), Effect.ALLOW, owned),
            PolicyRule(frozenset({ACTION}), Effect.ALLOW, unowned_with_department),
        ],
        plan_filters={
            ACTION: or_(
                and_(has_owner, department_is_marketing),
                and_(not_(has_owner), department_is_marketing),
            )
        },
    )


@pytest.fixture
def action():
    return ACTION


@pytest.fixture
def principal():
    return Principal(id="user-1", roles={"employee"}, attr={})


@pytest.fixture
def complete_resource():
    # Has every attribute the plans reference -> both versions agree (allow).
    return Resource(
        id="doc-complete",
        kind=RESOURCE_KIND,
        attr={"department": "marketing", "owner": "user-1"},
    )


@pytest.fixture
def missing_owner_resource():
    # ``owner`` is absent while ``department`` is present -> opposite decisions.
    return Resource(
        id="doc-missing-owner",
        kind=RESOURCE_KIND,
        attr={"department": "marketing"},
    )


@pytest.fixture
def missing_all_resource():
    # No attributes at all -> candidate plan is undefined (inconclusive).
    return Resource(id="doc-missing-all", kind=RESOURCE_KIND, attr={})


@pytest.fixture
def evaluation_resources(
    complete_resource, missing_owner_resource, missing_all_resource
):
    return [complete_resource, missing_owner_resource, missing_all_resource]


@pytest.fixture
def resource_desc():
    return ResourceDesc(kind=RESOURCE_KIND)


@pytest.fixture
def approved_engine():
    return InMemoryCerbosEngine("approved", [_approved_policy()])


@pytest.fixture
def candidate_engine():
    return InMemoryCerbosEngine("candidate", [_candidate_policy()])


@pytest.fixture
def slow_candidate_engine(candidate_engine):
    # Slower than the client's shadow timeout, simulating a late candidate.
    candidate_engine.latency_secs = 0.5
    return candidate_engine
