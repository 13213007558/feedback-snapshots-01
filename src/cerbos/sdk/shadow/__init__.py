# Copyright 2021-2025 Zenauth Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Optional shadow checking support for the Cerbos Python SDK.

This package lets an application compare the *approved* policy version it
enforces against a *candidate* policy version using the same authorization
input, without letting the candidate affect any real decision.

The public surface is intentionally transport-free: an in-memory policy engine
(:class:`~cerbos.sdk.shadow.engine.InMemoryCerbosEngine`) holds each version,
and a shadow client drives both while always returning the approved result.
"""

from cerbos.sdk.shadow._async import AsyncShadowCerbosClient
from cerbos.sdk.shadow._sync import ShadowCerbosClient
from cerbos.sdk.shadow.engine import (
    InMemoryCerbosEngine,
    ResourcePolicy,
    PolicyRule,
    and_,
    eq,
    evaluate,
    evaluate_plan_filter,
    has,
    lit,
    ne,
    not_,
    or_,
    var,
)
from cerbos.sdk.shadow.model import (
    ShadowAuditEntry,
    ShadowCheckReport,
    ShadowOutcome,
    ShadowPlanReport,
    ShadowPlanResourceReport,
)

__all__ = [
    "AsyncShadowCerbosClient",
    "InMemoryCerbosEngine",
    "PolicyRule",
    "ResourcePolicy",
    "ShadowAuditEntry",
    "ShadowCerbosClient",
    "ShadowCheckReport",
    "ShadowOutcome",
    "ShadowPlanReport",
    "ShadowPlanResourceReport",
    "and_",
    "eq",
    "evaluate",
    "evaluate_plan_filter",
    "has",
    "lit",
    "ne",
    "not_",
    "or_",
    "var",
]
